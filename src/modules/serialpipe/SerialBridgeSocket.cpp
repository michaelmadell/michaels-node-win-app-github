#if defined(__linux__)
#include "SerialBridgeSocket.h"
#include "LinuxIpcClientAuth.h"
#include "../../platform/LinuxPlatform.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <grp.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>

const char* const SerialBridgeSocket::kSocketPath = "/run/corestation/serial_bridge.sock";

namespace {
// A dedicated, unprivileged system group for local company applications
// that are allowed to *attempt* to connect to the bridge (the actual
// authentication decision is the signature check in LinuxIpcClientAuth,
// not this ACL -- this is defense-in-depth only, per spec.md FR-010 /
// Constitution Principle V). Falls back to root:root 0600 (root-only) if
// the group doesn't exist on this system yet, which is safe (more
// restrictive), just less convenient.
constexpr const char* kIpcGroupName = "corestation-ipc";
}  // namespace

SerialBridgeSocket::SerialBridgeSocket(LinuxPlatform* platform) : platform_(platform) {}

SerialBridgeSocket::~SerialBridgeSocket() {
    Stop();
}

void SerialBridgeSocket::Log(const std::string& msg) {
    if (platform_) {
        platform_->logMessage("[SerialBridgeSocket] " + msg);
    }
}

bool SerialBridgeSocket::Start() {
    // Fail closed: refuse to start at all if the trust anchor can't be
    // loaded, rather than silently rejecting (or worse, if a future change
    // introduced a bug, silently accepting) every connection forever with
    // no obvious cause. Skipped entirely for dev builds, where there's no
    // trust anchor to check.
#ifndef IPC_AUTH_DEV_DISABLE
    if (!IpcAuth::LinuxTrustAnchorIsUsable("[SerialBridgeSocket] ",
                                           [](const std::string& m) { fprintf(stderr, "%s\n", m.c_str()); })) {
        Log("FATAL: trust anchor unusable, refusing to start (see certs/README.md)");
        return false;
    }
#endif

    if (pipe(stopPipeFds_) != 0) {
        Log(std::string("Failed to create stop pipe: ") + std::strerror(errno));
        return false;
    }

    // Best-effort: the parent directory may not exist yet on a fresh
    // install (packaging is expected to create it, but don't hard-fail the
    // whole bridge over a missing runtime directory during development).
    mkdir("/run/corestation", 0755);

    listenFd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listenFd_ < 0) {
        Log(std::string("socket() failed: ") + std::strerror(errno));
        return false;
    }

    unlink(kSocketPath);  // clear a stale socket file from a previous run

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, kSocketPath, sizeof(addr.sun_path) - 1);

    if (bind(listenFd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        Log(std::string("bind(") + kSocketPath + ") failed: " + std::strerror(errno));
        close(listenFd_);
        listenFd_ = -1;
        return false;
    }

    // Restrict to owner+group; grant group access to the dedicated IPC
    // group if it exists, otherwise stay root-only (0600-equivalent via
    // group falling back to root's own primary group).
    struct group* grp = getgrnam(kIpcGroupName);
    if (grp) {
        if (chown(kSocketPath, static_cast<uid_t>(-1), grp->gr_gid) != 0) {
            Log(std::string("chown to group '") + kIpcGroupName + "' failed: " + std::strerror(errno) +
                " -- continuing with default group ownership");
        }
        chmod(kSocketPath, 0660);
    } else {
        Log(std::string("group '") + kIpcGroupName +
            "' does not exist -- socket left root-only (0600). Create the group to allow "
            "non-root company applications to connect.");
        chmod(kSocketPath, 0600);
    }

    if (listen(listenFd_, 4) != 0) {
        Log(std::string("listen() failed: ") + std::strerror(errno));
        close(listenFd_);
        listenFd_ = -1;
        return false;
    }

    stop_ = false;
    listenThread_ = std::thread([this]() { ListenThreadProc(); });
    Log("Serial bridge socket listener started");
    return true;
}

void SerialBridgeSocket::Stop() {
    if (stop_.exchange(true)) {
        return;
    }

    if (stopPipeFds_[1] >= 0) {
        char byte = 1;
        (void)!write(stopPipeFds_[1], &byte, 1);  // wake the poll() loop
    }

    if (listenThread_.joinable()) {
        listenThread_.join();
    }

    if (listenFd_ >= 0) {
        close(listenFd_);
        listenFd_ = -1;
    }
    unlink(kSocketPath);

    for (int fd : stopPipeFds_) {
        if (fd >= 0) close(fd);
    }
    stopPipeFds_[0] = stopPipeFds_[1] = -1;

    Log("Serial bridge socket listener stopped");
}

void SerialBridgeSocket::ListenThreadProc() {
    while (!stop_.load()) {
        struct pollfd fds[2];
        fds[0].fd = listenFd_;
        fds[0].events = POLLIN;
        fds[1].fd = stopPipeFds_[0];
        fds[1].events = POLLIN;

        int pollResult = poll(fds, 2, -1);
        if (pollResult < 0) {
            if (errno == EINTR) continue;
            Log(std::string("poll() failed: ") + std::strerror(errno));
            break;
        }

        if (fds[1].revents & POLLIN) {
            break;  // Stop() was called
        }

        if (!(fds[0].revents & POLLIN)) {
            continue;
        }

        int clientFd = accept4(listenFd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (clientFd < 0) {
            if (errno != EINTR) {
                Log(std::string("accept() failed: ") + std::strerror(errno));
            }
            continue;
        }

        HandleConnection(clientFd);
        close(clientFd);
    }
}

void SerialBridgeSocket::HandleConnection(int clientFd) {
    bool authenticated = IpcAuth::LinuxIsAuthenticated(
        clientFd, "[SerialBridgeSocket] ",
        [this](const std::string& m) { Log(m); });

    if (!authenticated) {
        Log("WARNING: rejected unauthenticated IPC bridge connection");
        return;  // connection closed by caller (HandleConnection's close(clientFd))
    }

    // Authenticated: forward whatever bytes arrive, as-is, no framing added
    // (matches SerialBridgePipe's Windows behavior -- spec.md FR-009),
    // until the client disconnects. No re-authentication per message.
    char buffer[1024];
    for (;;) {
        ssize_t bytesRead = recv(clientFd, buffer, sizeof(buffer), 0);
        if (bytesRead <= 0) {
            break;  // 0 = orderly close, <0 = error; either way, done
        }

        std::string payload(buffer, static_cast<size_t>(bytesRead));
        if (platform_) {
            if (!platform_->forwardSerialBridgeMessage(payload)) {
                Log("ERROR: Failed to forward message to serial port");
            }
        }
    }
}

#endif  // __linux__
