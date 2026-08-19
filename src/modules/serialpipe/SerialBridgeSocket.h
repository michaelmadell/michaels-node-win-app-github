#pragma once

#if defined(__linux__)
#include <string>
#include <thread>
#include <atomic>

// Forward declaration
class LinuxPlatform;

/**
 * @brief Unix domain socket bridge that forwards messages from another
 * local application straight to the serial port -- the Linux counterpart
 * of SerialBridgePipe (Windows named pipe).
 *
 * The socket is created at a fixed path (restricted by filesystem
 * permissions -- defense-in-depth only, see IpcClientAuth for the actual
 * authentication control) and forwards whatever bytes arrive, as-is, to
 * WindowsPlatform-equivalent LinuxPlatform::forwardSerialBridgeMessage(),
 * once (and only once) the connecting client authenticates -- see
 * LinuxIpcClientAuth.h.
 */
class SerialBridgeSocket {
public:
    explicit SerialBridgeSocket(LinuxPlatform* platform);
    ~SerialBridgeSocket();

    bool Start();
    void Stop();

    SerialBridgeSocket(const SerialBridgeSocket&) = delete;
    SerialBridgeSocket& operator=(const SerialBridgeSocket&) = delete;

private:
    void ListenThreadProc();
    void HandleConnection(int clientFd);
    void Log(const std::string& msg);

    static const char* const kSocketPath;

    LinuxPlatform* platform_ = nullptr;
    std::thread listenThread_;
    std::atomic<bool> stop_{false};
    int listenFd_ = -1;
    int stopPipeFds_[2] = {-1, -1};  // self-pipe, used to interrupt poll()
};

#endif  // __linux__
