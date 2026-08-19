#ifdef _WIN32
#include "SerialBridgePipe.h"
#include "WindowsIpcClientAuth.h"
#include "../../platform/WindowsPlatform.h"
#include <sddl.h>
#include <chrono>

const char* const SerialBridgePipe::PIPE_NAME = "\\\\.\\pipe\\corestation_serial_bridge";

SerialBridgePipe::SerialBridgePipe(WindowsPlatform* platform) : platform_(platform) {
    stopEvent_ = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!stopEvent_) {
        Log("Failed to create stop event");
    }
}

SerialBridgePipe::~SerialBridgePipe() {
    Stop();
    if (stopEvent_) {
        CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
    }
}

void SerialBridgePipe::Log(const std::string& msg) {
    if (platform_) {
        platform_->logMessage("[SerialBridgePipe] " + msg);
    }
}

bool SerialBridgePipe::Start() {
    if (!stopEvent_) {
        Log("Cannot start: stop event unavailable");
        return false;
    }

    stop_ = false;
    ResetEvent(stopEvent_);
    pipeThread_ = std::thread([this]() { PipeThreadProc(); });
    return true;
}

void SerialBridgePipe::Stop() {
    if (stop_.exchange(true)) {
        return;
    }

    if (stopEvent_) {
        SetEvent(stopEvent_);
    }

    if (pipeThread_.joinable()) {
        pipeThread_.join();
    }
}

void SerialBridgePipe::PipeThreadProc() {
    // Restrict connections to members of BUILTIN\Administrators. Any other
    // caller's CreateFile on this pipe fails with ERROR_ACCESS_DENIED before
    // a single byte is exchanged.
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:(A;;GA;;;BA)", SDDL_REVISION_1, &sd, NULL)) {
        Log("Failed to build pipe security descriptor, refusing to start");
        return;
    }

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    Log("Serial bridge pipe listener started");

    while (!stop_.load()) {
        HANDLE hPipe = CreateNamedPipeA(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            1024,
            1024,
            0,
            &sa);

        if (hPipe == INVALID_HANDLE_VALUE) {
            Log("Failed to create named pipe");
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        OVERLAPPED ovConnect = {};
        ovConnect.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        BOOL connected = ConnectNamedPipe(hPipe, &ovConnect);
        DWORD err = GetLastError();

        if (!connected && err == ERROR_IO_PENDING) {
            HANDLE handles[2] = { ovConnect.hEvent, stopEvent_ };
            DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0 + 1) {
                CancelIoEx(hPipe, &ovConnect);
            }
            else {
                connected = TRUE;
            }
        }
        else if (!connected && err == ERROR_PIPE_CONNECTED) {
            connected = TRUE;
        }

        if (connected && !stop_.load()) {
            // Authenticate before reading/forwarding a single byte -- see
            // WindowsIpcClientAuth.h and specs/001-secure-serial-ipc.
            // Administrator-only pipe ACL (above) is defense-in-depth only;
            // this check is the actual control (spec.md FR-001..FR-005).
            bool authenticated = IpcAuth::WindowsIsAuthenticated(
                hPipe, "[SerialBridgePipe] ",
                [this](const std::string& m) { Log(m); });

            if (!authenticated) {
                Log("WARNING: rejected unauthenticated IPC bridge connection");
                if (ovConnect.hEvent) {
                    CloseHandle(ovConnect.hEvent);
                }
                DisconnectNamedPipe(hPipe);
                CloseHandle(hPipe);
                continue;
            }

            for (;;) {
                char buffer[1024] = { 0 };
                DWORD bytesRead = 0;
                OVERLAPPED ovRead = {};
                ovRead.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

                BOOL readOk = ReadFile(hPipe, buffer, sizeof(buffer), NULL, &ovRead);
                if (!readOk) {
                    DWORD readErr = GetLastError();
                    if (readErr == ERROR_IO_PENDING) {
                        HANDLE handles[2] = { ovRead.hEvent, stopEvent_ };
                        DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
                        if (wait == WAIT_OBJECT_0 + 1) {
                            CancelIoEx(hPipe, &ovRead);
                            CloseHandle(ovRead.hEvent);
                            break;
                        }
                        GetOverlappedResult(hPipe, &ovRead, &bytesRead, FALSE);
                    }
                    else {
                        CloseHandle(ovRead.hEvent);
                        break;
                    }
                }
                else {
                    GetOverlappedResult(hPipe, &ovRead, &bytesRead, TRUE);
                }

                CloseHandle(ovRead.hEvent);

                if (bytesRead == 0) {
                    break;
                }

                std::string payload(buffer, bytesRead);
                if (platform_) {
                    if (!platform_->forwardSerialBridgeMessage(payload)) {
                        Log("ERROR: Failed to forward message to serial port");
                    }
                }
            }
        }

        if (ovConnect.hEvent) {
            CloseHandle(ovConnect.hEvent);
        }
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    LocalFree(sd);
    Log("Serial bridge pipe listener stopped");
}

#endif // _WIN32
