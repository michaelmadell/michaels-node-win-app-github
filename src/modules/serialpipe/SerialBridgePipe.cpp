#ifdef _WIN32
#include "SerialBridgePipe.h"
#include "WindowsIpcClientAuth.h"
#include "../../platform/WindowsPlatform.h"
#include "../../core/Logging.h"
#include <sddl.h>
#include <chrono>
#include <format>

const char* const SerialBridgePipe::PIPE_NAME = "\\\\.\\pipe\\corestation_serial_bridge";

SerialBridgePipe::SerialBridgePipe(WindowsPlatform* platform) : platform_(platform) {
    stopEvent_ = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!stopEvent_) {
        stopEventError_ = GetLastError();  // reported by Start()
    }
}

SerialBridgePipe::~SerialBridgePipe() {
    Stop();
    if (stopEvent_) {
        CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
    }
    if (securityDescriptor_) {
        LocalFree(securityDescriptor_);
        securityDescriptor_ = nullptr;
    }
}

void SerialBridgePipe::Log(const std::string& msg) {
    if (platform_) {
        platform_->logMessage("[SerialBridgePipe] " + msg);
    }
}

void SerialBridgePipe::ReportPipeError(const core::PipeError& error) {
    Log(core::describe(error));
    core::LogErrorOnChange("serialpipe", core::kMsgIDSerialBridge, "Serial bridge pipe", error);
}

std::expected<void, core::PipeError> SerialBridgePipe::Start() {
    if (!stopEvent_) {
        return std::unexpected(core::PipeError{
            .code = core::CoreError::Code::ResourceExhausted,
            .sub_code = core::PipeError::SubCode::SetupFailed,
            .message = "Cannot start: stop event unavailable",
            .platform_error = stopEventError_,
        });
    }

    // Restrict connections to members of BUILTIN\Administrators. Any other
    // caller's CreateFile on this pipe fails with ERROR_ACCESS_DENIED before
    // a single byte is exchanged. Built here rather than on the listener
    // thread so a failure reaches the caller instead of silently ending it.
    if (!securityDescriptor_ &&
        !ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:(A;;GA;;;BA)", SDDL_REVISION_1, &securityDescriptor_, NULL)) {
        DWORD err = GetLastError();
        securityDescriptor_ = nullptr;
        return std::unexpected(core::PipeError{
            .code = core::CoreError::Code::Internal,
            .sub_code = core::PipeError::SubCode::SetupFailed,
            .message = "Failed to build pipe security descriptor, refusing to start",
            .platform_error = err,
        });
    }

    stop_ = false;
    ResetEvent(stopEvent_);
    pipeThread_ = std::thread([this]() { PipeThreadProc(); });
    return {};
}

std::expected<HANDLE, core::PipeError> SerialBridgePipe::CreatePipeInstance(SECURITY_ATTRIBUTES& sa) {
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
        DWORD err = GetLastError();
        // Another process already owns the single allowed instance (e.g. a
        // second copy of the agent) -> busy rather than a hard failure.
        const bool busy = err == ERROR_PIPE_BUSY || err == ERROR_ACCESS_DENIED;
        return std::unexpected(core::PipeError{
            .code = busy ? core::CoreError::Code::Busy : core::CoreError::Code::Internal,
            .sub_code = busy ? core::PipeError::SubCode::PipeBusy : core::PipeError::SubCode::CreateFailed,
            .message = "Failed to create named pipe",
            .platform_error = err,
        });
    }
    return hPipe;
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
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = securityDescriptor_;
    sa.bInheritHandle = FALSE;

    Log("Serial bridge pipe listener started");

    while (!stop_.load()) {
        auto pipe = CreatePipeInstance(sa);
        if (!pipe) {
            ReportPipeError(pipe.error());
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        core::ClearReportedError("serialpipe", core::kMsgIDSerialBridge, "Serial bridge pipe: listener recovered");
        HANDLE hPipe = *pipe;

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
            auto client = IpcAuth::AuthenticateClient(hPipe);

            if (client && client->devBypass && !devBypassLogged_) {
                devBypassLogged_ = true;
                const char* notice = "DEV MODE: IPC authentication disabled (IPC_AUTH_DEV_DISABLE) -- "
                                     "this build MUST NOT be used in production";
                Log(notice);
                core::Log(core::LogLevel::Warning, core::kMsgIDSerialBridge,
                          std::format("Serial bridge pipe: {}", notice));
            }

            if (!client) {
                // Every rejection is logged - they're security-relevant and
                // the admin-only pipe ACL keeps the rate low.
                Log(core::describe(client.error()));
                Log("WARNING: rejected unauthenticated IPC bridge connection");
                core::LogError(core::kMsgIDSerialBridge,
                               "Serial bridge pipe: rejected unauthenticated IPC connection", client.error());
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

    Log("Serial bridge pipe listener stopped");
}

#endif // _WIN32
