#pragma once

#ifdef _WIN32
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <expected>
#include "../../core/Errors.h"

// Forward declaration
class WindowsPlatform;

/**
 * @brief Named pipe bridge that forwards messages from another local
 * application straight to the serial port.
 *
 * The pipe is created with a security descriptor that restricts connection
 * to members of BUILTIN\Administrators -- any other caller's CreateFile
 * fails at the OS level before a single byte is exchanged. Whatever bytes
 * arrive on the pipe are forwarded to WindowsPlatform::forwardSerialBridgeMessage()
 * as-is (no framing/newline is added or assumed).
 */
class SerialBridgePipe {
public:
    explicit SerialBridgePipe(WindowsPlatform* platform);
    ~SerialBridgePipe();

    // Builds the pipe's security descriptor and starts the listener thread.
    // Fails if the stop event or security descriptor can't be created.
    std::expected<void, core::PipeError> Start();

    // Signals the listener thread and joins it. Can't fail, so stays void.
    void Stop();

    SerialBridgePipe(const SerialBridgePipe&) = delete;
    SerialBridgePipe& operator=(const SerialBridgePipe&) = delete;

private:
    void PipeThreadProc();
    std::expected<HANDLE, core::PipeError> CreatePipeInstance(SECURITY_ATTRIBUTES& sa);
    void Log(const std::string& msg);

    // Logs every pipe error, but writes to Event Viewer only when it differs
    // from the last one - CreatePipeInstance() is retried every second.
    void ReportPipeError(const core::PipeError& error);

    static const char* const PIPE_NAME;

    WindowsPlatform* platform_ = nullptr;
    std::thread pipeThread_;
    std::atomic<bool> stop_{ false };
    HANDLE stopEvent_ = nullptr;
    DWORD stopEventError_ = ERROR_SUCCESS;
    PSECURITY_DESCRIPTOR securityDescriptor_ = nullptr;
    bool devBypassLogged_ = false;
};

#endif // _WIN32
