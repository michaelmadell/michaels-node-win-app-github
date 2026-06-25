#pragma once

#ifdef _WIN32
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>

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

    bool Start();
    void Stop();

    SerialBridgePipe(const SerialBridgePipe&) = delete;
    SerialBridgePipe& operator=(const SerialBridgePipe&) = delete;

private:
    void PipeThreadProc();
    void Log(const std::string& msg);

    static const char* const PIPE_NAME;

    WindowsPlatform* platform_ = nullptr;
    std::thread pipeThread_;
    std::atomic<bool> stop_{ false };
    HANDLE stopEvent_ = nullptr;
};

#endif // _WIN32
