#pragma once

#include <string>
#include <functional>
#include <atomic>
#include <chrono>

#include "../..//core/Platform.h"

#ifdef _WIN32
#include <cstddef>
#include <expected>
#include "../../core/Errors.h"
#endif

/**
 * @brief Manages serial port communication across platforms
 *
 * This class provides a platform-independent interface for serial communication.
 * It handles opening, closing, reading, and writing to serial ports, with
 * automatic retry logic for connection failures.
 */
class SerialManager {
public:
    /**
     * @brief Construct a new SerialManager object
     * @param onMessage Callback function to handle complete messages received
     */
    explicit SerialManager(StringCallback onMessage);

    /**
     * @brief Destroy the SerialManager and clean up resources
     */
    ~SerialManager();

    bool Open(const std::string& portName, int baudrate = 115200);

    void Close();

    bool IsOpen() const;

    bool Write(const std::string& data);

    bool Read(std::string& data);

    /**
     * @brief Process incoming data and extract complete messages
     *
     * This function should be called periodically to process buffered data.
     * Complete messages (delimited by \r\n) will trigger the onMessage callback.
     */
    void ProcessIncomingData();

    /**
     * @brief Try to reconnect if the port is closed
     *
     * This function implements a retry delay to avoid hammering the port.
     * @return true if reconnection succeeded, false otherwise
     */
    bool TryReconnect();

    /**
     * @brief Set the retry delay for reconnection attempts
     * @param delayMs Delay in milliseconds between retry attempts
     */
    void SetRetryDelay(int delayMs);

    // Delete copy constructor and assignment operator
    SerialManager(const SerialManager&) = delete;
    SerialManager& operator=(const SerialManager&) = delete;

private:
    StringCallback onMessage_;
    std::string rxBuffer_;
    std::string portName_;
    int baudrate_ = 115200;
    std::atomic<bool> isOpen_{ false };
    std::chrono::steady_clock::time_point lastAttempt_;
    int retryDelayMs_ = 5000;

#ifdef _WIN32
    void* hSerial_ = nullptr;  // HANDLE

    // Windows implementations behind the public bool API. Failures come back
    // as SerialError and are reported through ReportError().
    std::expected<void*, core::SerialError> OpenWindowsPort(const std::string& portName);
    std::expected<void, core::SerialError> WriteWindows(const std::string& data);
    std::expected<std::size_t, core::SerialError> ReadWindows(char* buffer, std::size_t size);

    // Logs to stderr every time, but to Event Viewer only when the error
    // differs from the last one reported - TryReconnect() retries every few
    // seconds while the port is absent and would otherwise flood the log.
    void ReportError(const core::SerialError& error);
    void ClearReportedError();
#else
    int serialFd_ = -1;
#endif
};