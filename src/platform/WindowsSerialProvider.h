// src/platform/WindowsSerialProvider.h
#pragma once
// Windows COM port serial I/O — owns the HANDLE lifetime for one port at a time.
#ifdef _WIN32
#include "Windows_Addon.h"
#include <string>
#include <functional>
#include <chrono>

class WindowsSerialProvider {
public:
    using Logger = std::function<void(const std::string&)>;
    explicit WindowsSerialProvider(Logger logger);

    bool open(const std::string& portName, int baudrate);
    void close();
    bool write(const std::string& data);
    bool read(std::string& outData);
    bool isOpen() const;

private:
    Logger log_;
    UniqueHandle hSerial_{INVALID_HANDLE_VALUE};
    std::string lastPortName_;
    int lastBaudrate_ = 115200;
    std::chrono::steady_clock::time_point lastAttempt_;
    // Minimum milliseconds between reconnect attempts in write() when port is closed.
    static constexpr int RETRY_DELAY_MS = 5000;
};

#endif // _WIN32
