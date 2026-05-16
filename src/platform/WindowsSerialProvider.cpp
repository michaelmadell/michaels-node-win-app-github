// src/platform/WindowsSerialProvider.cpp
// Windows COM port serial I/O — owns the HANDLE lifetime for one port at a time.
#ifdef _WIN32
#include "WindowsSerialProvider.h"
#include <windows.h>
#include <string>
#include <sstream>
#include <chrono>

WindowsSerialProvider::WindowsSerialProvider(Logger logger)
    : log_(std::move(logger))
    , hSerial_(INVALID_HANDLE_VALUE)
{}

bool WindowsSerialProvider::isOpen() const {
    return hSerial_.get() != INVALID_HANDLE_VALUE && hSerial_.get() != nullptr;
}

bool WindowsSerialProvider::open(const std::string& portName, int baudrate)
{
    lastPortName_ = portName;
    lastBaudrate_ = baudrate;

    HANDLE rawHandle = CreateFileA(
        portName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (rawHandle == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        std::ostringstream oss;
        oss << "CreateFileA failed for " << portName << " with error " << err;
        log_(oss.str());
        return false;
    }

    hSerial_.reset(rawHandle);

    if (hSerial_.get() == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DCB dcbSerialParams = {0};
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);

    if (!GetCommState(hSerial_.get(), &dcbSerialParams))
    {
        hSerial_.reset(INVALID_HANDLE_VALUE);
        return false;
    }

    dcbSerialParams.BaudRate = CBR_115200; // You can use the 'baudrate' parameter
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;

    if (!SetCommState(hSerial_.get(), &dcbSerialParams))
    {
        hSerial_.reset();
        return false;
    }

    // Set timeouts
    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 5;
    timeouts.ReadTotalTimeoutConstant = 5;
    timeouts.ReadTotalTimeoutMultiplier = 1;
    timeouts.WriteTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutMultiplier = 10;

    if (!SetCommTimeouts(hSerial_.get(), &timeouts))
    {
        hSerial_.reset();
        return false;
    }

    return true;
}

void WindowsSerialProvider::close()
{
    hSerial_.reset(INVALID_HANDLE_VALUE);
}

bool WindowsSerialProvider::write(const std::string& data)
{
    if (hSerial_.get() == INVALID_HANDLE_VALUE) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - lastAttempt_).count();

        if (elapsed >= RETRY_DELAY_MS) {
            lastAttempt_ = now;
            log_("Attempting to reconnect serial port...");
            if (open(lastPortName_, lastBaudrate_)) {
                log_("Serial port reconnected successfully");
            }
        }
        return false;
    }

    DWORD bytesWritten = 0;
    if (WriteFile(hSerial_.get(), data.c_str(), (DWORD)data.length(), &bytesWritten, NULL)) {
        DWORD err = GetLastError();
        log_("WriteFile failed (Error " + std::to_string(err) + "), closing serial port");
        close();
        return false;
    }

    if (bytesWritten != data.length()) {
        log_("Partial write detected (" + std::to_string(bytesWritten) + " of " + std::to_string(data.length()) + " bytes)");
        return false;
    }
    return true;
}

bool WindowsSerialProvider::read(std::string& readData) {
    if (!hSerial_) {
        return false;
    }

    char buffer[256];
    DWORD bytesRead = 0;

    if (ReadFile(hSerial_.get(), buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        if (bytesRead > 0) {
            readData.append(buffer, bytesRead);
            return true;
        }
    }
    else {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            log_("Error reading from serial port: " + std::to_string(err));
        }
    }
    return false;
}

#endif // _WIN32
