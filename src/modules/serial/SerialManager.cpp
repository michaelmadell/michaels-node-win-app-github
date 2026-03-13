#include "SerialManager.h"
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <cstring>
#include <cerrno>
#endif

SerialManager::SerialManager(MessageCallback onMessage)
    : onMessage_(onMessage) {
}

SerialManager::~SerialManager() {
    Close();
}

bool SerialManager::Open(const std::string& portName, int baudrate) {
    if (isOpen_) {
        Close();
    }

    portName_ = portName;
    baudrate_ = baudrate;

#ifdef _WIN32
    HANDLE handle = CreateFileA(
        portName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::cerr << "CreateFileA failed for " << portName << " with error " << err << std::endl;
        return false;
    }

    DCB dcbSerialParams = { 0 };
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);

    if (!GetCommState(handle, &dcbSerialParams)) {
        CloseHandle(handle);
        return false;
    }

    dcbSerialParams.BaudRate = CBR_115200;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;

    if (!SetCommState(handle, &dcbSerialParams)) {
        CloseHandle(handle);
        return false;
    }

    COMMTIMEOUTS timeouts = { 0 };
    timeouts.ReadIntervalTimeout = 5;
    timeouts.ReadTotalTimeoutConstant = 5;
    timeouts.ReadTotalTimeoutMultiplier = 1;
    timeouts.WriteTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutMultiplier = 10;

    if (!SetCommTimeouts(handle, &timeouts)) {
        CloseHandle(handle);
        return false;
    }

    hSerial_ = handle;
    isOpen_ = true;
    return true;

#else
    int fd = open(portName.c_str(), O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        std::cerr << "Error opening serial port " << portName << std::endl;
        return false;
    }

    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        std::cerr << "Error getting termios attributes" << std::endl;
        close(fd);
        return false;
    }

    cfsetospeed(&tty, B115200);
    cfsetispeed(&tty, B115200);

    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tty.c_cflag &= ~CRTSCTS;
    tty.c_cflag |= CREAD | CLOCAL;

    tty.c_iflag &= ~(IXON | IXOFF | IXANY);
    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_oflag &= ~OPOST;

    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        std::cerr << "Error setting termios attributes" << std::endl;
        close(fd);
        return false;
    }

    serialFd_ = fd;
    isOpen_ = true;
    return true;
#endif
}

void SerialManager::Close() {
    if (!isOpen_) {
        return;
    }

#ifdef _WIN32
    if (hSerial_ != nullptr && hSerial_ != INVALID_HANDLE_VALUE) {
        CloseHandle((HANDLE)hSerial_);
        hSerial_ = nullptr;
    }
#else
    if (serialFd_ >= 0) {
        close(serialFd_);
        serialFd_ = -1;
    }
#endif

    isOpen_ = false;
}

bool SerialManager::IsOpen() const {
    return isOpen_;
}

bool SerialManager::Write(const std::string& data) {
    if (!isOpen_) {
        return false;
    }

#ifdef _WIN32
    DWORD bytesWritten = 0;
    if (!WriteFile((HANDLE)hSerial_, data.c_str(), (DWORD)data.length(), &bytesWritten, NULL)) {
        DWORD err = GetLastError();
        std::cerr << "WriteFile failed (Error " << err << "), closing serial port" << std::endl;
        Close();
        return false;
    }

    if (bytesWritten != data.length()) {
        std::cerr << "Partial write detected (" << bytesWritten << " of " << data.length() << " bytes)" << std::endl;
        return false;
    }
    return true;

#else
    ssize_t bytes_written = write(serialFd_, data.c_str(), data.length());
    if (bytes_written < 0) {
        std::cerr << "Error on write(): " << strerror(errno) << std::endl;
        return false;
    }
    return bytes_written == (ssize_t)data.length();
#endif
}

bool SerialManager::Read(std::string& data) {
    if (!isOpen_) {
        return false;
    }

    char buffer[256];

#ifdef _WIN32
    DWORD bytesRead = 0;
    if (ReadFile((HANDLE)hSerial_, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        if (bytesRead > 0) {
            data.append(buffer, bytesRead);
            return true;
        }
    }
    else {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            std::cerr << "Error reading from serial port: " << err << std::endl;
        }
    }
    return false;

#else
    ssize_t bytes_read = read(serialFd_, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        data.append(buffer, bytes_read);
        return true;
    }
    return false;
#endif
}

void SerialManager::ProcessIncomingData() {
    std::string newData;
    Read(newData);
    rxBuffer_ += newData;

    size_t pos = 0;
    while ((pos = rxBuffer_.find_first_of("\r\n")) != std::string::npos) {
        std::string line = rxBuffer_.substr(0, pos);
        if (!line.empty() && onMessage_) {
            onMessage_(line);
        }
        rxBuffer_.erase(0, pos + 1);
        if (!rxBuffer_.empty() && (rxBuffer_[0] == '\r' || rxBuffer_[0] == '\n')) {
            rxBuffer_.erase(0, 1);
        }
    }
}

bool SerialManager::TryReconnect() {
    if (isOpen_) {
        return true;
    }

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - lastAttempt_).count();

    if (elapsed >= retryDelayMs_) {
        lastAttempt_ = now;
        std::cout << "Attempting to reconnect serial port..." << std::endl;
        if (Open(portName_, baudrate_)) {
            std::cout << "Serial port reconnected successfully" << std::endl;
            return true;
        }
    }

    return false;
}

void SerialManager::SetRetryDelay(int delayMs) {
    retryDelayMs_ = delayMs;
}