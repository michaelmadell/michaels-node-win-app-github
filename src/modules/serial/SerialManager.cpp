#include "SerialManager.h"
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <format>
#include "../../core/Logging.h"
#include "../../platform/WinHandles.h"
#else
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <cstring>
#include <cerrno>
#endif

SerialManager::SerialManager(StringCallback onMessage)
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
    auto handle = OpenWindowsPort(portName);
    if (!handle) {
        ReportError(handle.error());
        return false;
    }
    ClearReportedError();

    hSerial_ = *handle;
    isOpen_ = true;
    return true;

#else
    int fd = open(portName.c_str(), O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        std::cerr << "Error opening serial port " << portName
            << ": " << strerror(errno) << " (errno " << errno << ")" << std::endl;
        return false;
    }

    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        std::cerr << "Error getting termios attributes for " << portName
            << ": " << strerror(errno) << " (errno " << errno << ")" << std::endl;
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
        std::cerr << "Error setting termios attributes for " << portName
            << ": " << strerror(errno) << " (errno " << errno << ")" << std::endl;
        close(fd);
        return false;
    }

    serialFd_ = fd;
    isOpen_ = true;
    return true;
#endif
}

#ifdef _WIN32
std::expected<void*, core::SerialError> SerialManager::OpenWindowsPort(const std::string& portName) {
    UniqueHandle handle(CreateFileA(
        portName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    ));

    if (handle.get() == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        // ACCESS_DENIED / SHARING_VIOLATION on a COM port means another
        // process already has it open.
        const bool busy = err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION;
        const bool missing = err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND;
        return std::unexpected(core::SerialError{
            .code = busy ? core::CoreError::Code::Busy
                  : missing ? core::CoreError::Code::NotFound
                  : core::CoreError::Code::IoError,
            .sub_code = busy ? core::SerialError::SubCode::PortBusy : core::SerialError::SubCode::PortNotFound,
            .message = std::format("CreateFileA failed for {}", portName),
            .platform_error = err,
        });
    }

    auto configureFailed = [&portName](const char* call) {
        DWORD err = GetLastError();
        return std::unexpected(core::SerialError{
            .code = core::CoreError::Code::IoError,
            .sub_code = core::SerialError::SubCode::ConfigureFailed,
            .message = std::format("{} failed for {}", call, portName),
            .platform_error = err,
        });
    };

    DCB dcbSerialParams{};
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);

    if (!GetCommState(handle.get(), &dcbSerialParams)) {
        return configureFailed("GetCommState");
    }

    dcbSerialParams.BaudRate = CBR_115200;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;

    // Explicitly disable hardware and software flow control (mirrors the
    // Linux side's ~CRTSCTS / ~(IXON|IXOFF|IXANY)). Without this, whatever
    // handshaking mode the port driver defaulted to is left in place - if
    // that's CTS-based, WriteFile blocks until the timeout and returns a
    // partial write whenever the peer isn't actively asserting CTS.
    dcbSerialParams.fOutxCtsFlow = FALSE;
    dcbSerialParams.fOutxDsrFlow = FALSE;
    dcbSerialParams.fDsrSensitivity = FALSE;
    dcbSerialParams.fRtsControl = RTS_CONTROL_ENABLE;
    dcbSerialParams.fDtrControl = DTR_CONTROL_ENABLE;
    dcbSerialParams.fOutX = FALSE;
    dcbSerialParams.fInX = FALSE;

    // Without this, a single framing/overrun/parity error on the line
    // (very likely with nothing coherent driving the far end yet) latches
    // the port into an aborted state: every WriteFile/ReadFile after that
    // returns 0 bytes immediately, forever, until something acknowledges
    // the error via ClearCommError(). Keep the driver from doing that.
    dcbSerialParams.fAbortOnError = FALSE;

    if (!SetCommState(handle.get(), &dcbSerialParams)) {
        return configureFailed("SetCommState");
    }

    // Defensively clear any error already latched from a previous session,
    // and drop any stale bytes sitting in the driver's TX/RX buffers.
    DWORD commErrors = 0;
    ClearCommError(handle.get(), &commErrors, NULL);
    PurgeComm(handle.get(), PURGE_RXCLEAR | PURGE_TXCLEAR);

    COMMTIMEOUTS timeouts{};
    timeouts.ReadIntervalTimeout = 5;
    timeouts.ReadTotalTimeoutConstant = 5;
    timeouts.ReadTotalTimeoutMultiplier = 1;
    timeouts.WriteTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutMultiplier = 10;

    if (!SetCommTimeouts(handle.get(), &timeouts)) {
        return configureFailed("SetCommTimeouts");
    }

    return handle.release();
}

std::expected<void, core::SerialError> SerialManager::WriteWindows(const std::string& data) {
    DWORD bytesWritten = 0;
    if (!WriteFile((HANDLE)hSerial_, data.c_str(), (DWORD)data.length(), &bytesWritten, NULL)) {
        DWORD err = GetLastError();
        Close();
        return std::unexpected(core::SerialError{
            .code = core::CoreError::Code::IoError,
            .sub_code = core::SerialError::SubCode::WriteError,
            .message = std::format("WriteFile failed on {}, closing serial port", portName_),
            .platform_error = err,
        });
    }

    if (bytesWritten != data.length()) {
        return std::unexpected(core::SerialError{
            .code = core::CoreError::Code::IoError,
            .sub_code = core::SerialError::SubCode::WriteError,
            .message = std::format("Partial write detected on {} ({} of {} bytes)", portName_, bytesWritten, data.length()),
        });
    }
    return {};
}

// Returns the number of bytes read; 0 when nothing arrived before the
// COMMTIMEOUTS read timeout, which is the normal idle case.
std::expected<std::size_t, core::SerialError> SerialManager::ReadWindows(char* buffer, std::size_t size) {
    DWORD bytesRead = 0;
    if (!ReadFile((HANDLE)hSerial_, buffer, (DWORD)size, &bytesRead, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            return 0;
        }
        return std::unexpected(core::SerialError{
            .code = core::CoreError::Code::IoError,
            .sub_code = core::SerialError::SubCode::ReadError,
            .message = std::format("Error reading from serial port {}", portName_),
            .platform_error = err,
        });
    }
    return bytesRead;
}

void SerialManager::ReportError(const core::SerialError& error) {
    std::cerr << core::describe(error) << std::endl;
    core::LogErrorOnChange("serial:" + portName_, core::kMsgIDSerial, "Serial", error);
}

// Called after a successful open: if a failure had been reported, log the
// recovery so the Event Viewer trail doesn't end on a stale error.
void SerialManager::ClearReportedError() {
    core::ClearReportedError("serial:" + portName_, core::kMsgIDSerial,
                             std::format("Serial: port {} opened after earlier failure", portName_));
}
#endif

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
    if (auto written = WriteWindows(data); !written) {
        ReportError(written.error());
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
    auto bytesRead = ReadWindows(buffer, sizeof(buffer) - 1);
    if (!bytesRead) {
        ReportError(bytesRead.error());
        return false;
    }
    if (*bytesRead == 0) {
        return false;
    }
    data.append(buffer, *bytesRead);
    return true;

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