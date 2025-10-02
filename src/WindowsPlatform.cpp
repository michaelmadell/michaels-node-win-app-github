#ifdef _WIN32
#include "Platform.h"
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <WtsApi32.h>
#include <SetupAPI.h>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "setupapi.lib")

std::string WideToUtf8(const std::wstring &wstr)
{
    if (wstr.empty())
        return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

typedef LONG(WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

// --- 1. DEFINE THE CLASS FIRST ---
// The class definition must come before it is used.
class WindowsPlatform : public Platform
{
public:
    WindowsPlatform();
    ~WindowsPlatform();

    std::vector<NetworkInterface> getNetworkInterfaces() override;
    std::string getHostname() override;
    std::string getLoggedInUser() override;
    std::string getOsVersion() override;
    bool openSerialPort(const std::string &portName, int baudrate) override;
    void closeSerialPort() override;
    bool writeSerial(const std::string &data) override;
    void logMessage(const std::string &message) override;

    int run(
        int argc, char *argv[],
        VoidCallback on_start,
        VoidCallback on_stop,
        PowerStateCallback power_cb,
        SessionStateCallback session_cb) override;

    // Helper methods for the service
    void reportStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint);
    void registerServiceHandler();
    HANDLE getStopEvent();
    void startService();
    void stopService();

private:
    HANDLE hSerial = INVALID_HANDLE_VALUE;
    VoidCallback on_start_callback;
    VoidCallback on_stop_callback;
    PowerStateCallback power_callback;
    SessionStateCallback session_callback;
    SERVICE_STATUS g_service_status = {};
    SERVICE_STATUS_HANDLE g_status_handle = nullptr;
    HANDLE g_stop_event = nullptr;
};

// --- 2. DEFINE GLOBALS AND HANDLERS THAT USE THE CLASS ---
static WindowsPlatform *g_platform_instance = nullptr;

void WINAPI ServiceMain(DWORD, LPTSTR *)
{
    if (!g_platform_instance)
        return;
    g_platform_instance->registerServiceHandler();
    g_platform_instance->reportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    g_platform_instance->startService();
    g_platform_instance->reportStatus(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(g_platform_instance->getStopEvent(), INFINITE);
    g_platform_instance->reportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode)
{
    switch (ctrlCode)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        if (g_platform_instance)
        {
            g_platform_instance->reportStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
            g_platform_instance->stopService();
        }
        break;
    }
}

// --- 3. IMPLEMENT THE FACTORY FUNCTION AND CLASS METHODS ---
std::unique_ptr<Platform> createPlatform()
{
    return std::make_unique<WindowsPlatform>();
}

WindowsPlatform::WindowsPlatform()
{
    g_platform_instance = this;
    g_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
}

WindowsPlatform::~WindowsPlatform()
{
    CloseHandle(g_stop_event);
}

int WindowsPlatform::run(
    int argc, char *argv[],
    VoidCallback on_start,
    VoidCallback on_stop,
    PowerStateCallback power_cb,
    SessionStateCallback session_cb)
{
    this->on_start_callback = on_start;
    this->on_stop_callback = on_stop;
    this->power_callback = power_cb;
    this->session_callback = session_cb;

    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        {(LPWSTR)L"CoreStationAgent", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain},
        {NULL, NULL}};

    if (!StartServiceCtrlDispatcherW(ServiceTable))
    {
        logMessage("Running in interactive mode.");
        if (on_start_callback)
            on_start_callback();
        std::cout << "Service running interactively. Press Enter to stop." << std::endl;
        std::cin.get();
        if (on_stop_callback)
            on_stop_callback();
    }
    return 0;
}

// Implementations for the core virtual methods
std::vector<NetworkInterface> WindowsPlatform::getNetworkInterfaces()
{
    std::vector<NetworkInterface> interfaces;
    ULONG bufferSize = 0;

    // First call to get the required buffer size
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufferSize);

    if (bufferSize == 0)
    {
        return interfaces;
    }

    std::vector<BYTE> buffer(bufferSize);
    IP_ADAPTER_ADDRESSES *pAdapterAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());

    // Second call to get the actual data
    DWORD result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAdapterAddresses, &bufferSize);

    if (result == NO_ERROR)
    {
        for (IP_ADAPTER_ADDRESSES *pAdapter = pAdapterAddresses; pAdapter; pAdapter = pAdapter->Next)
        {
            // We only care about Ethernet interfaces
            if (pAdapter->IfType != IF_TYPE_ETHERNET_CSMACD)
            {
                continue;
            }

            NetworkInterface iface;
            iface.name = pAdapter->FriendlyName ? WideToUtf8(pAdapter->FriendlyName) : "Unknown";
            iface.linkStatus = (pAdapter->OperStatus == IfOperStatusUp) ? "up" : "down";
            iface.dhcp = (pAdapter->Flags & IP_ADAPTER_DHCP_ENABLED) ? "dhcp" : "static";
            iface.ipv4 = "none";
            iface.ipv6 = "none";

            // Format MAC address
            std::ostringstream macStream;
            for (ULONG i = 0; i < pAdapter->PhysicalAddressLength; i++)
            {
                if (i != 0)
                    macStream << ":";
                macStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pAdapter->PhysicalAddress[i]);
            }
            iface.macAddress = macStream.str();

            // Get IP addresses
            for (IP_ADAPTER_UNICAST_ADDRESS *pUnicast = pAdapter->FirstUnicastAddress; pUnicast; pUnicast = pUnicast->Next)
            {
                char ipBuffer[INET6_ADDRSTRLEN] = {0};
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                {
                    sockaddr_in *pSockAddr = reinterpret_cast<sockaddr_in *>(pUnicast->Address.lpSockaddr);
                    inet_ntop(AF_INET, &(pSockAddr->sin_addr), ipBuffer, sizeof(ipBuffer));
                    iface.ipv4 = ipBuffer;
                }
                else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
                {
                    sockaddr_in6 *pSockAddr6 = reinterpret_cast<sockaddr_in6 *>(pUnicast->Address.lpSockaddr);
                    inet_ntop(AF_INET6, &(pSockAddr6->sin6_addr), ipBuffer, sizeof(ipBuffer));
                    iface.ipv6 = ipBuffer;
                }
            }
            interfaces.push_back(iface);
        }
    }
    return interfaces;
}
std::string WindowsPlatform::getHostname()
{
    char hostnameChar[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD hostnameLen = sizeof(hostnameChar);
    if (GetComputerNameA(hostnameChar, &hostnameLen))
    {
        return std::string(hostnameChar);
    }
    return "Unknown Host";
}
std::string WindowsPlatform::getLoggedInUser()
{
    PWTS_SESSION_INFOW pSessionInfo = NULL;
    DWORD sessionCount = 0;
    std::string username = "none";

    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount))
    {
        for (DWORD i = 0; i < sessionCount; ++i)
        {
            if (pSessionInfo[i].State == WTSActive)
            {
                LPWSTR pBuffer = NULL;
                DWORD bytesReturned = 0;
                if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, pSessionInfo[i].SessionId, WTSUserName, &pBuffer, &bytesReturned) && pBuffer)
                {
                    username = WideToUtf8(std::wstring(pBuffer));
                    WTSFreeMemory(pBuffer);
                    break; // Found the first active user
                }
            }
        }
        WTSFreeMemory(pSessionInfo);
    }
    return username;
}

std::string WindowsPlatform::getOsVersion()
{
    // First, get the raw version info to check the build number
    HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
    if (!hMod) return "Unknown Windows Version";

    RtlGetVersionPtr fn = (RtlGetVersionPtr)::GetProcAddress(hMod, "RtlGetVersion");
    if (!fn) return "Unknown Windows Version";

    RTL_OSVERSIONINFOW rovi = {0};
    rovi.dwOSVersionInfoSize = sizeof(rovi);
    if (fn(&rovi) != 0) return "Unknown Windows Version";

    // Now, query the registry for the friendly name
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        // Fallback to build number if registry fails
        std::ostringstream version;
        version << rovi.dwMajorVersion << "." << rovi.dwMinorVersion << "." << rovi.dwBuildNumber;
        return version.str();
    }

    char productName[255];
    DWORD productNameSize = sizeof(productName);
    if (RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)productName, &productNameSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "Unknown Windows Version";
    }

    std::string finalProductName = productName;

    // Correct the product name if the build number indicates Windows 11
    if (rovi.dwBuildNumber >= 22000) {
        size_t pos = finalProductName.find("10");
        if (pos != std::string::npos) {
            finalProductName.replace(pos, 2, "11");
        }
    }

    char displayVersion[255];
    DWORD displayVersionSize = sizeof(displayVersion);
    if (RegQueryValueExA(hKey, "DisplayVersion", NULL, NULL, (LPBYTE)displayVersion, &displayVersionSize) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return finalProductName + " " + std::string(displayVersion);
    }
    
    RegCloseKey(hKey);
    return finalProductName;
}

bool WindowsPlatform::openSerialPort(const std::string &portName, int baudrate)
{
    // The port name is passed in, but we will use the one from version.h for this implementation
    hSerial = CreateFileA(
        portName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hSerial == INVALID_HANDLE_VALUE)
    {
        // You can get more detailed error info here if needed
        // DWORD error = GetLastError();
        return false;
    }

    DCB dcbSerialParams = {0};
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);

    if (!GetCommState(hSerial, &dcbSerialParams))
    {
        CloseHandle(hSerial);
        return false;
    }

    dcbSerialParams.BaudRate = CBR_115200; // You can use the 'baudrate' parameter
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;

    if (!SetCommState(hSerial, &dcbSerialParams))
    {
        CloseHandle(hSerial);
        return false;
    }

    // Set timeouts
    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 50;
    timeouts.ReadTotalTimeoutConstant = 50;
    timeouts.ReadTotalTimeoutMultiplier = 10;
    timeouts.WriteTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutMultiplier = 10;

    if (!SetCommTimeouts(hSerial, &timeouts))
    {
        CloseHandle(hSerial);
        return false;
    }

    return true;
}
void WindowsPlatform::closeSerialPort()
{
    if (hSerial != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hSerial);
        hSerial = INVALID_HANDLE_VALUE;
    }
}
bool WindowsPlatform::writeSerial(const std::string &data)
{
    if (hSerial == INVALID_HANDLE_VALUE)
        return false;
    DWORD bytesWritten = 0;
    return WriteFile(hSerial, data.c_str(), (DWORD)data.length(), &bytesWritten, NULL);
}
void WindowsPlatform::logMessage(const std::string &message)
{
    const wchar_t *dirPath = L"C:\\ProgramData\\ahk";
    const wchar_t *logPath = L"C:\\ProgramData\\ahk\\node-win-app.log";

    DWORD fileAttr = GetFileAttributesW(dirPath);
    if (fileAttr == INVALID_FILE_ATTRIBUTES)
    {
        if (!CreateDirectoryW(dirPath, NULL))
        {
            // Could add error handling here, but for now, we'll just fail silently
            // if the directory can't be created.
            return;
        }
    }

    std::ofstream logFile(logPath, std::ios::app);
    if (logFile.is_open())
    {
        SYSTEMTIME time;
        GetLocalTime(&time);

        logFile << "[" << time.wYear << "-" << time.wMonth << "-" << time.wDay << " "
                << std::setfill('0') << std::setw(2) << time.wHour << ":"
                << std::setfill('0') << std::setw(2) << time.wMinute << ":"
                << std::setfill('0') << std::setw(2) << time.wSecond << "."
                << std::setfill('0') << std::setw(3) << time.wMilliseconds << "] "
                << message << std::endl;
        logFile.close();
    }
}

// Helper methods for the service
void WindowsPlatform::reportStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint)
{
    if (g_status_handle == nullptr)
        return;
    g_service_status.dwCurrentState = currentState;
    g_service_status.dwWin32ExitCode = win32ExitCode;
    g_service_status.dwWaitHint = waitHint;
    SetServiceStatus(g_status_handle, &g_service_status);
}

void WindowsPlatform::registerServiceHandler()
{
    g_status_handle = RegisterServiceCtrlHandlerW(L"CoreStationHXAgent", ServiceCtrlHandler);
    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    reportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
}

HANDLE WindowsPlatform::getStopEvent()
{
    return g_stop_event;
}

void WindowsPlatform::startService()
{
    if (on_start_callback)
        on_start_callback();
}

void WindowsPlatform::stopService()
{
    if (on_stop_callback)
        on_stop_callback();
    SetEvent(g_stop_event);
}

#endif // _WIN32