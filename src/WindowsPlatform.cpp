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
#include <Psapi.h>
#include <tlhelp32.h>
#include <Pdh.h>
#include <WbemIdl.h>
#include <comutil.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "ole32.lib")     // <<< FIX: Required for CoInitializeEx, CoUninitialize, CoCreateInstance, etc.
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Psapi.lib")

HQUERY m_hQuery = NULL;
HCOUNTER m_hDiskCounter = NULL;
HCOUNTER m_hNetRetransCounter = NULL;

#ifndef PDH_FMT_FLOAT
#define PDH_FMT_FLOAT 0x00000200
#endif

#ifndef PDH_MORE_DATA
#define PDH_MORE_DATA ((PDH_STATUS)0x800007D2)
#endif

static ULONGLONG FileTimeToInt64(const FILETIME& ft) {
    return ((ULONGLONG)ft.dwHighDateTime) << 32 | ((ULONGLONG)ft.dwLowDateTime);
}

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
    int getCpuUsagePercent() override;
    int getRamUsagePercent() override;
    std::string getFreeDiskSpaceGB(const std::string& drivePath) override;
    std::string getWindowsUpdateState() override;
    float getDiskQueueLength() override;
    float getNetworkRetransRate() override;
    std::string getSystemUptime() override;
    void updatePdhMetrics() override;
    std::string getGpuDriverInfo() override;
    float getGpuUsagePercent() override;
    std::string getHighRamProcesses() override;

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
    ULONGLONG m_previousIdleTime = 0;
    ULONGLONG m_previousKernelTime = 0;
    ULONGLONG m_previousUserTime = 0;
    PDH_HQUERY m_hQuery = NULL;
    PDH_HCOUNTER m_hDiskCounter = NULL;
    PDH_HCOUNTER m_hNetRetransCounter = NULL;
    PDH_HCOUNTER m_hGpuTotalCounter = NULL;

    void updateCpuTimes();
    std::string getProcessName(HANDLE hProcess);
};

void WindowsPlatform::updateCpuTimes() {
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        m_previousIdleTime = FileTimeToInt64(idleTime);
        m_previousKernelTime = FileTimeToInt64(kernelTime) - m_previousIdleTime;
        m_previousUserTime = FileTimeToInt64(userTime);
    }
}

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

    updateCpuTimes();

    // Initialize PDH Query for Disk and Network Counters
    if (PdhOpenQuery(NULL, 0, &m_hQuery) == ERROR_SUCCESS) {
        // Counter for Avg. Disk Queue Length for the entire physical disk subsystem
        PdhAddCounterA(m_hQuery, "\\PhysicalDisk(_Total)\\Avg. Disk Queue Length", 0, &m_hDiskCounter);
        // Counter for Segments Retransmitted/sec for IPv4 traffic
        PdhAddCounterA(m_hQuery, "\\TCPv4\\Segments Retransmitted/sec", 0, &m_hNetRetransCounter);

        PdhAddCounterW(m_hQuery, L"\\GPU Engine(*)\\Utilization Percentage", 0, &m_hGpuTotalCounter);

        // Collect initial data sample for counters that require two samples (like averages/rates)
        PdhCollectQueryData(m_hQuery);
    }
    else {
        logMessage("[WARNING] Failed to open PDH Query for system metrics.");
        m_hQuery = NULL;
    }

    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        logMessage("[WARNING] Failed to initialize COM for WMI access.");
    }
}

WindowsPlatform::~WindowsPlatform()
{
    if (m_hQuery) {
        PdhCloseQuery(m_hQuery);
    }
    CoUninitialize();
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
        for (IP_ADAPTER_ADDRESSES* pAdapter = pAdapterAddresses; pAdapter; pAdapter = pAdapter->Next)
        {
            // We only care about Ethernet interfaces
            if (pAdapter->IfType != IF_TYPE_ETHERNET_CSMACD)
            {
                continue;
            }

            NetworkInterface iface;

            // Format MAC address
            std::ostringstream macStream;
            for (ULONG i = 0; i < pAdapter->PhysicalAddressLength; i++)
            {
                if (i != 0)
                    macStream << ":";
                macStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pAdapter->PhysicalAddress[i]);
            }
            iface.macAddress = macStream.str();

            if (iface.macAddress.rfind("00:17", 0) == 0 || iface.macAddress.rfind("00:13", 0) == 0)
            {
                iface.name = pAdapter->FriendlyName ? WideToUtf8(pAdapter->FriendlyName) : "Unknown";
                iface.linkStatus = (pAdapter->OperStatus == IfOperStatusUp) ? "up" : "down";
                iface.dhcp = (pAdapter->Flags & IP_ADAPTER_DHCP_ENABLED) ? "dhcp" : "static";
                iface.ipv4 = "none";
                iface.ipv6 = "none";

                // Get IP addresses
                for (IP_ADAPTER_UNICAST_ADDRESS* pUnicast = pAdapter->FirstUnicastAddress; pUnicast; pUnicast = pUnicast->Next)
                {
                    char ipBuffer[INET6_ADDRSTRLEN] = { 0 };
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                    {
                        sockaddr_in* pSockAddr = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                        inet_ntop(AF_INET, &(pSockAddr->sin_addr), ipBuffer, sizeof(ipBuffer));
                        iface.ipv4 = ipBuffer;
                    }
                    else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
                    {
                        sockaddr_in6* pSockAddr6 = reinterpret_cast<sockaddr_in6*>(pUnicast->Address.lpSockaddr);
                        inet_ntop(AF_INET6, &(pSockAddr6->sin6_addr), ipBuffer, sizeof(ipBuffer));
                        iface.ipv6 = ipBuffer;
                    }
                }
                interfaces.push_back(iface);
            }
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

int WindowsPlatform::getCpuUsagePercent()
{
    // NOTE: This now relies on updatePdhMetrics being called right before it
    // The previous times were updated in updatePdhMetrics.

    FILETIME idleTime, kernelTime, userTime;
    if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        return 0;
    }

    ULONGLONG currentIdleTime = FileTimeToInt64(idleTime);
    ULONGLONG currentKernelTime = FileTimeToInt64(kernelTime) - currentIdleTime;
    ULONGLONG currentUserTime = FileTimeToInt64(userTime);

    // Calculate delta times based on the previous sample taken in updatePdhMetrics
    ULONGLONG idleTimeDelta = currentIdleTime - m_previousIdleTime;
    ULONGLONG kernelTimeDelta = currentKernelTime - m_previousKernelTime;
    ULONGLONG userTimeDelta = currentUserTime - m_previousUserTime;

    // No need to update previous times here, that is done in updatePdhMetrics

    ULONGLONG totalTimeDelta = kernelTimeDelta + userTimeDelta;

    if (totalTimeDelta == 0) {
        return 0;
    }

    // CPU Usage = (Total Time - Idle Time) / Total Time * 100
    int cpuUsage = (int)((totalTimeDelta - idleTimeDelta) * 100 / totalTimeDelta);

    if (cpuUsage < 0) return 0;
    if (cpuUsage > 100) return 100;

    return cpuUsage;
}

int WindowsPlatform::getRamUsagePercent() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);

    if (GlobalMemoryStatusEx(&statex)) {
        return (int)statex.dwMemoryLoad;
    }
    
    return 0;
}

std::string WindowsPlatform::getFreeDiskSpaceGB(const std::string& drivePath) {
    ULARGE_INTEGER freeBytesAvailableToCaller;
    ULARGE_INTEGER totalNumberOfBytes;
    ULARGE_INTEGER totalNumberOfFreeBytes;

    // Pseudocode plan:
    // 1. Identify the problematic line: if (path.size() == 2 && path[1] == ":") path += "\\";
    // 2. The error is caused by comparing path[1] (a char) to ":" (a const char*).
    // 3. Fix by comparing path[1] to ':' (a char), not ":" (a string).
    // 4. The rest of the code remains unchanged.

    std::wstring wDrivePath = L"C:\\";
    if (!drivePath.empty()) {
        std::string path = drivePath;
        if (path.size() == 2 && path[1] == ':') path += "\\";
        wDrivePath = std::wstring(path.begin(), path.end());
    }

    if (GetDiskFreeSpaceExW(
        wDrivePath.c_str(),
        &freeBytesAvailableToCaller,
        &totalNumberOfBytes,
        &totalNumberOfFreeBytes
    ))
    {
        double freeGB = (double)freeBytesAvailableToCaller.QuadPart / (1024.0 * 1024.0 * 1024.0);
        std::stringstream ss;
        ss << std::fixed << std::setprecision(1) << freeGB;
        return ss.str();
    }
    return "Unknown";
}

std::string WindowsPlatform::getWindowsUpdateState() {
    HKEY hKey;

    LONG lResult = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired",
        0,
        KEY_READ,
        &hKey
    );

    if (lResult == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "Pending Reboot";
    }

    lResult = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending",
        0,
        KEY_READ,
        &hKey
    );

    if (lResult == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "Pending Reboot";
    }

    return "Up to Date or Unknown";
}

void WindowsPlatform::updatePdhMetrics() {
    if (m_hQuery) {
        PdhCollectQueryData(m_hQuery);
    }

    updateCpuTimes();
}

float WindowsPlatform::getDiskQueueLength()
{
    if (m_hQuery == NULL || m_hDiskCounter == NULL) return 0.0f;

    PDH_FMT_COUNTERVALUE value;
    // PdhCollectQueryData is now called externally in updatePdhMetrics()
    if (PdhGetFormattedCounterValue(m_hDiskCounter, PDH_FMT_FLOAT, NULL, &value) == ERROR_SUCCESS) {
        return (float)value.doubleValue;
    }
    return 0.0f;
}

float WindowsPlatform::getNetworkRetransRate()
{
    if (m_hQuery == NULL || m_hNetRetransCounter == NULL) return 0.0f;

    PDH_FMT_COUNTERVALUE value;
    // PdhCollectQueryData is now called externally in updatePdhMetrics()
    if (PdhGetFormattedCounterValue(m_hNetRetransCounter, PDH_FMT_FLOAT, NULL, &value) == ERROR_SUCCESS) {
        return (float)value.doubleValue;
    }
    return 0.0f;
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

std::string WindowsPlatform::getSystemUptime()
{
    // Get the system tick count in milliseconds
    ULONGLONG ms = GetTickCount64();

    // Convert milliseconds to days, hours, minutes, seconds
    ULONGLONG seconds = ms / 1000;
    ULONGLONG minutes = seconds / 60;
    ULONGLONG hours = minutes / 60;
    ULONGLONG days = hours / 24;

    seconds %= 60;
    minutes %= 60;
    hours %= 24;

    std::stringstream ss;
    ss << days << "d ";
    ss << std::setw(2) << std::setfill('0') << hours << "h ";
    ss << std::setw(2) << std::setfill('0') << minutes << "m ";
    ss << std::setw(2) << std::setfill('0') << seconds << "s";

    return ss.str();
}

std::string WindowsPlatform::getGpuDriverInfo() {
    std::string result = "GPU: Not Found.";
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;

    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc
    );

    if (FAILED(hr)) goto cleanup;

    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hr)) goto cleanup;

    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hr)) goto cleanup;

    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT Name, DriverVersion FROM Win32_VideoController"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) goto cleanup;

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) break;

        VARIANT vtPropName, vtPropVersion;
        hr = pclsObj->Get(L"Name", 0, &vtPropName, 0, 0);
        hr = pclsObj->Get(L"DriverVersion", 0, &vtPropVersion, 0, 0);

        if (hr == S_OK) {
            std::string name = WideToUtf8(vtPropName.bstrVal ? vtPropName.bstrVal : L"Unknown GPU");
            std::string version = WideToUtf8(vtPropVersion.bstrVal ? vtPropVersion.bstrVal : L"Unknown Version");

            if (name.find("Intel") != std::string::npos ||
                name.find("HD Graphics") != std::string::npos ||
                name.find("UHD Graphics") != std::string::npos ||
                name.find("Xe Graphics") != std::string::npos) {
                result = "GPU: " + name + " | Driver: " + version;
                VariantClear(&vtPropName);
                VariantClear(&vtPropVersion);
                pclsObj->Release();
                goto cleanup;
            }

            VariantClear(&vtPropName);
            VariantClear(&vtPropVersion);
        }

        pclsObj->Release();
    }

cleanup:
    if (pEnumerator) pEnumerator->Release();
    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();

    return result;
}

float WindowsPlatform::getGpuUsagePercent() {
    if (m_hQuery == NULL | m_hGpuTotalCounter == NULL) return 0.0f;

    PDH_FMT_COUNTERVALUE_ITEM_W* items = nullptr;
    DWORD bufferSize = 0;
    DWORD item_count = 0;
    float totalUsage = 0.0f;
    PDH_STATUS status;

    status = PdhGetFormattedCounterArrayW(m_hGpuTotalCounter, PDH_FMT_FLOAT, &bufferSize, &item_count, nullptr);

    if (status != PDH_MORE_DATA && status != ERROR_SUCCESS) {
        return 0.0f;
    }

    items = (PDH_FMT_COUNTERVALUE_ITEM_W*)malloc(bufferSize);
    if (items == nullptr) return 0.0f;

    status = PdhGetFormattedCounterArrayW(m_hGpuTotalCounter, PDH_FMT_FLOAT, &bufferSize, &item_count, items);

    if (status == ERROR_SUCCESS) {
        for (DWORD i = 0; i < item_count; i++) {
            totalUsage += (float)items[i].FmtValue.doubleValue;
        }
    }

    free(items);
    return (totalUsage > 100.0f ? 100.0f : totalUsage);
}

std::string WindowsPlatform::getProcessName(HANDLE hProcess) {
    wchar_t szProcessPath[MAX_PATH];
    DWORD pathSize = MAX_PATH;

    if (QueryFullProcessImageNameW(hProcess, 0, szProcessPath, &pathSize)) {
        std::wstring wsPath = szProcessPath;
        size_t lastSlash = wsPath.find_last_of(L"\\");
        if (lastSlash != std::wstring::npos) {
            return WideToUtf8(wsPath.substr(lastSlash + 1));
        }

        return WideToUtf8(wsPath);
    }

    TCHAR szProcessName[MAX_PATH] = TEXT("unknown");
    DWORD bufferSize = sizeof(szProcessName) / sizeof(TCHAR);

    if (GetModuleBaseName(hProcess, NULL, szProcessName, bufferSize)) {
        return WideToUtf8(std::wstring(reinterpret_cast<const wchar_t*>(szProcessName)));
    }

    return "unknown";
}

std::string WindowsPlatform::getHighRamProcesses() {
    const ULONGLONG HIGH_RAM_THRESHOLD_MB = 500;
    const ULONGLONG HIGH_RAM_THRESHOLD_BYTES = HIGH_RAM_THRESHOLD_MB * 1024 * 1024;

    DWORD aProcesses[2048];
    DWORD cbNeeded;
    DWORD cProcesses;
    std::stringstream ss;
    bool first = true;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return "error: EnumProcesses failed";
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < cProcesses; i++) {
        if (aProcesses[i] == 0) continue;

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 
            FALSE, 
            aProcesses[i]
        );

        if (hProcess == NULL) continue;

        PROCESS_MEMORY_COUNTERS pmc;

        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            if (pmc.PagefileUsage >= HIGH_RAM_THRESHOLD_BYTES) {
                std::string name = getProcessName(hProcess);

                ULONGLONG ram_mb = pmc.PagefileUsage / (1024 * 1024);

                if (!first) {
                    ss << "|";
                }

                ss << name << "(" << aProcesses[i] << ")=" << ram_mb  << "MB";
                first = false;
            }
        }

        CloseHandle(hProcess);
    }

    std::string result = ss.str();
    return result.empty() ? "None" : result;
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