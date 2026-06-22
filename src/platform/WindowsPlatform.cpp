#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "WindowsPlatform.h"
#include <iostream>
#undef min
#undef max
#include <iphlpapi.h>
#include <wtsapi32.h>
#include <setupapi.h>
#include <shellapi.h>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <psapi.h>
#include <tlhelp32.h>
#include <pdh.h>
#include <wbemidl.h>
#include <comutil.h>
#include <shellapi.h>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <chrono>
#include <cctype>
#include "Windows_Addon.h"
#include "../version.h"
#include "../modules/metrics/MetricCache.h"

#ifdef ENABLE_TRAY_APP
#include "../modules/tray/TrayApp.h"
#endif

#include "../modules/session/SessionMonitor.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "shell32.lib")

#ifndef PDH_FMT_FLOAT
#define PDH_FMT_FLOAT 0x00000200
#endif

#ifndef PDH_MORE_DATA
#define PDH_MORE_DATA ((PDH_STATUS)0x800007D2)
#endif

static const wchar_t* const LOG_DIR_PATH = L"C:\\ProgramData\\ahk";
static const wchar_t* const LOG_FILE_PATH = L"C:\\ProgramData\\ahk\\node-win-app.log";

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

static std::string Trim(const std::string& input) {
    if (input.empty()) {
        return std::string();
    }

    const char* whitespace = " \t\r\n";
    size_t start = input.find_first_not_of(whitespace);
    if (start == std::string::npos) {
        return std::string();
    }

    size_t end = input.find_last_not_of(whitespace);
    return input.substr(start, end - start + 1);
}

static WindowsPlatform* g_platform_instance = nullptr;

static const char* ServiceControlToReason(DWORD ctrlCode) {
    switch (ctrlCode) {
    case SERVICE_CONTROL_SHUTDOWN:
        return "shutdown";
    case SERVICE_CONTROL_STOP:
    default:
        return "stop";
    }
}

void WINAPI ServiceMain(DWORD, LPTSTR*) {
    if (!g_platform_instance)
        return;

    g_platform_instance->registerServiceHandler();
    g_platform_instance->reportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    g_platform_instance->startService();
    g_platform_instance->reportStatus(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(g_platform_instance->getStopEvent(), INFINITE);
    g_platform_instance->reportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch (ctrlCode) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        if (g_platform_instance) {
            g_platform_instance->stopService(ServiceControlToReason(ctrlCode));
        }
        break;
    }
}

std::unique_ptr<Platform> createPlatform() {
    return std::make_unique<WindowsPlatform>();
}

WindowsPlatform::WindowsPlatform()
{
    g_platform_instance = this;
    g_stop_event = UniqueHandle(CreateEvent(NULL, TRUE, FALSE, NULL));

    updateCpuTimes();

    PDH_HQUERY rawQuery = NULL;
    if (PdhOpenQuery(NULL, 0, &rawQuery) == ERROR_SUCCESS && rawQuery != NULL) {
        // Store the raw handle in the unique_ptr wrapper
        m_hQuery = UniquePdhQuery(rawQuery);
        if (m_hQuery) {

            // Counter for Avg. Disk Queue Length for the entire physical disk subsystem
            PdhAddCounterA(m_hQuery.get(), "\\PhysicalDisk(_Total)\\Avg. Disk Queue Length", 0, &m_hDiskCounter);
            // Counter for Segments Retransmitted/sec for IPv4 traffic
            PdhAddCounterA(m_hQuery.get(), "\\TCPv4\\Segments Retransmitted/sec", 0, &m_hNetRetransCounter);

            PdhAddCounterW(m_hQuery.get(), L"\\GPU Engine(*)\\Utilization Percentage", 0, &m_hGpuTotalCounter);

            // Collect initial data sample for counters that require two samples (like averages/rates)
            PdhCollectQueryData(m_hQuery.get());
        }
    }
    else {
        logMessage("[WARNING] Failed to open PDH Query for system metrics.");
    }

    if (!com_initializer.Succeeded()) {
        logMessage("[WARNING] Failed to initialize COM for WMI access.");
    }
}

WindowsPlatform::~WindowsPlatform()
{
    stopSessionMonitor();
}

int WindowsPlatform::run(
    int argc, char* argv[],
    VoidCallback on_start,
    StringCallback on_stop,
    PowerStateCallback power_cb,
    SessionStateCallback session_cb)
{
    this->on_start_callback = on_start;
    this->on_stop_callback = on_stop;
    this->power_callback = power_cb;
    this->session_callback = session_cb;

    // Ensure stop event exists and is unsignaled
    if (!g_stop_event)
        g_stop_event = UniqueHandle(CreateEvent(NULL, TRUE, FALSE, NULL));
    else
        ResetEvent(g_stop_event.get());

    const bool forceInteractive =
        hasSwitch(argc, argv, "--interactive") ||
        hasSwitchCmd(L"--interactive") ||
        hasSwitchCmd(L"/interactive");
    const bool forceService =
        hasSwitch(argc, argv, "--service") ||
        hasSwitchCmd(L"--service") ||
        hasSwitchCmd(L"/service");
    const bool isServiceLaunch = runningUnderServiceControlManager();

    {
        std::ostringstream oss;
        oss << "Mode Detection: forceInteractive=" << (forceInteractive ? "true" : "false")
            << ", forceService=" << (forceService ? "true" : "false")
            << ", isServiceLaunch=" << (isServiceLaunch ? "true" : "false");
        logMessage(oss.str());
    }

    // Attempt SCM dispatch unless interactive mode is explicitly requested.
    // This avoids false negatives from parent-process heuristics in some environments.
    if (!forceInteractive)
    {
        SERVICE_TABLE_ENTRYW ServiceTable[] = {
            { (LPWSTR)L"CoreStationHXAgent", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
            { NULL, NULL }
        };

        if (StartServiceCtrlDispatcherW(ServiceTable))
            return 0;

        DWORD err = GetLastError();
        if (forceService || err != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            std::ostringstream oss;
            oss << "StartServiceCtrlDispatcher failed (" << err << "), cannot continue.";
            logMessage(oss.str());
            return static_cast<int>(err);
        }

        std::ostringstream oss;
        oss << "StartServiceCtrlDispatcher failed (" << err << "), falling back to interactive mode.";
        logMessage(oss.str());
    }

    logMessage("Running in interactive mode.");
    startSessionMonitor();
#ifdef ENABLE_TRAY_APP
    startTrayApp();
#endif
    if (on_start_callback)
        on_start_callback();
    std::cout << "Service running interactively. Press Enter to stop." << std::endl;
    std::cin.get();
    if (on_stop_callback)
        on_stop_callback("interactive-stop");
#ifdef ENABLE_TRAY_APP
    stopTrayApp();
#endif
    return 0;
}

bool WindowsPlatform::hasSwitch(int argc, char* argv[], const char* sw)
{
    for (int i = 1; i < argc; ++i)
    {
        if (_stricmp(argv[i], sw) == 0) return true;
    }
    return false;
}

bool WindowsPlatform::hasSwitchCmd(const wchar_t* sw) {
    int argcW = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
    if (!argvW) return false;
    for (int i = 1; i < argcW; ++i) {
        if (_wcsicmp(argvW[i], sw) == 0) { LocalFree(argvW); return true;}
    }
    LocalFree(argvW);
    return false;
}

bool WindowsPlatform::runningUnderServiceControlManager()
{
    DWORD pid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(pe);
    DWORD parentPid = 0;

    if (Process32First(hSnap, &pe))
    {
        do
        {
            if (pe.th32ProcessID == pid)
            {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    if (parentPid == 0) return false;

    HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, parentPid);
    if (!hParent) return false;

    char name[MAX_PATH] = {0};
    if (GetModuleBaseNameA(hParent, NULL, name, MAX_PATH) == 0)
    {
        CloseHandle(hParent);
        return false;
    }
    CloseHandle(hParent);

    for (char* p = name; *p; ++p) *p = (char)tolower(*p);
    return strcmp(name, "services.exe") == 0;
}

void WindowsPlatform::startSessionMonitor() {
    session_monitor_ = std::make_unique<SessionMonitor>(this, session_callback);
    session_monitor_->Start();
}

void WindowsPlatform::stopSessionMonitor() {
    if (session_monitor_) {
        session_monitor_->Stop();
        session_monitor_.reset();
    }
}


std::string WindowsPlatform::getCurrentSessionState() {
    if (session_monitor_) {
        return session_monitor_->GetCurrentSessionState();
    }
    return "0";
}

void WindowsPlatform::updateCpuTimes() {
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        m_previousIdleTime = FileTimeToInt64(idleTime);
        m_previousKernelTime = FileTimeToInt64(kernelTime) - m_previousIdleTime;
        m_previousUserTime = FileTimeToInt64(userTime);
    }
}

void WindowsPlatform::startTrayApp()
{
#ifdef ENABLE_TRAY_APP
    if (!tray_app_)
    {
        tray_app_ = std::make_unique<TrayApp>(this);
        tray_app_->Start();
        logMessage("Tray App Started.");
    }
#endif
}

void WindowsPlatform::stopTrayApp()
{
#ifdef ENABLE_TRAY_APP
    if (tray_app_)
    {
        tray_app_->Stop();
        tray_app_.reset();
        logMessage("Tray App Stopped.");
    }
#endif
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
                macStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pAdapter->PhysicalAddress[i]);
            }
            iface.macAddress = macStream.str();

            if (iface.macAddress.compare(0, 8, "00:17:FD") == 0 || // Amulet Hotkey MAC
                iface.macAddress.compare(0, 8, "00:07:32") == 0 || // AAEON MAC
                iface.macAddress.compare(0, 8, "00:13:95") == 0)   // Congatec MAC
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

std::string WindowsPlatform::getOsBuild()
{
    HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
    if (!hMod) return "Unknown Build (ntdll.dll)";

    RtlGetVersionPtr fn = (RtlGetVersionPtr)::GetProcAddress(hMod, "RtlGetVersion");
    if (!fn) return "Unknown Build (RtlGetVersion)";

    RTL_OSVERSIONINFOW rovi = {0};
    rovi.dwOSVersionInfoSize = sizeof(rovi);
    
    if (fn(&rovi) != 0) return "Unknown Build (RtlGetVersion failed)";

    // Format the version as a string: Major.Minor.Build
    std::ostringstream version;
    version << rovi.dwMajorVersion << "." << rovi.dwMinorVersion << "." << rovi.dwBuildNumber;
    
    return version.str();
}

bool WindowsPlatform::openSerialPort(const std::string &portName, int baudrate)
{
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
        logMessage(oss.str());
		return false;
    }

    hSerial.reset(rawHandle);

    if (hSerial.get() == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DCB dcbSerialParams = {0};
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);

    if (!GetCommState(hSerial.get(), &dcbSerialParams))
    {
        hSerial.reset(INVALID_HANDLE_VALUE);
        return false;
    }

    dcbSerialParams.BaudRate = CBR_115200; // You can use the 'baudrate' parameter
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;

    if (!SetCommState(hSerial.get(), &dcbSerialParams))
    {
        hSerial.reset();
        return false;
    }

    // Set timeouts
    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 5;
    timeouts.ReadTotalTimeoutConstant = 5;
    timeouts.ReadTotalTimeoutMultiplier = 1;
    timeouts.WriteTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutMultiplier = 10;

    if (!SetCommTimeouts(hSerial.get(), &timeouts))
    {
        hSerial.reset();
        return false;
    }

    return true;
}

void WindowsPlatform::closeSerialPort()
{
    hSerial.reset(INVALID_HANDLE_VALUE);
}

bool WindowsPlatform::writeSerial(const std::string &data)
{
    if (hSerial.get() == INVALID_HANDLE_VALUE) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - lastSerialAttempt_).count();

        if (elapsed >= SERIAL_RETRY_DELAY_MS) {
            lastSerialAttempt_ = now;
            logMessage("Attempting to reconnect serial port...");
            if (openSerialPort("COM3", 115200)) {
                logMessage("Serial port reconnected successfully");
            }
        }
        return false;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(hSerial.get(), data.c_str(), (DWORD)data.length(), &bytesWritten, NULL)) {
        DWORD err = GetLastError();
        logMessage("WriteFile failed (Error " + std::to_string(err) + "), closing serial port");
        closeSerialPort();
        return false;
    }

    if (bytesWritten != data.length()) {
        logMessage("Partial write detected (" + std::to_string(bytesWritten) + " of " + std::to_string(data.length()) + " bytes)");
        return false;
    }
    return true;
}

bool WindowsPlatform::readSerial(std::string &readData) {
    if (!hSerial) {
        return false;
    }

    if (hSerial == INVALID_HANDLE_VALUE) {
        return false;
    }

    char buffer[256];
    DWORD bytesRead = 0;

    if (ReadFile(hSerial.get(), buffer, sizeof(buffer) -1, &bytesRead, NULL)) {
        if (bytesRead > 0) {
            readData.append(buffer, bytesRead);
            return true;
        }
    }
    else {
		DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
			logMessage("Error reading from serial port: " + std::to_string(err));
        }
    }
    return false;
}

void WindowsPlatform::showMessageDialog(const std::string& title, const std::string& message) {
    std::wstring wTitle(title.begin(), title.end());
    std::wstring wMessage(message.begin(), message.end());

    MessageBoxW(
        NULL,
        wMessage.c_str(),
        wTitle.c_str(),
        MB_OK | MB_ICONINFORMATION
    );
}

void WindowsPlatform::logMessage(const std::string &message)
{
    if (std::string(VERSION_EXTRAVERSION) != "rc") {
        return;
    }

    const size_t MAX_LOG_SIZE = 10 * 1024 * 1024;

    std::ifstream checkSize(LOG_FILE_PATH, std::ios::ate | std::ios::binary);
    if (checkSize.is_open()) {
        size_t fileSize = checkSize.tellg();
        checkSize.close();

        if (fileSize >= MAX_LOG_SIZE) {
            std::wstring backupPath = std::wstring(LOG_FILE_PATH) + L".old";
            DeleteFileW(backupPath.c_str());
            MoveFileW(LOG_FILE_PATH, backupPath.c_str());
        }
    }

    DWORD fileAttr = GetFileAttributesW(LOG_DIR_PATH);
    if (fileAttr == INVALID_FILE_ATTRIBUTES)
    {
        CreateDirectoryW(LOG_DIR_PATH, NULL);
    }

    std::ofstream logFile(LOG_FILE_PATH, std::ios::app);
    if (logFile.is_open())
    {
        SYSTEMTIME time;
        GetLocalTime(&time);

        logFile << "[" << time.wYear << "-"
            << std::setfill('0') << std::setw(2) << time.wMonth << "-"
            << std::setfill('0') << std::setw(2) << time.wDay << " "
            << std::setfill('0') << std::setw(2) << time.wHour << ":"
            << std::setfill('0') << std::setw(2) << time.wMinute << ":"
            << std::setfill('0') << std::setw(2) << time.wSecond << "."
            << std::setfill('0') << std::setw(3) << time.wMilliseconds << "] "
            << message << std::endl;
        logFile.close();
    }
}

int WindowsPlatform::getCpuUsagePercent() {
    return cpuCache_.get([this]() {return getCpuUsagePercentImpl();  });
}

int WindowsPlatform::getCpuUsagePercentImpl()
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
    return ramCache_.get([this]() { return getRamUsagePercentImpl(); });
}

int WindowsPlatform::getRamUsagePercentImpl() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);

    if (GlobalMemoryStatusEx(&statex)) {
        return (int)statex.dwMemoryLoad;
    }
    
    return 0;
}

std::string WindowsPlatform::getFreeDiskSpaceGB(const std::string& drivePath) {
	return diskSpaceCache_.get([this, drivePath]() { return getFreeDiskSpaceGBImpl(drivePath); });
}

std::string WindowsPlatform::getFreeDiskSpaceGBImpl(const std::string& drivePath) {
    ULARGE_INTEGER freeBytesAvailableToCaller;
    ULARGE_INTEGER totalNumberOfBytes;
    ULARGE_INTEGER totalNumberOfFreeBytes;
    
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
    return windowsUpdateCache_.get([this]() { return getWindowsUpdateStateImpl(); });
}

std::string WindowsPlatform::getWindowsUpdateStateImpl() {
    HKEY hKey;

    const REGSAM samDesired = KEY_READ | KEY_WOW64_64KEY;

    LONG lResult = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired",
        0,
        samDesired,
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
        samDesired,
        &hKey
    );

    if (lResult == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "Pending Reboot";
    }

    return "Up to Date or Unknown";
}

void WindowsPlatform::updatePdhMetrics() {
	std::lock_guard<std::mutex> lock(platformMutex_);
    
    if (m_hQuery.get()) {
        PdhCollectQueryData((PDH_HQUERY)m_hQuery.get());
    }
    updateCpuTimes();
}

float WindowsPlatform::getDiskQueueLength() {
	return diskQueueCache_.get([this]() { return getDiskQueueLengthImpl(); });
}

float WindowsPlatform::getDiskQueueLengthImpl()
{
    if (m_hQuery.get() == NULL || m_hDiskCounter == NULL) return 0.0f;

    PDH_FMT_COUNTERVALUE value;
    // PdhCollectQueryData is now called externally in updatePdhMetrics()
    if (PdhGetFormattedCounterValue(m_hDiskCounter, PDH_FMT_FLOAT, NULL, &value) == ERROR_SUCCESS) {
        return (float)value.doubleValue;
    }
    return 0.0f;
}

float WindowsPlatform::getNetworkRetransRate() {
    return netRetransCache_.get([this]() { return getNetworkRetransRateImpl(); });
}

float WindowsPlatform::getNetworkRetransRateImpl()
{
    if (m_hQuery.get() == NULL || m_hNetRetransCounter == NULL) return 0.0f;

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

    if (currentState == SERVICE_START_PENDING || currentState == SERVICE_STOP_PENDING) {
        g_service_status.dwControlsAccepted = 0;
        g_service_status.dwCheckPoint = service_checkpoint_++;
    }
    else {
        g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        g_service_status.dwCheckPoint = 0;
        if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
            service_checkpoint_ = 1;
        }
    }

    SetServiceStatus(g_status_handle, &g_service_status);
}

std::string WindowsPlatform::getSystemUptime() {
	return uptimeCache_.get([this]() { return getSystemUptimeImpl(); });
}

std::string WindowsPlatform::getSystemUptimeImpl()
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
	return gpuDriverCache_.get([this]() { return getGpuDriverInfoImpl(); });
}

std::string WindowsPlatform::getGpuDriverInfoImpl() {
    std::string result = "GPU: Not Found.";
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

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
        0,
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

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) break;

        VARIANT vtPropName, vtPropVersion;
        HRESULT hrGet1 = pclsObj->Get(L"Name", 0, &vtPropName, 0, 0);
        HRESULT hrGet2 = pclsObj->Get(L"DriverVersion", 0, &vtPropVersion, 0, 0);

        if (hrGet1 == S_OK && hrGet2 == S_OK) {
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
                pclsObj = NULL;
                goto cleanup;
            }
        }
        VariantClear(&vtPropName);
        VariantClear(&vtPropVersion);
        pclsObj->Release();
        pclsObj = NULL;
    }

cleanup:
    if (pclsObj) pclsObj->Release();
    if (pEnumerator) pEnumerator->Release();
    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();

    return result;
}

float WindowsPlatform::getGpuUsagePercent() {
    return gpuUsageCache_.get([this]() { return getGpuUsagePercentImpl(); });
}

float WindowsPlatform::getGpuUsagePercentImpl() {
    if (m_hQuery.get() == NULL || m_hGpuTotalCounter == NULL) return 0.0f;

    PDH_FMT_COUNTERVALUE_ITEM_W* items = nullptr;
    DWORD bufferSize = 0;
    DWORD item_count = 0;
    float totalUsage = 0.0f;
    PDH_STATUS status;

    status = PdhGetFormattedCounterArrayW(m_hGpuTotalCounter, PDH_FMT_FLOAT, &bufferSize, &item_count, nullptr);

    if (status != PDH_MORE_DATA && status != ERROR_SUCCESS) {
        return 0.0f;
    }

    std::vector<BYTE> buffer(bufferSize);
    items = (PDH_FMT_COUNTERVALUE_ITEM_W*)buffer.data();

    status = PdhGetFormattedCounterArrayW(m_hGpuTotalCounter, PDH_FMT_FLOAT, &bufferSize, &item_count, items);

    if (status == ERROR_SUCCESS) {
        for (DWORD i = 0; i < item_count; i++) {
            totalUsage += (float)items[i].FmtValue.doubleValue;
        }
    }

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
    return highRamProcsCache_.get([this]() { return getHighRamProcessesImpl(); });
}

std::string WindowsPlatform::getHighRamProcessesImpl() {
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
    g_service_status.dwServiceSpecificExitCode = 0;
    g_service_status.dwCheckPoint = 0;
    g_service_status.dwWaitHint = 0;
    service_checkpoint_ = 1;
    stop_requested_.store(false);
    reportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
}

HANDLE WindowsPlatform::getStopEvent()
{
    return g_stop_event.get();
}

void WindowsPlatform::startService()
{
    startSessionMonitor();
    if (on_start_callback)
        on_start_callback();
}

void WindowsPlatform::stopService(const std::string& stopReason)
{
    if (stop_requested_.exchange(true)) {
        logMessage("Ignoring duplicate service stop request: " + stopReason);
        return;
    }

    logMessage("Service stop requested: " + stopReason);
    reportStatus(SERVICE_STOP_PENDING, NO_ERROR, 15000);
    stopSessionMonitor();
    if (on_stop_callback)
        on_stop_callback(stopReason);
    SetEvent(g_stop_event.get());
}

#endif // _WIN32
