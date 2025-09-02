#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <shellapi.h>
#include <thread>
#include <mutex>
#include <memory>
#include <string>
#include <tuple>
#include <vector>
#include <sstream>
#include <iphlpapi.h>
#include <lmcons.h>
#include <cstring>
#include <cfgmgr32.h>
#include <locale.h>
#include <iomanip>
#include <WtsApi32.h>
#include <SetupAPI.h>
#include <netioapi.h>
#include <fstream>
#include <iostream>
#include <WbemIdl.h>
#include <comdef.h>
#include <chrono>

#include "version.h"
#include "git_info.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

std::ofstream g_logFile;
std::mutex g_logMutex;

std::chrono::steady_clock::time_point g_lastRotationTime;

// Helper functions to convert macro values to string
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)


// Top level Windows service boiler plate functionality...
SERVICE_STATUS        g_ServiceStatus = {};           // for passing status to windows
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
HANDLE                g_StopEvent = nullptr;
HWND                  g_hWnd = nullptr;

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD);

// Share power state string + mutex to pass from main windows into serial therad
std::shared_ptr<std::string> powerState = std::make_shared<std::string>("");
std::mutex powerStateMutex;

std::shared_ptr<std::string> sessionState = std::make_shared<std::string>("");
std::mutex sessionStateMutex;

struct NetworkInterface;
struct SystemState;

struct NetworkInterface {
    std::string name;
    std::string ipv4;
    std::string ipv6;
    std::string dhcp;             // "dhcp" or "static"
    std::string linkStatus;       // "up" or "down"
    std::string adapterStatus;    // "enabled" or "disabled"
    std::string macAddress;
    

    // overload the != to allow lines like if (net1 != net1) {...}  
    bool operator!=(const NetworkInterface& other) const {
        return std::tie(name, ipv4, ipv6, dhcp, linkStatus, macAddress, adapterStatus) != 
        std::tie(other.name, other.ipv4, other.ipv6, other.dhcp, other.linkStatus, other.macAddress, other.adapterStatus);
    }

    bool operator==(const NetworkInterface& other) const {
        return std::tie(name, ipv4, ipv6, linkStatus, dhcp, macAddress, adapterStatus) ==
               std::tie(other.name, other.ipv4, other.ipv6, other.linkStatus,  other.dhcp, other.macAddress, other.adapterStatus);
    }

    void Clear() {
        name.clear();
        ipv4.clear();
        ipv6.clear();
        dhcp.clear();
        linkStatus.clear();
        macAddress.clear();
        adapterStatus.clear();
    }
    
};

struct SystemState {
    NetworkInterface network1;
    NetworkInterface network2;
    std::string hostname;
    std::string powerState;
    std::string sessionState;
    std::string username;

    bool operator!=(const SystemState& other) const {
        return std::tie(network1, network2, hostname, powerState, sessionState, username) !=
               std::tie(other.network1, other.network2, other.hostname, other.powerState, other.sessionState, other.username);
    }

    void Clear() {
        network1.Clear();
        network2.Clear();
        hostname.clear();
        powerState.clear();
        sessionState.clear();
        username.clear();
    }
};

SystemState g_CurrentState;
std::mutex g_stateMutex;

// Helper function to work out if running a ga version
bool IsGaBuild() {
    return _stricmp(VERSION_EXTRAVERSION, "ga") == 0;
}

double GetFileAgeInDays(const wchar_t* filePath) {
    WIN32_FILE_ATTRIBUTE_DATA fileinfo;

    if (!GetFileAttributesExW(filePath, GetFileExInfoStandard, &fileinfo)) {
        return -1.0;
    }

    FILETIME ft = fileinfo.ftCreationTime;

    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    long long fileTime_100ns = uli.QuadPart;

    FILETIME CurrentFt;
    GetSystemTimeAsFileTime(&CurrentFt);
    ULARGE_INTEGER currentUli;
    currentUli.LowPart = CurrentFt.dwLowDateTime;
    currentUli.HighPart = CurrentFt.dwHighDateTime;
    long long currentTime_100ns = currentUli.QuadPart;

    long long diff = currentTime_100ns - fileTime_100ns;

    double seconds = static_cast<double>(diff) / 10000000.0;
    double days = seconds / (60.0 * 60.0 * 24.0);

    return days;
}

void PerformLogRotationInternal() {
    const wchar_t* logPath = L"C:\\ProgramData\\ahk\\CoreStation_Management_Service.log";
    const wchar_t* oldLogPath = L"C:\\ProgramData\\ahk\\CoreStation_Management_Service.old.log";

    double oldLogAge = GetFileAgeInDays(oldLogPath);
    if (oldLogAge != -1.0 && oldLogAge >= 14.0) {
        DeleteFileW(oldLogPath);
    }

    double currentLogAge = GetFileAgeInDays(logPath);
    if (currentLogAge != -1.0 && currentLogAge >= 7.0) {
        if (GetFileAgeInDays(oldLogPath) != -1.0 )
        {
            DeleteFileW(oldLogPath);
        }

        MoveFileW(logPath, oldLogPath);
    }
}


void InitLogging() {
    if (IsGaBuild()) {
        return;
    }

    PerformLogRotationInternal();

    const wchar_t* dirPath = L"C:\\ProgramData\\ahk";
    const wchar_t* logPath = L"C:\\ProgramData\\ahk\\CoreStation_Management_Service.log";

    DWORD fileAttr = GetFileAttributesW(dirPath);
    if (fileAttr == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryW(dirPath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            return;
        }
    }

    g_logFile.open(logPath, std::ios::out | std::ios::app);
    g_lastRotationTime = std::chrono::steady_clock::now();
}

void ShutdownLogging() {
    if (g_logFile.is_open()) {
        g_logFile.close();
    }
}

void LogMessage(const std::string& message) {
    
    if (!g_logFile.is_open()) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_logMutex);
    
    SYSTEMTIME time;
    GetLocalTime(&time);

    g_logFile << "[" << time.wYear << "-"
            << std::setw(2) << std::setfill('0') << time.wMonth << "-"
            << std::setw(2) << std::setfill('0') << time.wDay << " "
            << std::setw(2) << std::setfill('0') << time.wHour << ":"
            << std::setw(2) << std::setfill('0') << time.wMinute << ":"
            << std::setw(2) << std::setfill('0') << time.wSecond << "."
            << std::setw(3) << std::setfill('0') << time.wMilliseconds << "] "
            << message << std::endl;
}

void CheckAndRotateLogs() {
    LogMessage("Performing periodic log rotation check...");
    
    {
        std::lock_guard<std::mutex> lock(g_logMutex);

        if (g_logFile.is_open()) {
            g_logFile.close();
        }

        PerformLogRotationInternal();

        const wchar_t* logPath = L"C:\\ProgramData\\ahk\\CoreStation_Management_Service.log";
        g_logFile.open(logPath, std::ios::out | std::ios::app);
    }
    LogMessage("Log Rotation check finished.");
}

void passPowerStateToSerial(std::string powerStateStr) {
    std::lock_guard<std::mutex> lock(powerStateMutex);
    *powerState = powerStateStr;
}

void passSessionStateToSerial(std::string sessionStateStr) {
    std::lock_guard<std::mutex> lock(sessionStateMutex);
    *sessionState = sessionStateStr;
}


void RunMainWindow(); // We'll define this after

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        { (LPWSTR)L"CoreStationService", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
        { NULL, NULL }
    };
        
    if (!StartServiceCtrlDispatcherW(ServiceTable)) {
        // Running interactively (for debugging)
        RunMainWindow(); 
    }

    return 0;
}


// Called by the Service Control Manager (SCM) when service started via sc start or at system boot...
void WINAPI ServiceMain(DWORD, LPTSTR *) {
    
    // Register handler for control events (e.g. stop, pause etc) name==sc create <name>
    g_StatusHandle = RegisterServiceCtrlHandlerW(L"CoreStationService", ServiceCtrlHandler);
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;    // stand alone process
    // Define what events can be handled
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN; 
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;       // is starting up (not ready yet)
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);           // tell windows our current status

    g_StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);           // Create manual reset event object
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;             // tell windows we are now fully running
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Launch window to receive session notifications, power events
    RunMainWindow(); 

    // When RunMainWindow exits:
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;             // tell window we have stopped  
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// Called if Stop or Pause send by windows....
void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    std::string val;    
    switch(ctrlCode)
    {
        case SERVICE_CONTROL_STOP: 
            passPowerStateToSerial("controlStop");
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;    // tell windows we are stopping
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            SetEvent(g_StopEvent);
            break;

        // This case is called if windows shutdown is kicked off...
        case SERVICE_CONTROL_PRESHUTDOWN:
            LogMessage("PreShutdown");
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            passPowerStateToSerial("shutdownRequest");
            SetEvent(g_StopEvent);
            break;

        case SERVICE_CONTROL_SHUTDOWN:
            LogMessage("Shutdown");
            SetEvent(g_StopEvent);
            passPowerStateToSerial("controlShutdown");
            break;

        default:
            val = std::to_string(static_cast<int>(ctrlCode));
            passSessionStateToSerial(val);        
            break;
    }    
}

//... Windows service boiler plate functionality





void sendLineToBmc( HANDLE hSerial, const std::string& output_string) {
    DWORD bytesWritten;
    std::string str = output_string + "\r\n";
    LogMessage(output_string);
    WriteFile(hSerial, str.c_str(), (DWORD)str.size(), &bytesWritten, NULL); 
}


std::string getVersionString() {
    // Build version string
    std::string versionString = std::string(TOSTRING(VERSION_YEAR_1) "." TOSTRING(VERSION_YEAR_2) "." TOSTRING(VERSION_MONTH) "." TOSTRING(VERSION_RELEASE) "_" VERSION_EXTRAVERSION);
    if (std::string(VERSION_EXTRAVERSION) == "rc") {
        versionString += TOSTRING(VERSION_RC_NO);
    }
    else if (std::string(VERSION_EXTRAVERSION) == "adhoc") {
        versionString += TOSTRING(VERSION_ADHOC_NO);
    }
    return versionString;
}

// String to wide string helper function
std::wstring s2ws(const std::string& str) {
    return std::wstring(str.begin(), str.end());
}

std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    // Determine the required buffer size (including the null terminator).
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) {
        // An error occurred.
        return "";
    }

    std::string result(size_needed, 0);
    // Perform the conversion.
    int bytes_written = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size_needed, nullptr, nullptr);
    if (bytes_written > 0) {
        result.resize(bytes_written - 1); // Remove the null terminator from the string's size.
    } else {
        result.clear(); // Conversion failed.
    }
    return result;
}

typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

BOOL resetNetworkAdapter(const IP_ADAPTER_ADDRESSES* adapter) {

    if (!adapter) return FALSE;

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(nullptr, L"PCI", nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT);

    if (hDevInfo == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    SP_DEVINFO_DATA devInfoData = {};
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        WCHAR desc[256] = {};
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_FRIENDLYNAME, nullptr, (PBYTE)desc, sizeof(desc), nullptr)) {
            if (wcsstr(desc, adapter->FriendlyName)) {
                SP_PROPCHANGE_PARAMS params = {};
                params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
                params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
                params.Scope = DICS_FLAG_GLOBAL;
                params.HwProfile = 0;

                // Disable
                params.StateChange = DICS_DISABLE;
                SetupDiSetClassInstallParams(hDevInfo, &devInfoData, &params.ClassInstallHeader, sizeof(params));
                SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devInfoData);
                
                Sleep(200);  //ms

                // Enable
                params.StateChange = DICS_ENABLE;
                SetupDiSetClassInstallParams(hDevInfo, &devInfoData, &params.ClassInstallHeader, sizeof(params));
                SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devInfoData);

                SetupDiDestroyDeviceInfoList(hDevInfo);
                return TRUE;
            }
        }
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
    return FALSE;    

}

std::string GetFriendlyOSName() {
    HRESULT hres;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return "COM Init Failed";

    // Set security levels
    hres = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL
    );
    if (FAILED(hres)) {
        CoUninitialize();
        return "Security Init Failed";
    }

    // Obtain WMI locator
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                            IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return "WbemLocator Failed";
    }

    // Connect to WMI namespace
    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc
    );
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return "WMI Connect Failed";
    }

    // Set proxy security
    hres = CoSetProxyBlanket(
        pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE
    );
    if (FAILED(hres)) {
        pSvc->Release(); pLoc->Release();
        CoUninitialize();
        return "Proxy Blanket Failed";
    }

    // Execute WMI query
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT Caption FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator
    );
    if (FAILED(hres)) {
        pSvc->Release(); pLoc->Release(); CoUninitialize();
        return "Query Failed";
    }

    // Get result
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    std::string result = "Unknown OS";

    if (pEnumerator) {
        while (pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK) {
            VARIANT vtProp;
            VariantInit(&vtProp);
            if (SUCCEEDED(pclsObj->Get(L"Caption", 0, &vtProp, 0, 0))) {
                result = _bstr_t(vtProp.bstrVal);
                VariantClear(&vtProp);
            }
            pclsObj->Release();
        }
        pEnumerator->Release();
    }

    // Cleanup
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return result;
}

std::string GetRealWindowsVersion() {
    HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
    if (!hMod) return "Unknown Version";

    RtlGetVersionPtr fn = (RtlGetVersionPtr)::GetProcAddress(hMod, "RtlGetVersion");
    if (!fn) return "Unknown Version";

    RTL_OSVERSIONINFOW rovi = { 0 };
    rovi.dwOSVersionInfoSize = sizeof(rovi);
    if (fn(&rovi) != 0) return "Unknown Version";

    std::ostringstream version;
    version << rovi.dwMajorVersion << "."
            << rovi.dwMinorVersion << "."
            << rovi.dwBuildNumber
            << " Build " << rovi.dwBuildNumber;
    return version.str();
}

void checkNetworkAdapters(HANDLE hSerial, SystemState* currentState) {
    static std::vector<BYTE> data;
    DWORD size = 0;

    NetworkInterface* currentNetworks[] = { &currentState->network1, &currentState->network2 };
    int interfaceIndex = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &size) == ERROR_BUFFER_OVERFLOW) {
        data.resize(size);
    } else {
        return;
    }

    IP_ADAPTER_ADDRESSES* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(data.data());

    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &size) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *adapter = adapters; adapter; adapter = adapter->Next) {
            if (adapter->IfType != IF_TYPE_ETHERNET_CSMACD) continue; // Skip non-Ethernet

            std::ostringstream macStream;
            for (ULONG i = 0; i < adapter->PhysicalAddressLength; i++) {
                if (i != 0) macStream << ":";
                macStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(adapter->PhysicalAddress[i]);
            }
            std::string macAddress = macStream.str();

            if (macAddress.rfind("00:17:fd", 0) != 0 && macAddress.rfind("00:13:95", 0) != 0) {
                continue;
            }

            // We only handle a fixed number of network interfaces.
            if (interfaceIndex >= std::size(currentNetworks)) break;
 
            // Convert FriendlyName from wide to UTF-8
            // Explicitly construct a wstring from the PWCHAR.
            std::string name = adapter->FriendlyName ? WideToUtf8(std::wstring(adapter->FriendlyName)) : "Unknown";
            std::string linkStatus = (adapter->OperStatus == IfOperStatusUp) ? "up" : "down";
            std::string ipv4 = "none", ipv6 = "none";
            std::string dhcp = (adapter->Flags & IP_ADAPTER_DHCP_ENABLED) ? "dhcp" : "static";

            for (IP_ADAPTER_UNICAST_ADDRESS *addr = adapter->FirstUnicastAddress; addr; addr = addr->Next) {
                char buffer[INET6_ADDRSTRLEN] = {0};

                if (addr->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in *sa = reinterpret_cast<sockaddr_in *>(addr->Address.lpSockaddr);
                    inet_ntop(AF_INET, &(sa->sin_addr), buffer, sizeof(buffer));
                    ipv4 = buffer;
                } else if (addr->Address.lpSockaddr->sa_family == AF_INET6) {
                    sockaddr_in6 *sa6 = reinterpret_cast<sockaddr_in6 *>(addr->Address.lpSockaddr);
                    inet_ntop(AF_INET6, &(sa6->sin6_addr), buffer, sizeof(buffer));
                    ipv6 = buffer;
                }
            }

            // If only one port up, it will be returned first

            // Check for changes    
            bool valueChanged = false;
            if (currentNetworks[interfaceIndex]->name != name ) {
                currentNetworks[interfaceIndex]->name = name;
                valueChanged = true;
            }

            if (currentNetworks[interfaceIndex]->ipv6 != ipv6 ) {
                currentNetworks[interfaceIndex]->ipv6 = ipv6;
                valueChanged = true;
            }

            if (currentNetworks[interfaceIndex]->ipv4 != ipv4 ) {
                currentNetworks[interfaceIndex]->ipv4 = ipv4;
                valueChanged = true;
            }

            if (currentNetworks[interfaceIndex]->dhcp != dhcp ) {
                currentNetworks[interfaceIndex]->dhcp = dhcp;
                valueChanged = true;
            }

            // if (currentNetworks[interfaceIndex]->adapterStatus != adapterStatus ) {
            //     currentNetworks[interfaceIndex]->adapterStatus = adapterStatus;
            //     valueChanged = true;
            // }


            if (currentNetworks[interfaceIndex]->linkStatus != linkStatus ) {
                if (linkStatus == "down") {
                    // link just transistioned to "down"
                    resetNetworkAdapter(adapter);
                }
                currentNetworks[interfaceIndex]->linkStatus = linkStatus;
                valueChanged = true;
            }

            // macAddress obviously wont change, but this gets the first value into the struct
            if (currentNetworks[interfaceIndex]->macAddress != macAddress ) {
                currentNetworks[interfaceIndex]->macAddress = macAddress;
                valueChanged = true;
            }
            
            if (valueChanged) {
                // sendLineToBmc(hSerial,  std::string(name) + ", " + adapterStatus + ", " + linkStatus + ", " + ipv6 + ", " + ipv4 + ", " + dhcp + ", " + macAddress  );
                sendLineToBmc(hSerial, "network, " + macAddress + ", " + linkStatus + ", "+ ipv4 + ", " + ipv6 + ", " + dhcp + ", "  + std::string(name)  );
            }
            interfaceIndex += 1;
        }
    }
}

void checkHostName(HANDLE hSerial, SystemState* currentState) {
    char hostnameChar[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD hostnameLen = sizeof(hostnameChar);
    if (! GetComputerNameA(hostnameChar, &hostnameLen)) {
        strcpy_s(hostnameChar, sizeof(hostnameChar), "none");        
    }

    if (currentState->hostname !=std::string(hostnameChar)) {
        currentState->hostname = std::string(hostnameChar);
        sendLineToBmc(hSerial, "hostname, " +  currentState->hostname);
    }
}

void checkLoggedInUser(HANDLE hSerial, SystemState* currentState) {
    PWTS_SESSION_INFO pSessionInfo = NULL;
    DWORD sessionCount = 0;

    if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount)) {
        for (DWORD i = 0; i < sessionCount; ++i) {
            WTS_SESSION_INFO session = pSessionInfo[i];

            // Only consider active sessions
            if (session.State == WTSActive) {
                LPWSTR buffer = NULL;
                DWORD bytesReturned = 0;

                if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session.SessionId, WTSUserName, &buffer, &bytesReturned)) {
                    // buffer is now LPWSTR (wchar_t*), so we can construct a wstring.
                    std::string username = buffer ? WideToUtf8(std::wstring(buffer)) : "none";
                    WTSFreeMemory(buffer);

                    if (!username.empty() && currentState->username != username) {
                        currentState->username = username;
                        sendLineToBmc(hSerial, "username, " + currentState->username);
                        break; // Exit after finding first active user
                    } else if (username.empty() && currentState->username != "none") {
                        currentState->username = "none";
                        sendLineToBmc(hSerial, "username, none");
                        break;
                    }
                }
            }
        }
        WTSFreeMemory(pSessionInfo);
    }
}

void checkPowerState(HANDLE hSerial, SystemState* currentState) {
    // Get a local copy protected by mutex
    std::string powerStateLocalCopy;
    {
        std::lock_guard<std::mutex> lock(powerStateMutex);
        powerStateLocalCopy = *powerState;
    }
    // Check if it has changed since last pass
    if (currentState->powerState != powerStateLocalCopy) {
        currentState->powerState = powerStateLocalCopy;
        sendLineToBmc(hSerial, "powerState, " +  currentState->powerState);
    }
}

void checkSessionState(HANDLE hSerial, SystemState* currentState) {
    // Get a local copy protected by mutex
    std::string sessionStateLocalCopy;
    {
        std::lock_guard<std::mutex> lock(sessionStateMutex);
        sessionStateLocalCopy = *sessionState;
    }
    // Check if it has changed since last pass
    if (currentState->sessionState != sessionStateLocalCopy) {
        currentState->sessionState = sessionStateLocalCopy;
        sendLineToBmc(hSerial, "sessionState, " +  currentState->sessionState);

        // If WTS_SESSION_LOGOFF, clear user name 
        if (sessionStateLocalCopy == "6") {
            currentState->username = "none";
            sendLineToBmc(hSerial, "username, none");
        }
    }
}
// Serial port thread
void serialThread() {
    InitLogging();
    // Setup serial port
    LogMessage("------------------------------------------------------------------------------------------------");
    std::ostringstream logStr;
    logStr << "Starting service with "  << SERIAL_PORT;
    LogMessage(logStr.str());

    HANDLE hSerial = CreateFileA(SERIAL_PORT, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                 OPEN_EXISTING, 0, NULL);
    if (hSerial == INVALID_HANDLE_VALUE) {
        LogMessage("FATAL: Failed to open serial port. Service will stop.");
        ShutdownLogging();
        // Signal the main service to stop because we can't function.
        SetEvent(g_StopEvent);
        return;
    }

    DCB dcbSerialParams = {0};
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
    GetCommState(hSerial, &dcbSerialParams);
    dcbSerialParams.BaudRate = CBR_115200;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;
    SetCommState(hSerial, &dcbSerialParams);

    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 50;
    SetCommTimeouts(hSerial, &timeouts);
    
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        g_CurrentState.Clear();
    }
    
    // Send Running sting
    std::string out = std::string("\r\nappVersion, " + getVersionString() + "\r\n" +
                                      "gitDetails, " + GitInfo::BRANCH + ", " + GitInfo::HASH + "\r\n" +
                                      "buildTime, " + GitInfo::BUILD_TIME + "\r\n" +
                                      "winVersion, " + GetFriendlyOSName() + "\r\n" +
                                      "sessionState, 0\r\n");                            // send session state 0 - app running
    LogMessage(out.c_str());   
    DWORD bytesWritten;                                   
    WriteFile(hSerial, out.c_str(), (DWORD)out.size(), &bytesWritten, NULL);
    
    // main serial input processing loop 
    while (WaitForSingleObject(g_StopEvent, 1000) != WAIT_OBJECT_0) 
    {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::hours>(now - g_lastRotationTime);

        if (elapsed.count() >= 4) {
            CheckAndRotateLogs();
            g_lastRotationTime = now;
        }

        {
            std::lock_guard<std::mutex> lock(g_stateMutex);
            checkSessionState(hSerial, &g_CurrentState);
            checkNetworkAdapters(hSerial, &g_CurrentState);
            checkLoggedInUser(hSerial, &g_CurrentState);
            checkHostName(hSerial, &g_CurrentState);
            checkPowerState(hSerial, &g_CurrentState);
        }
    }

    LogMessage("Stop event received, serialThread closing...");
    out = "appClosing, service stopping...\r\n";
    WriteFile(hSerial, out.c_str(), (DWORD)out.size(), &bytesWritten, NULL);

    CloseHandle(hSerial);
    ShutdownLogging();
}

void namedPipeServerThread() {
    LogMessage("Named pipe server thread starting...");
    const wchar_t* pipeName = L"\\\\.\\pipe\\CoreStationInfoPipe";
    HANDLE hPipe = INVALID_HANDLE_VALUE;

    while (WaitForSingleObject(g_StopEvent, 0) != WAIT_OBJECT_0) {
        hPipe = CreateNamedPipeW(
            pipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            1024,
            1024,
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            LogMessage("Failed to create named pipe. retrying in 5s.");
            Sleep(5000);
            continue;
        }

        if (ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED)) {
            LogMessage("Client Connected to named pipe.");

            std::string stateData;
            {
                std::lock_guard<std::mutex> lock(g_stateMutex);
                std::stringstream ss;
                ss << "hostname=" << g_CurrentState.hostname << "\n";
                ss << "ipv4_1=" << g_CurrentState.network1.ipv4 << "\n";
                ss << "ipv4_2=" << g_CurrentState.network2.ipv4 << "\n";
                stateData = ss.str();
            }

            DWORD bytesWritten;
            if (!WriteFile(hPipe, stateData.c_str(), (DWORD)stateData.length(), &bytesWritten, NULL)) {
                LogMessage("Failed to write to named pipe.");
            } else {
                LogMessage("Send data to client: " + stateData);
            }
        } else {
            LogMessage("Client failed to connect to named pipe.");
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
    LogMessage("Named pipe server thread shutting down.");
}

// Forward declaration
LRESULT CALLBACK WindowProc(HWND, UINT, WPARAM, LPARAM);


// main...
void RunMainWindow() {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = TEXT("ServiceWindowClass");
    RegisterClass(&wc);

    HWND hWnd = CreateWindow(wc.lpszClassName, TEXT("AHK CoreStation HX"), 0, 0, 0, 0, 0,
                             HWND_MESSAGE, NULL, wc.hInstance, NULL);

    g_hWnd = hWnd;
    WTSRegisterSessionNotification(hWnd, NOTIFY_FOR_ALL_SESSIONS);                             

    std::thread(serialThread).detach();
    std::thread(namedPipeServerThread).detach();

    MSG msg;
    LogMessage("Main loop starting");
    // Look for incoming windows messages until service told to stop...
    while (WaitForSingleObject(g_StopEvent, 0) != WAIT_OBJECT_0) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(50);  // ms 
    }

    LogMessage("Main loop shuting down");    
    WTSUnRegisterSessionNotification(hWnd);
    DestroyWindow(hWnd);
}



LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // Watch for windows system messages and handle accordingly
    std::string val;
    std::string stateStr;
    std::stringstream ss;
    
    if (msg == WM_WTSSESSION_CHANGE) {

        switch (wParam) {
            case WTS_CONSOLE_CONNECT : stateStr = "WTS_CONSOLE_CONNECT"; break;
            case WTS_CONSOLE_DISCONNECT : stateStr = "WTS_CONSOLE_DISCONNECT"; break;
            case WTS_REMOTE_CONNECT : stateStr = "WTS_REMOTE_CONNECT"; break;
            case WTS_REMOTE_DISCONNECT: stateStr = "WTS_REMOTE_DISCONNECT"; break;
            case  WTS_SESSION_LOGON : stateStr = "WTS_SESSION_LOGON"; break;
            case WTS_SESSION_LOGOFF : stateStr = "WTS_SESSION_LOGOFF"; break;
            case WTS_SESSION_LOCK : stateStr = "WTS_SESSION_LOCK"; break;
            case WTS_SESSION_UNLOCK : stateStr = "WTS_SESSION_UNLOCK"; break;
            case WTS_SESSION_REMOTE_CONTROL : stateStr = "WTS_SESSION_REMOTE_CONTROL"; break;
            case WTS_SESSION_CREATE : stateStr = "WTS_SESSION_CREATE"; break;
            case  WTS_SESSION_TERMINATE: stateStr = "WTS_SESSION_TERMINATE"; break;
            default : stateStr = "unknown"; break;
               
        }

        ss << "WM_WTSSESSION_CHANGE: session(" + std::to_string(lParam) + ") " +  std::to_string(wParam)  + " " + stateStr ;

    } else {

        ss << "WindowProc() with msg 0x" << std::hex << msg
        << " wParam 0x" << std::hex << wParam
        << " lParam session ID 0x" << std::hex << lParam;
    }
    LogMessage(ss.str());

    switch (msg) {


        case WM_WTSSESSION_CHANGE:
            /* wParam defines the new state, defined in WinUser.h
            C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um
            
                    APP_STARTING                       0
            #define WTS_CONSOLE_CONNECT                1
            #define WTS_CONSOLE_DISCONNECT             2
            #define WTS_REMOTE_CONNECT                 3
            #define WTS_REMOTE_DISCONNECT              4
            #define WTS_SESSION_LOGON                  5
            #define WTS_SESSION_LOGOFF                 6
            #define WTS_SESSION_LOCK                   7
            #define WTS_SESSION_UNLOCK                 8
            #define WTS_SESSION_REMOTE_CONTROL         9
            #define WTS_SESSION_CREATE                 10
            #define WTS_SESSION_TERMINATE              11   */
            
            // convert session state to its integer value
            val = std::to_string(static_cast<int>(wParam));
            passSessionStateToSerial(val);
            
        break;

        case WM_QUERYENDSESSION:
            passPowerStateToSerial("queryEndSession");
            return TRUE;

        case WM_DESTROY:
            passPowerStateToSerial("appExit");
            Sleep(500);
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}