#include <winsock2.h>      // Modern Winsock (must come before windows.h)
#include <ws2tcpip.h>      // IPv4 helpers
#include <windows.h>       // AFTER winsock2
#include <shellapi.h>
#include <thread>
#include <mutex>
#include <memory>
#include <string>
#include <tuple>
#include <vector>
#include <sstream>
#include <iphlpapi.h>      // For GetAdaptersAddresses
#include <lmcons.h>        // For UNLEN in getLoggedInUser
#include <cstring>         // for strcpy_s
#include <shellapi.h>
#include <thread>
#include <string>
#include <vector>
#include <locale>
#include <codecvt>
#include <iomanip>
#include <wtsapi32.h>    

#include "version.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Wtsapi32.lib")

#define DEV_VERSION

#ifdef DEV_VERSION
#define SERIAL_PORT "\\\\.\\COM4"
#else
#define SERIAL_PORT "\\\\.\\COM1"
#endif

// Options on tray app 
#define WM_TRAYICON (WM_USER + 1) 
#define ID_TRAY_EXIT 1001
#define ID_TRAY_ABOUT 1002

NOTIFYICONDATA nid = {0};
HMENU hMenu;

// Helper functions to convert macro values to string
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Wtsapi32.lib")


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
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_PRESHUTDOWN | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;    // stand alone process
    // Define what events can be handled
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP |SERVICE_ACCEPT_PRESHUTDOWN | SERVICE_ACCEPT_SHUTDOWN; 
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
            SetEvent(g_StopEvent);                                    // Set our internal stop 

        case SERVICE_CONTROL_PRESHUTDOWN:
            passPowerStateToSerial("shutdownRequest");
            break;

        case SERVICE_CONTROL_SHUTDOWN:
            passPowerStateToSerial("controlShutdown");
            break;

        default:
            val = std::to_string(static_cast<int>(ctrlCode));
            passSessionStateToSerial(val);        
            break;
    }    
}



//... Windows service boiler plate functionality





struct NetworkInterface {
    std::string name;
    std::string ipv4;
    std::string ipv6;
    std::string dhcp;    // "DHCP" or "Static"
    std::string linkStatus;  // "Up" or "Down"
    std::string macAddress;
    

    // overload the != to allow lines like if (net1 != net1) {...}  
    bool operator!=(const NetworkInterface& other) const {
        return std::tie(name, ipv4, ipv6, dhcp, linkStatus, macAddress) != 
        std::tie(other.name, other.ipv4, other.ipv6, other.dhcp, other.linkStatus, other.macAddress);
    }

    bool operator==(const NetworkInterface& other) const {
        return std::tie(name, ipv4, ipv6, linkStatus, dhcp, macAddress) ==
               std::tie(other.name, other.ipv4, other.ipv6, other.linkStatus,  other.dhcp, other.macAddress);
    }

    void Clear() {
        name.clear();
        ipv4.clear();
        ipv6.clear();
        dhcp.clear();
        linkStatus.clear();
        macAddress.clear();
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

void sendLineToBmc( HANDLE hSerial, const std::string& output_string) {
    DWORD bytesWritten;
    std::string str = output_string + "\r\n";
    WriteFile(hSerial, str.c_str(), (DWORD)str.size(), &bytesWritten, NULL); 
}


std::string getVersionString() {
    // Build version string
    std::string versionString = std::string(TOSTRING(VERSION_YEAR) "." TOSTRING(VERSION_MONTH) "." TOSTRING(VERSION_RELEASE) "_" VERSION_EXTRAVERSION);
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

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, NULL, NULL);
    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size_needed, NULL, NULL);
    result.resize(strlen(result.c_str()));  // Trim extra nulls
    return result;
}

typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

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
    DWORD size = 0;
    NetworkInterface* currentNetworks[] = { &currentState->network1, &currentState->network2 };
    int interfaceIndex = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &size);

    std::vector<BYTE> data(size);
    IP_ADAPTER_ADDRESSES *adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(data.data());

    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &size) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *adapter = adapters; adapter; adapter = adapter->Next) {
            if (adapter->IfType != IF_TYPE_ETHERNET_CSMACD) continue; // Skip non-Ethernet

            // Convert FriendlyName from wide to UTF-8
            std::string name = adapter->FriendlyName ? WideToUtf8(adapter->FriendlyName) : "Unknown";
            std::string linkStatus = (adapter->OperStatus == IfOperStatusUp) ? "up" : "down";
            std::string ipv4 = "none", ipv6 = "none";
            std::string dhcp = (adapter->Flags & IP_ADAPTER_DHCP_ENABLED) ? "dhcp" : "static";

            // Format MAC address
            std::ostringstream macStream;
            for (ULONG i = 0; i < adapter->PhysicalAddressLength; i++) {
                if (i != 0) macStream << ":";
                macStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(adapter->PhysicalAddress[i]);
            }
            std::string macAddress = macStream.str();

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

            if (currentNetworks[interfaceIndex]->linkStatus != linkStatus ) {
                currentNetworks[interfaceIndex]->linkStatus = linkStatus;
                valueChanged = true;
            }

            // macAddress obviously wont change, but this gets the first value into the struct
            if (currentNetworks[interfaceIndex]->macAddress != macAddress ) {
                currentNetworks[interfaceIndex]->macAddress = macAddress;
                valueChanged = true;
            }
            
            if (valueChanged) {
                sendLineToBmc(hSerial,  std::string(name) + ", " + linkStatus + ", " + ipv6 + ", " + ipv4 + ", " + dhcp + ", " + macAddress  );
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
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    LPTSTR buffer = NULL;
    DWORD bytesReturned = 0;

    if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, &buffer, &bytesReturned)) {
        std::string username = buffer ? std::string(buffer) : "none";
        WTSFreeMemory(buffer);

        if (currentState->username != username) {
            currentState->username = username;
            if (username == "" ) {
                sendLineToBmc(hSerial, "username, none");
            } else {
                sendLineToBmc(hSerial, "username, " + currentState->username);
            }

        }
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
    }
}
// Serial port thread
void serialThread() {
    // Setup serial port
    HANDLE hSerial = CreateFileA(SERIAL_PORT, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                 OPEN_EXISTING, 0, NULL);
    if (hSerial == INVALID_HANDLE_VALUE) return;

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

    char buffer[256];
    DWORD bytesRead;
    DWORD bytesWritten;
    std::string input;

     
    SystemState currentState;
    currentState.Clear();
    
    
    // Send Running sting
    std::string out = std::string("\r\nappVersion, " + getVersionString() + "\r\n" +
    "winVersion, " + GetRealWindowsVersion() + "\r\n" +
    "sessionState, 0\r\n");                              // send session state 0 - app running
    WriteFile(hSerial, out.c_str(), (DWORD)out.size(), &bytesWritten, NULL);
    
    
    // main serial input processing loop 
    while (true) {
        // Get latest state and push any changes
        checkSessionState(hSerial, & currentState);
        checkNetworkAdapters(hSerial, &currentState);
        checkLoggedInUser(hSerial, &currentState);
        checkHostName(hSerial, &currentState);
        checkPowerState(hSerial, & currentState);
        Sleep(500);  // ms

        

        // if (ReadFile(hSerial, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        //     input.append(buffer, bytesRead);
        //     // If carriage return detected...
        //     if (input.find("\r") != std::string::npos) {
        //         // Generate [status] response
        //         if (input.find("status") != std::string::npos) {

        //             // Clear current status so all fields are re-sent
        //             currentState.Clear();
        //         }
        //         input.clear();
        //     }
        // }

    }
    out = "serialThread closing...\r\n";
    WriteFile(hSerial, out.c_str(), (DWORD)out.size(), &bytesWritten, NULL);
    CloseHandle(hSerial) ;
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

    MSG msg;
    // Look for incoming windows messages until service told to stop...
    while (WaitForSingleObject(g_StopEvent, 0) != WAIT_OBJECT_0) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(50);  // ms 
    }

    WTSUnRegisterSessionNotification(hWnd);
    DestroyWindow(hWnd);
}



LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // Watch for windows system messages and handle accordingly
    std::string val;
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
            // System is asking if it's OK to shut down / log off
            passPowerStateToSerial("queryEndSession");
            return TRUE; // Return FALSE to cancel shutdown

        // // This is meant for user space oriented code
        // case WM_ENDSESSION:
        //     if (wParam) {
        //         if (lParam & ENDSESSION_LOGOFF) {
        //             passPowerStateToSerial("userLoggedOff");
        //         } else if (lParam & ENDSESSION_CRITICAL) {
        //             // Forces shutdown; apps can't veto
        //             passPowerStateToSerial("criticalShutdown");  
        //         } else {
        //             passPowerStateToSerial("shuttingDown");
        //         }
        //     } else {
        //         // Session was going to end but was cancelled
        //         passPowerStateToSerial("logoffCanceled");  
        //     }
        //     // Give time for message to get out
        //     Sleep(500);
        //     break; 
            

        case WM_DESTROY:
            // Un-register interest in Session notifications
            passPowerStateToSerial("appExit");
            Sleep(500);
            Shell_NotifyIcon(NIM_DELETE, &nid);
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}
