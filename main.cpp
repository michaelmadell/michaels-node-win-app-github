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
#include <windows.h>
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

//#define SERIAL_PORT "\\\\.\\COM4"
#define SERIAL_PORT "\\\\.\\COM1"

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

// Share power state string + mutex to pass from main windows into serial therad
std::shared_ptr<std::string> powerState = std::make_shared<std::string>("unknown");
std::mutex powerStateMutex;

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
    std::string username;

    bool operator!=(const SystemState& other) const {
        return std::tie(network1, network2, hostname, powerState, username) !=
               std::tie(other.network1, other.network2, other.hostname, other.powerState, other.username);
    }

    void Clear() {
        network1.Clear();
        network2.Clear();
        hostname.clear();
        powerState.clear();
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
    char username[UNLEN + 1];
    DWORD usernameLen = sizeof(username);
    if (! GetUserNameA(username, &usernameLen)) {
        strcpy_s(username, sizeof(username), "none");        
    }

    if (currentState->username !=std::string(username)) {
        currentState->username = std::string(username);
        sendLineToBmc(hSerial, "username, " +  currentState->username);
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
    std::string out = std::string("\r\nstate, windowsRunning\r\n") +
                                  "appVersion, " + getVersionString() + "\r\n" +
                                  "winVersion, " + GetRealWindowsVersion() + "\r\n" ;
    WriteFile(hSerial, out.c_str(), (DWORD)out.size(), &bytesWritten, NULL);


    // main serial input processing loop 
    while (true) {
        // Get latest state and push any changes
        checkNetworkAdapters(hSerial, &currentState);
        checkLoggedInUser(hSerial, &currentState);
        checkHostName(hSerial, &currentState);
        checkPowerState(hSerial, & currentState);

        

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
    CloseHandle(hSerial);
}

// Forward declaration
LRESULT CALLBACK WindowProc(HWND, UINT, WPARAM, LPARAM);

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = TEXT("TrayAppClass");
    RegisterClass(&wc);

    HWND hWnd = CreateWindow(wc.lpszClassName, TEXT("AHK CoreStation HX"), 0, 0, 0, 0, 0,
                             NULL, NULL, hInstance, NULL);

    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hWnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;

    // Load the icon from an .ico file
    nid.hIcon = (HICON)LoadImage(NULL, TEXT("ahk_white.ico"), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE);
    lstrcpy(nid.szTip, TEXT("AHK CoreStation HX"));
    Shell_NotifyIcon(NIM_ADD, &nid);

    hMenu = CreatePopupMenu();
    AppendMenu(hMenu, MF_STRING, ID_TRAY_ABOUT, TEXT("About"));
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, ID_TRAY_EXIT, TEXT("Exit"));

    std::thread(serialThread).detach();

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg); 
    }

    return 0;
}


void passPowerStateToSerial(std::string powerStateStr) {
    std::lock_guard<std::mutex> lock(powerStateMutex);
    *powerState = powerStateStr;
}

LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // Watch for windows system messages and handle accordingly
    switch (msg) {

        case WM_CREATE:
            // Register for session notifications (logon/logoff)
            WTSRegisterSessionNotification(hWnd, NOTIFY_FOR_THIS_SESSION);
            break;

        case WM_POWERBROADCAST:
            if (wParam == PBT_APMSUSPEND) {
                
               passPowerStateToSerial("suspending");
            } else if (wParam == PBT_APMRESUMEAUTOMATIC) {
                passPowerStateToSerial("resumed");
            }
            break;

        case WM_WTSSESSION_CHANGE:
            if (wParam == WTS_SESSION_LOGON) {
                passPowerStateToSerial("userLoggedIn");
            }
            break;

        case WM_QUERYENDSESSION:
            // System is asking if it's OK to shut down / log off
            passPowerStateToSerial("Shutdown Requested");
            return TRUE; // Return FALSE to cancel shutdown

        case WM_ENDSESSION:
            if (wParam) {
                if (lParam & ENDSESSION_LOGOFF) {
                    passPowerStateToSerial("userLoggedOff");
                } else {
                    passPowerStateToSerial("shuttingDown");
                }
            }
            break;            

        case WM_TRAYICON:
            if (LOWORD(lParam) == WM_RBUTTONUP) {
                POINT pt;
                GetCursorPos(&pt);
                SetForegroundWindow(hWnd);
                TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hWnd, NULL);
            }
            break;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_TRAY_ABOUT: {
                    std::wstring versionText = s2ws(getVersionString());

                    std::wstring message = L"Version " + versionText;
                    MessageBoxW(hWnd, message.c_str(), L"Amulet Hotkey CoreStation HX", MB_ICONINFORMATION);
                    break;
                }
                case ID_TRAY_EXIT: {
                    // Un-register interest in Session notifications
                    passPowerStateToSerial("appExitingCmd");
                    WTSUnRegisterSessionNotification(hWnd);
                    Shell_NotifyIcon(NIM_DELETE, &nid);
                    PostQuitMessage(0);
                    break;
                }
            }
            break;

        case WM_DESTROY:
            // Un-register interest in Session notifications
            passPowerStateToSerial("appExitingDstry");
            Shell_NotifyIcon(NIM_DELETE, &nid);
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}
