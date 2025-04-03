#include <winsock2.h>      // Modern Winsock (must come before windows.h)
#include <ws2tcpip.h>      // IPv4 helpers
#include <windows.h>       // AFTER winsock2
#include <shellapi.h>
#include <thread>
#include <string>
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
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <locale>
#include <codecvt>


#include "version.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define SERIAL_PORT "\\\\.\\COM4"

// Options on tray app
#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1001
#define ID_TRAY_ABOUT 1002

NOTIFYICONDATA nid = {0};
HMENU hMenu;

// Helper functions to convert macro values to string
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <locale>
#include <codecvt>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

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


std::string getNetworkAdaptersInfo() {
    DWORD size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &size);

    std::vector<BYTE> data(size);
    IP_ADAPTER_ADDRESSES *adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(data.data());

    std::ostringstream result;

    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &size) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *adapter = adapters; adapter; adapter = adapter->Next) {
            if (adapter->IfType != IF_TYPE_ETHERNET_CSMACD) continue; // Skip non-Ethernet

            // Convert FriendlyName from wide to UTF-8
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            std::string name = adapter->FriendlyName ? converter.to_bytes(adapter->FriendlyName) : "Unknown";

            std::string status = (adapter->OperStatus == IfOperStatusUp) ? "up" : "down";
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

            result << name << ", " << status << ", " << ipv6 << ", " << ipv4 << ", " << dhcp << ", " << macAddress << "\r\n";
        }
    }

    return result.str();
}

std::string getHostName() {
    std::ostringstream result;
    char hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD hostnameLen = sizeof(hostname);
    if (! GetComputerNameA(hostname, &hostnameLen)) {
        strcpy_s(hostname, sizeof(hostname), "none");        
    }
    result << "hostname, " << std::string(hostname) << "\r\n";
    return result.str();
}

std::string getLoggedInUser() {
    std::ostringstream result;
    
    char username[UNLEN + 1];
    DWORD usernameLen = sizeof(username);
    if (! GetUserNameA(username, &usernameLen)) {
        strcpy_s(username, sizeof(username), "none");        
    }

    result << "user, " << std::string(username) << "\r\n";
    return result.str();
}

// Serial port thread
void serialThread() {
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

     
    // Send Running sting
    std::string out = std::string("\r\nNodeWinApp ") + getVersionString() + " running...\r\n";
    WriteFile(hSerial, out.c_str(), (DWORD)out.size(), &bytesWritten, NULL);

    // main serial input processing loop 
    while (true) {
        if (ReadFile(hSerial, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            input.append(buffer, bytesRead);
            // If carriage return detected...
            if (input.find("\r") != std::string::npos) {
                // Generate [status] response
                if (input.find("status") != std::string::npos) {
                    // Version    
                    std::string version = std::string("NodeWinApp, ") + getVersionString() + "\r\n";
                    WriteFile(hSerial, version.c_str(), (DWORD)version.size(), &bytesWritten, NULL);
                    // Network 
                    std::string network = getNetworkAdaptersInfo();
                    WriteFile(hSerial, network.c_str(), (DWORD)network.size(), &bytesWritten, NULL);
                    // User
                    std::string user = getLoggedInUser();
                    WriteFile(hSerial, user.c_str(), (DWORD)user.size(), &bytesWritten, NULL);
                    // Hostname
                    std::string hostname = getHostName();
                    WriteFile(hSerial, hostname.c_str(), (DWORD)hostname.size(), &bytesWritten, NULL);

                }
                input.clear();
            }
        }
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

    HWND hwnd = CreateWindow(wc.lpszClassName, TEXT("AHK CoreStation HX"), 0, 0, 0, 0, 0,
                             NULL, NULL, hInstance, NULL);

    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
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

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_TRAYICON:
            if (LOWORD(lParam) == WM_RBUTTONUP) {
                POINT pt;
                GetCursorPos(&pt);
                SetForegroundWindow(hwnd);
                TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, NULL);
            }
            break;
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_TRAY_ABOUT: {
                    std::wstring versionText = s2ws(getVersionString());

                    std::wstring message = L"Version " + versionText;
                    MessageBoxW(hwnd, message.c_str(), L"Amulet Hotkey CoreStation HX", MB_ICONINFORMATION);
                    break;
                }
                case ID_TRAY_EXIT: {
                    Shell_NotifyIcon(NIM_DELETE, &nid);
                    PostQuitMessage(0);
                    break;
                }
            }
            break;
        case WM_DESTROY:
            Shell_NotifyIcon(NIM_DELETE, &nid);
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}
