#include <winsock2.h>      // Modern Winsock (must come before windows.h)
#include <ws2tcpip.h>      // IPv4 helpers
#include <windows.h>       // AFTER winsock2
#include <shellapi.h>
#include <thread>
#include <string>
#include <vector>
#include <iphlpapi.h>      // For GetAdaptersAddresses

#include <windows.h>
#include <shellapi.h>
#include <thread>
#include <string>
#include <vector>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include "version.h"

// For  10 sec while loop
#include <chrono>
#include <thread>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define SERIAL_PORT "\\\\.\\COM4"
#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1001


NOTIFYICONDATA nid = {0};
HMENU hMenu;

// Helper functions to convert macro values to string
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)


// Utility: Get first IPv4 address
std::string getIPv4Address() {
    char buffer[INET_ADDRSTRLEN] = "0.0.0.0";
    DWORD size = 0;
    GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &size);

    std::vector<BYTE> data(size);
    IP_ADAPTER_ADDRESSES *adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(data.data());

    if (GetAdaptersAddresses(AF_INET, 0, nullptr, adapters, &size) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *adapter = adapters; adapter; adapter = adapter->Next) {
            for (IP_ADAPTER_UNICAST_ADDRESS *addr = adapter->FirstUnicastAddress; addr; addr = addr->Next) {
                SOCKADDR_IN *sa = reinterpret_cast<SOCKADDR_IN *>(addr->Address.lpSockaddr);
                inet_ntop(AF_INET, &(sa->sin_addr), buffer, sizeof(buffer));
                return buffer;
            }
        }
    }
    return "0.0.0.0";
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
    std::string input;
    
    // Send Hello string
    DWORD bytesWritten;

    std::string versionString = std::string(TOSTRING(VERSION_YEAR) "." TOSTRING(VERSION_MONTH) "." TOSTRING(VERSION_RELEASE) "_" VERSION_EXTRAVERSION);
    if (std::string(VERSION_EXTRAVERSION) == "rc") {
        versionString += TOSTRING(VERSION_RC_NO);
    }
    else if (std::string(VERSION_EXTRAVERSION) == "adhoc") {
        versionString += TOSTRING(VERSION_ADHOC_NO);
    }
     
    std::string out = std::string("NodeWinApp ") + versionString + " running...\r\n";

    WriteFile(hSerial, out.c_str(), (DWORD)out.size(), &bytesWritten, NULL);


    auto start = std::chrono::steady_clock::now();
    auto end = start + std::chrono::seconds(5);
    //while (true) {
    while (std::chrono::steady_clock::now() < end) {
        if (ReadFile(hSerial, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            
            input.append(buffer, bytesRead);

            if (input.find("\n") != std::string::npos) {
                if (input.find("status") != std::string::npos) {
                    std::string ip = "IP: " + getIPv4Address() + "\r\n";
                    DWORD bytesWritten;
                    WriteFile(hSerial, ip.c_str(), (DWORD)ip.size(), &bytesWritten, NULL);
                }
                input.clear();
            }
        }
    }
    out = "serialThread closing...\r\n";
    WriteFile(hSerial, out.c_str(), (DWORD)out.size(), &bytesWritten, NULL);
    CloseHandle(hSerial);
}

// Tray message handler
LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_TRAYICON && lParam == WM_RBUTTONUP) {
        POINT pt;
        GetCursorPos(&pt);
        SetForegroundWindow(hwnd);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    } else if (msg == WM_COMMAND && LOWORD(wParam) == ID_TRAY_EXIT) {
        Shell_NotifyIcon(NIM_DELETE, &nid);
        PostQuitMessage(0);
    } else if (msg == WM_DESTROY) {
        Shell_NotifyIcon(NIM_DELETE, &nid);
        PostQuitMessage(0);
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = TEXT("TrayAppClass");
    RegisterClass(&wc);

    HWND hwnd = CreateWindow(wc.lpszClassName, TEXT("AHK CoreStation"), 0, 0, 0, 0, 0,
                             NULL, NULL, hInstance, NULL);

    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    lstrcpy(nid.szTip, TEXT("AHK CoreStation HX"));
    Shell_NotifyIcon(NIM_ADD, &nid);

    hMenu = CreatePopupMenu();
    AppendMenu(hMenu, MF_STRING, ID_TRAY_EXIT, TEXT("Exit"));

    std::thread(serialThread).detach();

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}
