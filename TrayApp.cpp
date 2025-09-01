#include <windows.h>
#include <shellapi.h>
#include <string>
#include <sstream>
#include <map>

#define WM_TRAYICON (WM_USER + 1)

// Global variables
NOTIFYICONDATAW nid = {}; // Use the wide-character version
HWND g_hWnd = NULL;
// CHANGE: Use std::wstring for Unicode strings
std::wstring g_hostname = L"Loading...";
std::wstring g_ipv4_1 = L"Loading...";
std::wstring g_ipv4_2 = L"Loading...";

// Function to query the service for information
void QueryServiceForInfo() {
    const wchar_t* pipeName = L"\\\\.\\pipe\\CoreStationInfoPipe";
    HANDLE hPipe;
    char buffer[1024]; // Pipe communication can remain multi-byte
    DWORD bytesRead;

    hPipe = CreateFileW(
        pipeName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hPipe != INVALID_HANDLE_VALUE) {
        if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            buffer[bytesRead] = '\0';
            
            std::stringstream ss(buffer);
            std::string line;
            std::map<std::string, std::string> data;
            while(std::getline(ss, line, '\n')) {
                size_t equals_pos = line.find('=');
                if (equals_pos != std::string::npos) {
                    std::string key = line.substr(0, equals_pos);
                    std::string value = line.substr(equals_pos + 1);
                    data[key] = value;
                }
            }
            
            // Convert from multi-byte (from pipe) to wide-character (for GUI)
            auto to_wstring = [](const std::string& s) {
                int len;
                int slength = (int)s.length() + 1;
                len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0); 
                wchar_t* buf = new wchar_t[len];
                MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
                std::wstring r(buf);
                delete[] buf;
                return r;
            };

            if (data.count("hostname")) g_hostname = to_wstring(data["hostname"]); else g_hostname = L"N/A";
            if (data.count("ipv4_1")) g_ipv4_1 = to_wstring(data["ipv4_1"]); else g_ipv4_1 = L"N/A";
            if (data.count("ipv4_2")) g_ipv4_2 = to_wstring(data["ipv4_2"]); else g_ipv4_2 = L"N/A";

        } else {
             g_hostname = L"Error reading pipe";
             g_ipv4_1 = L"N/A";
             g_ipv4_2 = L"N/A";
        }
        CloseHandle(hPipe);
    } else {
        g_hostname = L"Service not running";
        g_ipv4_1 = L"N/A";
        g_ipv4_2 = L"N/A";
    }
}

void ShowContextMenu() {
    POINT pt;
    GetCursorPos(&pt);

    HMENU hMenu = CreatePopupMenu();
    
    // CHANGE: Construct wstrings for the menu
    std::wstring titleStr = L"CoreStation HX Agent";
    std::wstring hostMenuStr = L"Hostname: " + g_hostname;
    std::wstring ip1MenuStr = L"IP Address 1: " + g_ipv4_1;
    std::wstring ip2MenuStr = L"IP Address 2: " + g_ipv4_2;

    // CHANGE: Use AppendMenuW (or the generic AppendMenu)
    AppendMenuW(hMenu, MF_STRING, 0, titleStr.c_str());
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, 0, hostMenuStr.c_str());
    AppendMenuW(hMenu, MF_STRING, 0, ip1MenuStr.c_str());
    AppendMenuW(hMenu, MF_STRING, 0, ip2MenuStr.c_str());

    SetForegroundWindow(g_hWnd);

    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, g_hWnd, NULL);
    DestroyMenu(hMenu);
}


LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            SetTimer(hWnd, 1, 5000, NULL);
            QueryServiceForInfo();
            break;

        case WM_TIMER:
            if (wParam == 1) {
                QueryServiceForInfo();
            }
            break;

        case WM_TRAYICON:
            if (lParam == WM_RBUTTONUP) {
                QueryServiceForInfo();
                ShowContextMenu();
            }
            break;

        case WM_DESTROY:
            Shell_NotifyIconW(NIM_DELETE, &nid); // Use wide version
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    // CHANGE: Use a wide character string for the class name.
    const wchar_t* CLASS_NAME = L"TrayAppClass";
    
    WNDCLASSW wc = {}; // Use the wide-character version
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClassW(&wc); // Use the wide-character version

    // CHANGE: Use wide character strings for window creation
    g_hWnd = CreateWindowExW(0, CLASS_NAME, L"Tray App", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, NULL);
    if (!g_hWnd) {
        return 1;
    }

    nid.cbSize = sizeof(NOTIFYICONDATAW);
    nid.hWnd = g_hWnd;
    nid.uID = 100;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIcon(NULL, IDI_INFORMATION);
    // CHANGE: Use wcscpy_s for wide strings and the L"" literal prefix
    wcscpy_s(nid.szTip, L"CoreStation Info");

    Shell_NotifyIconW(NIM_ADD, &nid); // Use the wide-character version

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}