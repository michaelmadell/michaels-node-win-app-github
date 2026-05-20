#ifdef _WIN32
#include "TrayApp.h"
#include "../../platform/WindowsPlatform.h"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <windowsx.h>

// Define constants
const char* const TrayApp::TRAY_PIPE_NAME = "\\\\.\\pipe\\corestation_tray";

/**
 * @brief Trim whitespace from a string
 */
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

TrayApp::TrayApp(WindowsPlatform* platform) : platform_(platform) {
    stopEvent_ = CreateEvent(NULL, TRUE, FALSE, NULL);
}

TrayApp::~TrayApp() {
    Stop();
    if (stopEvent_) {
        CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
    }
}

bool TrayApp::Start() {
    stop_ = false;

    if (stopEvent_) {
        ResetEvent(stopEvent_);
    }

    uiThread_ = std::thread([this]() { UiThreadProc(); });

    {
        std::unique_lock<std::mutex> lock(dataMutex_);
        hwndReadyCv_.wait_for(lock, std::chrono::seconds(5),
            [this]() { return hwnd_ != nullptr || stop_.load(); });
    }

    pipeThread_ = std::thread([this]() { PipeThreadProc(); });
    return true;
}

void TrayApp::Stop() {
    if (stop_.exchange(true)) {
        return;
    }

    if (stopEvent_) {
        SetEvent(stopEvent_);
    }

    if (hwnd_) {
        PostMessage(hwnd_, WM_CLOSE, 0, 0);
    }

    if (pipeThread_.joinable()) {
        pipeThread_.join();
    }
    if (uiThread_.joinable()) {
        uiThread_.join();
    }
}

void TrayApp::Log(const std::string& msg) {
    if (platform_) {
        platform_->logMessage("[Tray] " + msg);
    }
}

void TrayApp::UpdateData(const std::string& hostname, const std::string& ip, const std::string& uptime) {
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        hostname_ = hostname.empty() ? "Unknown" : hostname;
        ip_ = ip.empty() ? "Unknown" : ip;
        uptime_ = uptime.empty() ? "Unknown" : uptime;
    }

    if (hwnd_) {
        PostMessage(hwnd_, WM_TRAY_UPDATE, 0, 0);
    }
}

void TrayApp::RefreshFromPlatform() {
    if (!platform_) return;

    std::string hostname = platform_->getHostname();
    std::string winVer   = platform_->getOsVersion() + " (" + platform_->getOsBuild() + ")";

    auto ifaces = platform_->getNetworkInterfaces();
    std::string ip;
    for (const auto& iface : ifaces) {
        if (iface.ipv4.empty()) continue;
        if (iface.ipv4.size() >= 8 && iface.ipv4.substr(0, 8) == "169.254.") continue;
        if (!ip.empty()) ip += ", ";
        ip += iface.ipv4;
    }
    if (ip.empty()) ip = "None";

    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        hostname_   = hostname.empty() ? "Unknown" : hostname;
        ip_         = ip;
        winVersion_ = winVer;
    }

    if (hwnd_) {
        PostMessage(hwnd_, WM_TRAY_UPDATE, 0, 0);
    }
}

void TrayApp::ApplyTooltip() {
    std::string tooltip;
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        tooltip = "Host: " + hostname_ + " | IP: " + ip_ + " | Up: " + uptime_;
    }

    if (tooltip.size() >= sizeof(nid_.szTip)) {
        tooltip.resize(sizeof(nid_.szTip) - 1);
    }

    std::wstring wtip(tooltip.begin(), tooltip.end());
    wcsncpy_s(nid_.szTip, wtip.c_str(), _TRUNCATE);
    nid_.uFlags = NIF_TIP;
    Shell_NotifyIconW(NIM_MODIFY, &nid_);
}

LRESULT CALLBACK TrayApp::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CREATE) {
        auto createStruct = reinterpret_cast<LPCREATESTRUCT>(lParam);
        if (createStruct && createStruct->lpCreateParams) {
            SetWindowLongPtr(hwnd, GWLP_USERDATA,
                reinterpret_cast<LONG_PTR>(createStruct->lpCreateParams));
        }
    }

    auto self = reinterpret_cast<TrayApp*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));

    switch (msg) {
    case WM_TRAY_UPDATE:
        if (self) {
            self->ApplyTooltip();
        }
        return 0;
    case WM_TRAY_CALLBACK:
        if (self) {
            UINT event = LOWORD(lParam);
            if (event == WM_RBUTTONUP || event == WM_LBUTTONUP) {
                // ShowContextMenu added in step 1.5
                self->Log("Tray clicked — context menu not yet implemented");
            }
        }
        return 0;
    case WM_TIMER:
        if (self && wParam == 1) {
            self->RefreshFromPlatform();
        }
        return 0;
    case WM_COMMAND:
        if (self && LOWORD(wParam) == 1001) {
            self->RefreshFromPlatform();
        }
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, 1);
        if (self) {
            Shell_NotifyIconW(NIM_DELETE, &self->nid_);
        }
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

void TrayApp::UiThreadProc() {
    HINSTANCE hInstance = GetModuleHandle(NULL);

    WNDCLASSEXW wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = TrayApp::WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(NULL, IDI_INFORMATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = windowClassName_.c_str();
    wcex.hIconSm = LoadIcon(NULL, IDI_INFORMATION);

    RegisterClassExW(&wcex);

    hwnd_ = CreateWindowExW(
        0,
        windowClassName_.c_str(),
        L"NodeWinTrayWindow",
        WS_OVERLAPPED,
        CW_USEDEFAULT, CW_USEDEFAULT,
        CW_USEDEFAULT, CW_USEDEFAULT,
        HWND_MESSAGE,
        NULL,
        hInstance,
        this);

    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        hwndReadyCv_.notify_all();
    }

    if (!hwnd_) {
        Log("Failed to create tray window");
        return;
    }

    ZeroMemory(&nid_, sizeof(NOTIFYICONDATAW));
    nid_.cbSize = sizeof(NOTIFYICONDATAW);
    nid_.hWnd = hwnd_;
    nid_.uID = 1;
    nid_.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    nid_.uCallbackMessage = WM_TRAY_CALLBACK;
    nid_.hIcon = LoadIcon(NULL, IDI_INFORMATION);

    {
        std::string tooltip;
        {
            std::lock_guard<std::mutex> lock(dataMutex_);
            tooltip = "Host: " + hostname_ + " | IP: " + ip_ + " | Up: " + uptime_;
        }

        if (tooltip.size() >= sizeof(nid_.szTip)) {
            tooltip.resize(sizeof(nid_.szTip) - 1);
        }

        std::wstring wtip(tooltip.begin(), tooltip.end());
        wcsncpy_s(nid_.szTip, wtip.c_str(), _TRUNCATE);
    }

    if (!Shell_NotifyIconW(NIM_ADD, &nid_)) {
        Log("Failed to add tray icon");
    }
    else {
        nid_.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &nid_);
        SetTimer(hwnd_, 1, 30000, NULL);
        RefreshFromPlatform();
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void TrayApp::PipeThreadProc() {
    Log("Named pipe listener started");

    while (!stop_.load()) {
        HANDLE hPipe = CreateNamedPipeA(
            TRAY_PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            1024,
            1024,
            0,
            NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            Log("Failed to create named pipe");
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        OVERLAPPED ovConnect = {};
        ovConnect.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        BOOL connected = ConnectNamedPipe(hPipe, &ovConnect);
        DWORD err = GetLastError();

        if (!connected && err == ERROR_IO_PENDING) {
            HANDLE handles[2] = { ovConnect.hEvent, stopEvent_ };
            DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0 + 1) {
                CancelIoEx(hPipe, &ovConnect);
            }
            else {
                connected = TRUE;
            }
        }
        else if (!connected && err == ERROR_PIPE_CONNECTED) {
            connected = TRUE;
        }

        if (connected && !stop_.load()) {
            for (;;) {
                char buffer[512] = { 0 };
                DWORD bytesRead = 0;
                OVERLAPPED ovRead = {};
                ovRead.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

                BOOL readOk = ReadFile(hPipe, buffer, sizeof(buffer) - 1, NULL, &ovRead);
                if (!readOk) {
                    DWORD readErr = GetLastError();
                    if (readErr == ERROR_IO_PENDING) {
                        HANDLE handles[2] = { ovRead.hEvent, stopEvent_ };
                        DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
                        if (wait == WAIT_OBJECT_0 + 1) {
                            CancelIoEx(hPipe, &ovRead);
                            CloseHandle(ovRead.hEvent);
                            break;
                        }
                        GetOverlappedResult(hPipe, &ovRead, &bytesRead, FALSE);
                    }
                    else {
                        CloseHandle(ovRead.hEvent);
                        break;
                    }
                }
                else {
                    GetOverlappedResult(hPipe, &ovRead, &bytesRead, TRUE);
                }

                CloseHandle(ovRead.hEvent);

                if (bytesRead == 0) {
                    break;
                }

                buffer[bytesRead] = '\0';
                std::string payload(buffer);

                std::istringstream iss(payload);
                std::string line;
                std::string host;
                std::string ip;
                std::string up;

                {
                    std::lock_guard<std::mutex> lock(dataMutex_);
                    host = hostname_;
                    ip = ip_;
                    up = uptime_;
                }

                while (std::getline(iss, line)) {
                    line = Trim(line);
                    if (line.empty()) continue;
                    size_t pos = line.find('=');
                    if (pos == std::string::npos) {
                        pos = line.find(':');
                    }
                    if (pos == std::string::npos) continue;
                    std::string key = Trim(line.substr(0, pos));
                    std::string value = Trim(line.substr(pos + 1));
                    std::transform(key.begin(), key.end(), key.begin(),
                        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    if (key == "hostname") {
                        host = value;
                    }
                    else if (key == "ip" || key == "ipaddress" || key == "address") {
                        ip = value;
                    }
                    else if (key == "uptime") {
                        up = value;
                    }
                }

                UpdateData(host, ip, up);
            }
        }

        if (ovConnect.hEvent) {
            CloseHandle(ovConnect.hEvent);
        }
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    Log("Named pipe listener stopped");
}

#endif // _WIN32