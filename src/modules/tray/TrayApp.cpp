#ifdef _WIN32
#include "TrayApp.h"
#include "../../platform/WindowsPlatform.h"
#include <windowsx.h>


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

    if (uiThread_.joinable()) {
        uiThread_.join();
    }
}

void TrayApp::Log(const std::string& msg) {
    if (platform_) {
        platform_->logMessage("[Tray] " + msg);
    }
}


void TrayApp::RefreshFromPlatform() {
    if (!platform_) return;

    std::string hostname = platform_->getHostname();
    std::string winVer   = platform_->getOsVersion() + " (" + platform_->getOsBuild() + ")";

    auto ifaces = platform_->getNetworkInterfaces();
    std::vector<std::string> ips;
    for (const auto& iface : ifaces) {
        if (iface.ipv4.empty()) continue;
        if (iface.ipv4.size() >= 8 && iface.ipv4.substr(0, 8) == "169.254.") continue;
        ips.push_back(iface.ipv4);
    }

    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        hostname_   = hostname.empty() ? "Unknown" : hostname;
        ips_        = std::move(ips);
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
        std::string ipList;
        for (const auto& ip : ips_) {
            if (!ipList.empty()) ipList += ", ";
            ipList += ip;
        }
        if (ipList.empty()) ipList = "None";
        tooltip = hostname_ + "  |  " + ipList + "  |  " + winVersion_;
    }

    // szTip is WCHAR[128]; clamp narrow source to 127 chars before widening
    const size_t maxChars = (sizeof(nid_.szTip) / sizeof(wchar_t)) - 1;
    if (tooltip.size() > maxChars) {
        tooltip.resize(maxChars);
    }

    std::wstring wtip(tooltip.begin(), tooltip.end());
    wcsncpy_s(nid_.szTip, wtip.c_str(), _TRUNCATE);
    nid_.uFlags = NIF_TIP;
    Shell_NotifyIconW(NIM_MODIFY, &nid_);
}

void TrayApp::ShowContextMenu(int x, int y) {
    HMENU hMenu = CreatePopupMenu();
    if (!hMenu) return;

    // Title row
    AppendMenuW(hMenu, MF_STRING | MF_GRAYED, 0, L"CoreStation HX Agent");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

    // Snapshot data under lock, convert to wide strings for the menu
    std::wstring hostItem, osItem;
    std::vector<std::wstring> ipItems;
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        hostItem = L"Host:  " + std::wstring(hostname_.begin(), hostname_.end());
        osItem   = L"OS:    " + std::wstring(winVersion_.begin(), winVersion_.end());
        for (const auto& ip : ips_) {
            ipItems.push_back(L"IP:    " + std::wstring(ip.begin(), ip.end()));
        }
    }
    if (ipItems.empty()) {
        ipItems.push_back(L"IP:    None");
    }

    AppendMenuW(hMenu, MF_STRING | MF_GRAYED, 0, hostItem.c_str());
    AppendMenuW(hMenu, MF_STRING | MF_GRAYED, 0, osItem.c_str());
    for (const auto& ipItem : ipItems) {
        AppendMenuW(hMenu, MF_STRING | MF_GRAYED, 0, ipItem.c_str());
    }

    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, 1001, L"Refresh");

    // SetForegroundWindow is required by TrackPopupMenu to dismiss the menu
    // correctly when the user clicks elsewhere.
    SetForegroundWindow(hwnd_);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                   x, y, 0, hwnd_, nullptr);
    PostMessage(hwnd_, WM_NULL, 0, 0);
    DestroyMenu(hMenu);
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
                self->ShowContextMenu(GET_X_LPARAM(wParam), GET_Y_LPARAM(wParam));
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

    wcsncpy_s(nid_.szTip, L"CoreStation HX Agent", _TRUNCATE);

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


#endif // _WIN32