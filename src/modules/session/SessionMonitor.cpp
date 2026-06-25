#ifdef _WIN32
#include "SessionMonitor.h"
#include "../../platform/WindowsPlatform.h"
#include <sstream>
#include <chrono>

SessionMonitor::SessionMonitor(WindowsPlatform* platform, SessionStateCallback callback)
    : platform_(platform), callback_(callback) {
}

SessionMonitor::~SessionMonitor() {
    Stop();
}

void SessionMonitor::Start() {
    active_ = true;
    windowReady_ = false;
    thread_ = std::thread([this]() { ThreadProc(); });

    {
        std::unique_lock<std::mutex> lock(windowMutex_);
        windowReadyCv_.wait_for(lock, std::chrono::seconds(5),
            [this]() { return windowReady_; });
    }

    if (platform_) {
        platform_->logMessage("Session state monitor started");
    }
}

void SessionMonitor::Stop() {
    active_ = false;

    HWND window;
    {
        std::lock_guard<std::mutex> lock(windowMutex_);
        window = window_;
    }
    if (window) {
        PostMessage(window, WM_CLOSE, 0, 0);
    }

    if (thread_.joinable()) {
        thread_.join();
    }

    if (platform_) {
        platform_->logMessage("Session state monitor stopped");
    }
}

void SessionMonitor::ThreadProc() {
    HINSTANCE hInstance = GetModuleHandle(NULL);

    WNDCLASSEXW wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.lpfnWndProc = SessionMonitor::WndProc;
    wcex.hInstance = hInstance;
    wcex.lpszClassName = L"SessionMonitorWindow";

    RegisterClassExW(&wcex);

    HWND window = CreateWindowExW(
        0,
        L"SessionMonitorWindow",
        L"Session Monitor",
        0,
        0, 0, 0, 0,
        HWND_MESSAGE,
        NULL,
        hInstance,
        this
    );

    {
        std::lock_guard<std::mutex> lock(windowMutex_);
        window_ = window;
        windowReady_ = true;
        windowReadyCv_.notify_all();
    }

    if (!window) {
        if (platform_) {
            platform_->logMessage("ERROR: Failed to create session monitor window");
        }
        return;
    }

    if (!WTSRegisterSessionNotification(window, NOTIFY_FOR_ALL_SESSIONS)) {
        DWORD err = GetLastError();
        if (platform_) {
            platform_->logMessage("ERROR: WTSRegisterSessionNotification failed, error: " + std::to_string(err));
        }
        DestroyWindow(window);
        return;
    }

    if (platform_) {
        platform_->logMessage("Session monitor registered successfully");
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0 && active_) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    WTSUnRegisterSessionNotification(window);
    DestroyWindow(window);
    {
        std::lock_guard<std::mutex> lock(windowMutex_);
        window_ = nullptr;
    }
}

LRESULT CALLBACK SessionMonitor::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    SessionMonitor* self = nullptr;

    if (msg == WM_CREATE) {
        auto createStruct = reinterpret_cast<LPCREATESTRUCT>(lParam);
        self = reinterpret_cast<SessionMonitor*>(createStruct->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    else {
        self = reinterpret_cast<SessionMonitor*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }

    switch (msg) {
    case WM_WTSSESSION_CHANGE:
        if (self) {
            DWORD sessionChangeType = static_cast<DWORD>(wParam);
            DWORD sessionId = static_cast<DWORD>(lParam);
            self->HandleSessionChange(sessionChangeType, sessionId);
        }
        return 0;

    case WM_CLOSE:
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

void SessionMonitor::HandleSessionChange(DWORD sessionChangeType, DWORD sessionId) {
    std::string eventName;
    std::string stateValue;

    switch (sessionChangeType) {
    case WTS_CONSOLE_CONNECT:
        eventName = "Console Connect";
        stateValue = "1";
        break;

    case WTS_CONSOLE_DISCONNECT:
        eventName = "Console Disconnect";
        stateValue = "2";
        break;

    case WTS_REMOTE_CONNECT:
        eventName = "Remote Connect (RDP)";
        stateValue = "3";
        break;

    case WTS_REMOTE_DISCONNECT:
        eventName = "Remote Disconnect (RDP)";
        stateValue = "4";
        break;

    case WTS_SESSION_LOGON:
        eventName = "Session Logon";
        stateValue = "5";
        break;

    case WTS_SESSION_LOGOFF:
        eventName = "Session Logoff";
        stateValue = "6";
        break;

    case WTS_SESSION_LOCK:
        eventName = "Session Lock";
        stateValue = "7";
        break;

    case WTS_SESSION_UNLOCK:
        eventName = "Session Unlock";
        stateValue = "8";
        break;

    case WTS_SESSION_REMOTE_CONTROL:
        eventName = "Remote Control";
        stateValue = "9";
        break;

    case WTS_SESSION_CREATE:
        eventName = "Session Create";
        stateValue = "10";
        break;

    case WTS_SESSION_TERMINATE:
        eventName = "Session Terminate";
        stateValue = "11";
        break;

    case 15:
        eventName = "Session Reconnect";
        stateValue = "15";
        break;

    default:
        eventName = "Unknown";
        stateValue = std::to_string(sessionChangeType);
        break;
    }

    if (platform_) {
        platform_->logMessage("Session State Change: " + eventName +
            " (Type: " + stateValue + ", Session ID: " + std::to_string(sessionId) + ")");
    }

    if (callback_) {
        callback_(stateValue);
    }
}

std::string SessionMonitor::GetCurrentSessionState() {
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) {
        if (platform_) {
            platform_->logMessage("No active console session detected");
        }
        return "0";
    }

    HDESK hDesk = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (hDesk == NULL) {
        if (platform_) {
            platform_->logMessage("Workstation appears to be locked");
        }
        CloseDesktop(hDesk);
        return "7";
    }

    char desktopName[256] = { 0 };
    DWORD needed = 0;
    if (GetUserObjectInformation(hDesk, UOI_NAME, desktopName, sizeof(desktopName), &needed)) {
        std::string deskName(desktopName);
        if (platform_) {
            platform_->logMessage("Current Desktop: " + deskName);
        }

        if (deskName.find("Winlogon") != std::string::npos) {
            CloseDesktop(hDesk);
            if (platform_) {
                platform_->logMessage("Desktop is Winlogon - workstation is locked");
            }
            return "7";
        }
    }
    CloseDesktop(hDesk);

    if (GetSystemMetrics(SM_REMOTESESSION)) {
        if (platform_) {
            platform_->logMessage("Running in RDP Session");
        }
        return "3";
    }

    LPWSTR pBuffer = NULL;
    DWORD bytesReturned = 0;

    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId,
        WTSConnectState, &pBuffer, &bytesReturned)) {
        WTS_CONNECTSTATE_CLASS state = *((WTS_CONNECTSTATE_CLASS*)pBuffer);
        WTSFreeMemory(pBuffer);

        switch (state) {
        case WTSActive:
            if (platform_) {
                platform_->logMessage("Session is active and connected");
            }
            return "5";

        case WTSConnected:
            if (platform_) {
                platform_->logMessage("Session is connected");
            }
            return "1";

        case WTSDisconnected:
            if (platform_) {
                platform_->logMessage("Session is Disconnected");
            }
            return "2";

        case WTSIdle:
            if (platform_) {
                platform_->logMessage("Session is Idle");
            }
            return "5";

        default:
            if (platform_) {
                platform_->logMessage("Session state: " + std::to_string(state));
            }
            return "6";
        }
    }

    // Final fallback - check if a user is logged in
    if (platform_) {
        std::string username = platform_->getLoggedInUser();
        if (username.empty() || username == "none" || username == "SYSTEM") {
            platform_->logMessage("No user logged in");
            return "6";
        }

        platform_->logMessage("User logged in: " + username);
    }
    return "5";
}

#endif // _WIN32