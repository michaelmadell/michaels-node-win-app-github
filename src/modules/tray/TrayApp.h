#pragma once

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

// Forward declaration
class WindowsPlatform;

class TrayApp {
public:
    explicit TrayApp(WindowsPlatform* platform);
    ~TrayApp();

    bool Start();
    void Stop();

    // Delete copy constructor and assignment operator
    TrayApp(const TrayApp&) = delete;
    TrayApp& operator=(const TrayApp&) = delete;

private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    void UiThreadProc();
    void ApplyTooltip();

    // Queries hostname, non-APIPA IPs, and Windows version directly from
    // the platform. Called once at startup and every 30s via WM_TIMER.
    void RefreshFromPlatform();

    // Builds and shows the right/left-click context menu at screen coords (x, y).
    void ShowContextMenu(int x, int y);

    void Log(const std::string& msg);

    // Constants
    static const UINT WM_TRAY_UPDATE   = WM_APP + 1;
    static const UINT WM_TRAY_CALLBACK = WM_APP + 2;

    // Member variables
    WindowsPlatform* platform_ = nullptr;
    HWND hwnd_ = nullptr;
    NOTIFYICONDATAW nid_{};
    std::thread uiThread_;
    std::mutex dataMutex_;
    std::condition_variable hwndReadyCv_;

    std::string hostname_              = "Waiting...";
    std::vector<std::string> ips_;
    std::string winVersion_            = "Waiting...";

    std::atomic<bool> stop_{ false };
    HANDLE stopEvent_ = nullptr;
    std::wstring windowClassName_ = L"NodeWinTrayWindow";
};

#endif // _WIN32
