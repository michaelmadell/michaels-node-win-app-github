#pragma once

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

// Forward declaration
class WindowsPlatform;

/**
 * @brief System tray application for displaying host information
 *
 * This class manages a Windows system tray icon that displays:
 * - Hostname
 * - IP address
 * - System uptime
 *
 * It runs on separate UI and named pipe threads to receive updates.
 */
class TrayApp {
public:
    /**
     * @brief Construct a new TrayApp object
     * @param platform Pointer to the parent WindowsPlatform instance for logging
     */
    explicit TrayApp(WindowsPlatform* platform);

    /**
     * @brief Destroy the TrayApp object and clean up resources
     */
    ~TrayApp();

    /**
     * @brief Start the tray application (UI and pipe threads)
     * @return true if started successfully, false otherwise
     */
    bool Start();

    /**
     * @brief Stop the tray application and wait for threads to finish
     */
    void Stop();

    /**
     * @brief Update the tray icon tooltip with new data
     * @param hostname The hostname to display
     * @param ip The IP address to display
     * @param uptime The system uptime to display
     */
    void UpdateData(const std::string& hostname, const std::string& ip, const std::string& uptime);

    // Delete copy constructor and assignment operator
    TrayApp(const TrayApp&) = delete;
    TrayApp& operator=(const TrayApp&) = delete;

private:
    /**
     * @brief Window procedure for the hidden tray window
     */
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    /**
     * @brief Main function for the UI thread
     */
    void UiThreadProc();

    /**
     * @brief Main function for the named pipe listener thread
     */
    void PipeThreadProc();

    /**
     * @brief Apply the current tooltip text to the tray icon
     */
    void ApplyTooltip();

    /**
     * @brief Log a message through the parent platform
     * @param msg Message to log
     */
    void Log(const std::string& msg);

    // Constants
    static const char* const TRAY_PIPE_NAME;
    static const UINT WM_TRAY_UPDATE    = WM_APP + 1;
    static const UINT WM_TRAY_CALLBACK  = WM_APP + 2;

    // Member variables
    WindowsPlatform* platform_ = nullptr;
    HWND hwnd_ = nullptr;
    NOTIFYICONDATAW nid_{};
    std::thread uiThread_;
    std::thread pipeThread_;
    std::mutex dataMutex_;
    std::condition_variable hwndReadyCv_;

    std::string hostname_ = "Waiting...";
    std::string ip_ = "Waiting...";
    std::string uptime_ = "Waiting...";

    std::atomic<bool> stop_{ false };
    HANDLE stopEvent_ = nullptr;
    std::wstring windowClassName_ = L"NodeWinTrayWindow";
};

#endif // _WIN32