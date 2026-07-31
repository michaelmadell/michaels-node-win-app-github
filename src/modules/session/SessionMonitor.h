#pragma once

#ifdef _WIN32
#include <windows.h>
#include <wtsapi32.h>
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <mutex>
#include <condition_variable>

// Forward declaration
class WindowsPlatform;

using SessionStateCallback = std::function<void(const std::string&)>;

/**
 * @brief Monitors Windows session state changes
 *
 * This class creates a hidden window to receive WTS session notifications
 * and reports state changes through a callback function.
 *
 * Monitored events include:
 * - Console connect/disconnect
 * - RDP connect/disconnect
 * - Session lock/unlock
 * - Session logon/logoff
 */
class SessionMonitor {
public:
    /**
     * @brief Construct a new SessionMonitor object
     * @param platform Pointer to the parent WindowsPlatform for logging
     * @param callback Function to call when session state changes
     */
    explicit SessionMonitor(WindowsPlatform* platform, SessionStateCallback callback);

    /**
     * @brief Destroy the SessionMonitor and clean up resources
     */
    ~SessionMonitor();

    /**
     * @brief Start the session monitor thread
     */
    void Start();

    /**
     * @brief Stop the session monitor and wait for thread to finish
     */
    void Stop();

    /**
     * @brief Get the current session state
     * @return String representing the current session state code
     */
    std::string GetCurrentSessionState();

    // Delete copy constructor and assignment operator
    SessionMonitor(const SessionMonitor&) = delete;
    SessionMonitor& operator=(const SessionMonitor&) = delete;

private:
    /**
     * @brief Main thread function for the session monitor
     */
    void ThreadProc();

    /**
     * @brief Window procedure for the hidden monitor window
     */
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    /**
     * @brief Handle a session change event
     * @param sessionChangeType The type of change (WTS_* constant)
     * @param sessionId The session ID that changed
     */
    void HandleSessionChange(DWORD sessionChangeType, DWORD sessionId);

    WindowsPlatform* platform_ = nullptr;
    SessionStateCallback callback_;
    HWND window_ = nullptr;
    std::thread thread_;
    std::atomic<bool> active_{ false };
    std::mutex windowMutex_;
    std::condition_variable windowReadyCv_;
    bool windowReady_ = false;
};

#endif // _WIN32