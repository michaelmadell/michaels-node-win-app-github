#pragma once

#ifdef _WIN32
#include "../core/Platform.h"
#include "WinHandles.h"
#include "../modules/metrics/MetricCache.h"
#include <windows.h>
#include <wtsapi32.h>
#include <pdh.h>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>

// Forward declarations for modules
class TrayApp;
class SessionMonitor;

/**
 * @brief Windows-specific platform implementation
 *
 * This class implements the Platform interface for Windows systems,
 * providing Windows-specific implementations for system monitoring,
 * serial communication, and service management.
 */
class WindowsPlatform : public Platform {
public:
    WindowsPlatform();
    ~WindowsPlatform();

    // Platform interface implementations
    std::vector<NetworkInterface> getNetworkInterfaces() override;
    std::string getHostname() override;
    std::string getCurrentSessionState() override;
    std::string getLoggedInUser() override;
    std::string getOsVersion() override;
    std::string getOsBuild() override;
    
    void logMessage(const std::string& message) override;

    int getCpuUsagePercent() override;
    int getRamUsagePercent() override;
    std::string getFreeDiskSpaceGB(const std::string& drivePath) override;
    std::string getWindowsUpdateState() override;
    float getDiskQueueLength() override;
    float getNetworkRetransRate() override;
    std::string getSystemUptime() override;
    void updatePdhMetrics() override;

    std::string getGpuDriverInfo() override;
    float getGpuUsagePercent() override;
    std::string getHighRamProcesses() override;

    void showMessageDialog(const std::string& title, const std::string& message) override;

    int run(
        int argc, char* argv[],
        VoidCallback on_start,
        StringCallback on_stop,
        PowerStateCallback power_cb,
        SessionStateCallback session_cb) override;

    // Windows service management
    void reportStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint);
    void registerServiceHandler();
    HANDLE getStopEvent();
    void startService();
    void stopService(const std::string& stopReason);

    // Tray-helper mode: called when this process is spawned by the service
    // into the user session via CreateProcessAsUser. Runs the tray app until
    // the parent service process exits, then returns.
    int runAsTrayHelper(DWORD parentPid);

    // Delete copy constructor and assignment operator
    WindowsPlatform(const WindowsPlatform&) = delete;
    WindowsPlatform& operator=(const WindowsPlatform&) = delete;

private:
    // Serial communication
    UniqueHandle hSerial = UniqueHandle(INVALID_HANDLE_VALUE);
    std::chrono::steady_clock::time_point lastSerialAttempt_;
    static constexpr int SERIAL_RETRY_DELAY_MS = 5000;

    // Callbacks
    VoidCallback on_start_callback;
    StringCallback on_stop_callback;
    PowerStateCallback power_callback;
    SessionStateCallback session_callback;

    // Service control
    SERVICE_STATUS g_service_status = {};
    SERVICE_STATUS_HANDLE g_status_handle = nullptr;
    UniqueHandle g_stop_event = nullptr;
    std::atomic<bool> stop_requested_{ false };
    DWORD service_checkpoint_ = 1;

    // CPU monitoring
    ULONGLONG m_previousIdleTime = 0;
    ULONGLONG m_previousKernelTime = 0;
    ULONGLONG m_previousUserTime = 0;

    // Performance counters
    UniquePdhQuery m_hQuery = nullptr;
    PDH_HCOUNTER m_hDiskCounter = NULL;
    PDH_HCOUNTER m_hNetRetransCounter = NULL;
    PDH_HCOUNTER m_hGpuTotalCounter = NULL;

    // COM initialization
    ComInitializer com_initializer;

    // Modules
#ifdef ENABLE_TRAY_APP
    std::unique_ptr<TrayApp> tray_app_;
#endif

#ifdef ENABLE_SESSION_MONITOR
    std::unique_ptr<SessionMonitor> session_monitor_;
#endif

    // Thread safety
    std::mutex platformMutex_;

    // Metric caches
    MetricCache<int> cpuCache_{ CacheDurations::CPU_USAGE };
    MetricCache<int> ramCache_{ CacheDurations::RAM_USAGE };
    MetricCache<std::string> diskSpaceCache_{ CacheDurations::FREE_DISK_SPACE };
    MetricCache<std::string> windowsUpdateCache_{ CacheDurations::WINDOWS_UPDATE };
    MetricCache<float> diskQueueCache_{ CacheDurations::DISK_QUEUE };
    MetricCache<float> netRetransCache_{ CacheDurations::NET_RETRANS };
    MetricCache<std::string> uptimeCache_{ CacheDurations::SYSTEM_UPTIME };
    MetricCache<std::string> gpuDriverCache_{ CacheDurations::GPU_DRIVER_INFO };
    MetricCache<float> gpuUsageCache_{ CacheDurations::GPU_USAGE };
    MetricCache<std::string> highRamProcsCache_{ CacheDurations::HIGH_RAM_PROCS };

    // Implementation methods (cached versions call these)
    int getCpuUsagePercentImpl();
    int getRamUsagePercentImpl();
    std::string getFreeDiskSpaceGBImpl(const std::string& drivePath);
    std::string getWindowsUpdateStateImpl();
    float getDiskQueueLengthImpl();
    float getNetworkRetransRateImpl();
    std::string getSystemUptimeImpl();
    std::string getGpuDriverInfoImpl();
    float getGpuUsagePercentImpl();
    std::string getHighRamProcessesImpl();

    // Helper methods
    void updateCpuTimes();
    std::string getProcessName(HANDLE hProcess);

    // Module management
    void startTrayApp();
    void stopTrayApp();
    void startSessionMonitor();
    void stopSessionMonitor();

    // Spawn a tray helper process in the active user session (called when
    // running as a Session 0 service where direct tray creation is invisible).
    void spawnTrayHelper();

    // Terminate and release the tray helper process handle. Must be called
    // with trayHelperMutex_ held.
    void killTrayHelper();

    // Mode detection
    bool hasSwitch(int argc, char* argv[], const char* sw);
    bool hasSwitchCmd(const wchar_t* sw);
    bool runningUnderServiceControlManager();

    // Handle to the tray helper child process (valid when service is in Session 0).
    // Always access under trayHelperMutex_.
    HANDLE hTrayHelperProcess_ = INVALID_HANDLE_VALUE;
    std::mutex trayHelperMutex_;
};

#endif // _WIN32