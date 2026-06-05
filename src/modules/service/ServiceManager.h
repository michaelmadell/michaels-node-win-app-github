#pragma once

#ifdef _WIN32
#include <windows.h>
#include <string>
#include <functional>

// Forward declaration
class WindowsPlatform;

using VoidCallback = std::function<void()>;

/**
 * @brief Manages Windows Service lifecycle
 *
 * This class handles all Windows service-related operations including:
 * - Service registration and control
 * - Status reporting
 * - Start/stop/pause/resume operations
 * - Installation and removal
 */
class ServiceManager {
public:
    /**
     * @brief Service installation configuration
     */
    struct ServiceConfig {
        std::wstring serviceName = L"CoreStationHXAgent";
        std::wstring displayName = L"CoreStation HX Agent";
        std::wstring description = L"Sends system information to CoreStation HX CMC";
        DWORD startType = SERVICE_AUTO_START;
        DWORD serviceType = SERVICE_WIN32_OWN_PROCESS;
        std::wstring dependencies = L"";
        std::wstring account = L"LocalSystem";
        std::wstring password = L"";
    };

    /**
     * @brief Service status information
     */
    struct ServiceStatus {
        DWORD currentState = SERVICE_STOPPED;
        DWORD win32ExitCode = NO_ERROR;
        DWORD serviceExitCode = 0;
        DWORD checkPoint = 0;
        DWORD waitHint = 0;
        DWORD controlsAccepted = 0;
    };

    /**
     * @brief Construct a ServiceManager
     * @param platform Pointer to parent platform for logging
     */
    explicit ServiceManager(WindowsPlatform* platform);
    ~ServiceManager();

    bool Install(const ServiceConfig& config = ServiceConfig());

    bool Uninstall();

    bool StartService();

    bool StopService();

    bool QueryStatus(ServiceStatus& status);

    bool IsInstalled();

    bool IsRunning();

    /**
     * @brief Report service status to SCM
     * @param currentState Current service state
     * @param win32ExitCode Exit code if stopping
     * @param waitHint Estimated time for pending operations (ms)
     */
    void ReportStatus(DWORD currentState, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0);

    /**
     * @brief Register the service control handler
     * @param serviceName Name of the service
     */
    void RegisterServiceHandler(const std::wstring& serviceName);

    /**
     * @brief Get the stop event handle
     * @return Handle to the stop event
     */
    HANDLE GetStopEvent() const;

    /**
     * @brief Set callbacks for service events
     * @param onStart Callback when service starts
     * @param onStop Callback when service stops
     */
    void SetCallbacks(VoidCallback onStart, VoidCallback onStop);

    /**
     * @brief Main entry point for service (called by SCM)
     * @param argc Argument count
     * @param argv Argument values
     */
    void ServiceMainProc(DWORD argc, LPTSTR* argv);

    /**
     * @brief Control handler (called by SCM for control requests)
     * @param ctrlCode Control code
     */
    void ServiceCtrlProc(DWORD ctrlCode);

    // Delete copy constructor and assignment operator
    ServiceManager(const ServiceManager&) = delete;
    ServiceManager& operator=(const ServiceManager&) = delete;

private:
    WindowsPlatform* platform_;

    SERVICE_STATUS serviceStatus_;
    SERVICE_STATUS_HANDLE statusHandle_ = nullptr;
    HANDLE stopEvent_ = nullptr;

    VoidCallback onStart_;
    VoidCallback onStop_;

    std::wstring serviceName_;

    // Helper methods
    bool OpenServiceManager(SC_HANDLE& scmHandle);
    bool OpenServiceHandle(SC_HANDLE scmHandle, SC_HANDLE& serviceHandle, DWORD desiredAccess);
    void LogError(const std::string& operation);
    std::string GetLastErrorString();
};

#endif // _WIN32