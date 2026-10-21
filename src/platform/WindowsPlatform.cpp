#ifdef _WIN32
#include <windows.h>
#include "WindowsPlatform.h"
#include <iostream>
#undef min
#undef max
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <sstream>
#include <cctype>
#include "WinHandles.h"
#include "../core/Logging.h"
#include <print>
#include <format>

#ifdef ENABLE_TRAY_APP
#include "../modules/tray/TrayApp.h"
#endif

#include "../modules/session/SessionMonitor.h"

#ifdef ENABLE_SERIAL_BRIDGE_PIPE
#include "../modules/serialpipe/SerialBridgePipe.h"
#endif

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "shell32.lib")

static WindowsPlatform* g_platform_instance = nullptr;

static const char* ServiceControlToReason(DWORD ctrlCode) {
    switch (ctrlCode) {
    case SERVICE_CONTROL_SHUTDOWN:
        return "shutdown";
    case SERVICE_CONTROL_STOP:
    default:
        return "stop";
    }
}

void WINAPI ServiceMain(DWORD, LPTSTR*) {
    if (!g_platform_instance)
        return;

    g_platform_instance->registerServiceHandler();
    g_platform_instance->reportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    g_platform_instance->startService();
    g_platform_instance->reportStatus(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(g_platform_instance->getStopEvent(), INFINITE);
    g_platform_instance->reportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch (ctrlCode) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        if (g_platform_instance) {
            g_platform_instance->stopService(ServiceControlToReason(ctrlCode));
        }
        break;
    }
}

std::unique_ptr<Platform> createPlatform() {
    return std::make_unique<WindowsPlatform>();
}

WindowsPlatform::WindowsPlatform()
{
    g_platform_instance = this;
    g_stop_event = UniqueHandle(CreateEvent(NULL, TRUE, FALSE, NULL));

    updateCpuTimes();

#ifdef ENABLE_METRICS
    initPdhCounters();

    if (!com_initializer.Succeeded()) {
        reportError(core::kMsgIDMetrics, "[WARNING] COM initialization for WMI access", core::PlatformError{
            .code = core::CoreError::Code::Internal,
            .sub_code = core::PlatformError::SubCode::WmiQueryFailed,
            .message = "CoInitializeEx failed",
            .platform_error = static_cast<std::uint32_t>(com_initializer.GetHResult()),
        });
    }
    #endif
}

#ifdef ENABLE_METRICS
// Failures here are reported once; the affected metric then quietly reports
// its placeholder value (its counter handle stays NULL) rather than logging
// on every poll.
void WindowsPlatform::initPdhCounters()
{
    auto pdhError = [](PDH_STATUS status, std::string message) {
        // NO_OBJECT/NO_COUNTER: the counter doesn't exist on this machine
        // (e.g. no "GPU Engine" counters without a GPU driver).
        const DWORD code = static_cast<DWORD>(status);
        const bool missing = code == PDH_CSTATUS_NO_OBJECT || code == PDH_CSTATUS_NO_COUNTER;
        return core::PlatformError{
            .code = missing ? core::CoreError::Code::NotFound : core::CoreError::Code::Internal,
            .sub_code = core::PlatformError::SubCode::WmiQueryFailed,
            .message = std::move(message),
            .platform_error = static_cast<std::uint32_t>(status),
        };
    };

    PDH_HQUERY rawQuery = NULL;
    if (PDH_STATUS status = PdhOpenQuery(NULL, 0, &rawQuery); status != ERROR_SUCCESS || rawQuery == NULL) {
        reportError(core::kMsgIDMetrics, "[WARNING] PDH setup for system metrics", pdhError(status, "PdhOpenQuery failed"));
        return;
    }
    // Store the raw handle in the unique_ptr wrapper
    m_hQuery = UniquePdhQuery(rawQuery);

    auto addCounter = [&](const wchar_t* path, PDH_HCOUNTER* counter, const char* name) {
        if (PDH_STATUS status = PdhAddCounterW(m_hQuery.get(), path, 0, counter); status != ERROR_SUCCESS) {
            *counter = NULL;
            reportError(core::kMsgIDMetrics, "[WARNING] PDH setup for system metrics",
                        pdhError(status, std::format("PdhAddCounter failed for {} counter", name)));
        }
    };

    // Avg. Disk Queue Length for the entire physical disk subsystem
    addCounter(L"\\PhysicalDisk(_Total)\\Avg. Disk Queue Length", &m_hDiskCounter, "disk queue");
    // Segments Retransmitted/sec for IPv4 traffic
    addCounter(L"\\TCPv4\\Segments Retransmitted/sec", &m_hNetRetransCounter, "TCP retransmit");
    addCounter(L"\\GPU Engine(*)\\Utilization Percentage", &m_hGpuTotalCounter, "GPU utilization");

    // Collect initial data sample for counters that require two samples (like averages/rates)
    PdhCollectQueryData(m_hQuery.get());
}
#endif

WindowsPlatform::~WindowsPlatform()
{
    stopSessionMonitor();
    stopSerialBridgePipe();
}

int WindowsPlatform::run(
    int argc, char* argv[],
    VoidCallback on_start,
    StringCallback on_stop,
    PowerStateCallback power_cb,
    SessionStateCallback session_cb)
{
    this->on_start_callback = on_start;
    this->on_stop_callback = on_stop;
    this->power_callback = power_cb;
    this->session_callback = session_cb;

    // Ensure stop event exists and is unsignaled
    if (!g_stop_event)
        g_stop_event = UniqueHandle(CreateEvent(NULL, TRUE, FALSE, NULL));
    else
        ResetEvent(g_stop_event.get());

    const bool forceInteractive =
        hasSwitch(argc, argv, "--interactive") ||
        hasSwitchCmd(L"--interactive") ||
        hasSwitchCmd(L"/interactive");
    const bool forceService =
        hasSwitch(argc, argv, "--service") ||
        hasSwitchCmd(L"--service") ||
        hasSwitchCmd(L"/service");
    const bool isServiceLaunch = runningUnderServiceControlManager();

    {
        std::string modeMessage = std::format("Mode Detection: forceInteractive={}, forceService={}, isServiceLaunch={}",
            forceInteractive ? "true" : "false",
            forceService ? "true" : "false",
            isServiceLaunch ? "true" : "false");
        logMessage(modeMessage);
    }

    // Attempt SCM dispatch unless interactive mode is explicitly requested.
    // This avoids false negatives from parent-process heuristics in some environments.
    if (!forceInteractive)
    {
        SERVICE_TABLE_ENTRYW ServiceTable[] = {
            { (LPWSTR)L"CoreStationHXAgent", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
            { NULL, NULL }
        };

        if (StartServiceCtrlDispatcherW(ServiceTable))
            return 0;

        DWORD err = GetLastError();
        if (forceService || err != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            reportError(core::kMsgIDPlatform, "Service start", core::PlatformError{
                .code = core::CoreError::Code::Internal,
                .sub_code = core::PlatformError::SubCode::ServiceStartFailed,
                .message = "StartServiceCtrlDispatcher failed, cannot continue",
                .platform_error = err,
            });
            return static_cast<int>(err);
        }

        std::string errMessage = std::format("StartServiceCtrlDispatcher failed ({}), falling back to interactive mode.", err);
        logMessage(errMessage);
    }

    logMessage("Running in interactive mode.");
    startSessionMonitor();
    startSerialBridgePipe();
#ifdef ENABLE_TRAY_APP
    startTrayApp();
#endif
    if (on_start_callback)
        on_start_callback();
    std::print("Service running interactively. Press Enter to stop.\n");
    std::cin.get();
    if (on_stop_callback)
        on_stop_callback("interactive-stop");
#ifdef ENABLE_TRAY_APP
    stopTrayApp();
#endif
    stopSerialBridgePipe();
    return 0;
}

bool WindowsPlatform::hasSwitch(int argc, char* argv[], const char* sw)
{
    for (int i = 1; i < argc; ++i)
    {
        if (_stricmp(argv[i], sw) == 0) return true;
    }
    return false;
}

bool WindowsPlatform::hasSwitchCmd(const wchar_t* sw) {
    int argcW = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
    if (!argvW) return false;
    for (int i = 1; i < argcW; ++i) {
        if (_wcsicmp(argvW[i], sw) == 0) { LocalFree(argvW); return true;}
    }
    LocalFree(argvW);
    return false;
}

bool WindowsPlatform::runningUnderServiceControlManager()
{
    DWORD pid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    DWORD parentPid = 0;

    if (Process32First(hSnap, &pe))
    {
        do
        {
            if (pe.th32ProcessID == pid)
            {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    if (parentPid == 0) return false;

    HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, parentPid);
    if (!hParent) return false;

    char name[MAX_PATH] = {0};
    if (GetModuleBaseNameA(hParent, NULL, name, MAX_PATH) == 0)
    {
        CloseHandle(hParent);
        return false;
    }
    CloseHandle(hParent);

    for (char* p = name; *p; ++p) *p = (char)tolower(*p);
    return strcmp(name, "services.exe") == 0;
}

// Helper methods for the service
void WindowsPlatform::reportStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint)
{
    if (g_status_handle == nullptr)
        return;

    g_service_status.dwCurrentState = currentState;
    g_service_status.dwWin32ExitCode = win32ExitCode;
    g_service_status.dwWaitHint = waitHint;

    if (currentState == SERVICE_START_PENDING || currentState == SERVICE_STOP_PENDING) {
        g_service_status.dwControlsAccepted = 0;
        g_service_status.dwCheckPoint = service_checkpoint_++;
    }
    else {
        g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        g_service_status.dwCheckPoint = 0;
        if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
            service_checkpoint_ = 1;
        }
    }

    SetServiceStatus(g_status_handle, &g_service_status);
}

void WindowsPlatform::registerServiceHandler()
{
    g_status_handle = RegisterServiceCtrlHandlerW(L"CoreStationHXAgent", ServiceCtrlHandler);
    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwServiceSpecificExitCode = 0;
    g_service_status.dwCheckPoint = 0;
    g_service_status.dwWaitHint = 0;
    service_checkpoint_ = 1;
    stop_requested_.store(false);
    reportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
}

HANDLE WindowsPlatform::getStopEvent()
{
    return g_stop_event.get();
}

void WindowsPlatform::startService()
{
    startSessionMonitor();
    startSerialBridgePipe();
#ifdef ENABLE_TRAY_APP
    startTrayApp();
#endif
    if (on_start_callback)
        on_start_callback();
}

void WindowsPlatform::stopService(const std::string& stopReason)
{
    if (stop_requested_.exchange(true)) {
        logMessage("Ignoring duplicate service stop request: " + stopReason);
        return;
    }

    logMessage("Service stop requested: " + stopReason);
    reportStatus(SERVICE_STOP_PENDING, NO_ERROR, 15000);
    stopSessionMonitor();
    stopSerialBridgePipe();
#ifdef ENABLE_TRAY_APP
    stopTrayApp();
#endif
    if (on_stop_callback)
        on_stop_callback(stopReason);
    SetEvent(g_stop_event.get());
}
void WindowsPlatform::reportError(std::uint32_t messageId, const std::string& context,
                                  const core::PlatformError& error)
{
    logMessage(std::format("{}: {}", context, core::describe(error)));
    core::LogError(messageId, context, error);
}

void WindowsPlatform::reportErrorOnChange(std::uint32_t messageId, const std::string& key,
                                          const std::string& context, const core::PlatformError& error)
{
    if (core::LogErrorOnChange(key, messageId, context, error)) {
        logMessage(std::format("{}: {}", context, core::describe(error)));
    }
}

void WindowsPlatform::clearReportedError(const std::string& key)
{
    core::ClearReportedError(key);
}

std::expected<DWORD, core::PlatformError> WindowsPlatform::activeConsoleSessionId()
{
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) {
        return std::unexpected(core::PlatformError{
            .code = core::CoreError::Code::NotFound,
            .sub_code = core::PlatformError::SubCode::SessionActionFailed,
            .message = "no active console session",
        });
    }
    return sessionId;
}

#ifdef ENABLE_C2A
std::expected<void, core::PlatformError> WindowsPlatform::enableShutdownPrivilege()
{
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &rawToken)) {
        DWORD err = GetLastError();
        return std::unexpected(core::PlatformError{
            .code = core::CoreError::Code::Internal,
            .sub_code = core::PlatformError::SubCode::PrivilegeAdjustFailed,
            .message = "Failed to open process token for shutdown/restart",
            .platform_error = err,
        });
    }
    UniqueHandle hToken(rawToken);

    TOKEN_PRIVILEGES tkp = {};
    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // AdjustTokenPrivileges can "succeed" without assigning the privilege;
    // GetLastError() (ERROR_NOT_ALL_ASSIGNED) is the real result.
    AdjustTokenPrivileges(hToken.get(), FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
    DWORD err = GetLastError();
    if (err != ERROR_SUCCESS) {
        return std::unexpected(core::PlatformError{
            .code = err == ERROR_NOT_ALL_ASSIGNED ? core::CoreError::Code::PermissionDenied
                                                  : core::CoreError::Code::Internal,
            .sub_code = core::PlatformError::SubCode::PrivilegeAdjustFailed,
            .message = "Failed to adjust token privileges for shutdown/restart",
            .platform_error = err,
        });
    }
    return {};
}

std::expected<void, core::PlatformError> WindowsPlatform::exitWindows(UINT flags, const char* action)
{
    if (auto privileged = enableShutdownPrivilege(); !privileged) {
        return privileged;
    }

    if (!ExitWindowsEx(flags, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER)) {
        DWORD err = GetLastError();
        return std::unexpected(core::PlatformError{
            .code = core::CoreError::Code::Internal,
            .sub_code = core::PlatformError::SubCode::PowerActionFailed,
            .message = std::format("Failed to initiate system {}", action),
            .platform_error = err,
        });
    }
    return {};
}

void WindowsPlatform::shutdownSystem(const std::string& reason)
{
    logMessage("Initiating system shutdown." + (reason.empty() ? "" : (" Reason: " + reason)));

    if (auto result = exitWindows(EWX_SHUTDOWN | EWX_FORCE, "shutdown"); !result) {
        reportError(core::kMsgIDPlatform, "shutdownSystem", result.error());
    }
}

void WindowsPlatform::restartSystem(const std::string& reason)
{
    logMessage("Initiating system restart." + (reason.empty() ? "" : (" Reason: " + reason)));

    if (auto result = exitWindows(EWX_REBOOT | EWX_FORCE, "restart"); !result) {
        reportError(core::kMsgIDPlatform, "restartSystem", result.error());
    }
}

void WindowsPlatform::lockActiveSession()
{
    auto sessionId = activeConsoleSessionId();
    if (!sessionId) {
        reportError(core::kMsgIDPlatform, "lockActiveSession", sessionId.error());
        return;
    }

    // Disconnecting the console session (as opposed to logging it off) locks
    // it: the user's apps and state are preserved, and Windows requires the
    // user to re-enter credentials to reconnect - identical to Win+L.
    if (!WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, *sessionId, FALSE)) {
        DWORD err = GetLastError();
        reportError(core::kMsgIDPlatform, "lockActiveSession", core::PlatformError{
            .code = core::CoreError::Code::Internal,
            .sub_code = core::PlatformError::SubCode::SessionActionFailed,
            .message = "WTSDisconnectSession failed",
            .platform_error = err,
        });
    }
}

void WindowsPlatform::logoffActiveSession()
{
    auto sessionId = activeConsoleSessionId();
    if (!sessionId) {
        reportError(core::kMsgIDPlatform, "logoffActiveSession", sessionId.error());
        return;
    }

    if (!WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, *sessionId, FALSE)) {
        DWORD err = GetLastError();
        reportError(core::kMsgIDPlatform, "logoffActiveSession", core::PlatformError{
            .code = core::CoreError::Code::Internal,
            .sub_code = core::PlatformError::SubCode::SessionActionFailed,
            .message = "WTSLogoffSession failed",
            .platform_error = err,
        });
    }
}
#endif

#endif // _WIN32
