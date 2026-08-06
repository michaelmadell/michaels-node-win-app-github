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
#include <sstream>
#include <cctype>
#include "WinHandles.h"

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
    PDH_HQUERY rawQuery = NULL;
    if (PdhOpenQuery(NULL, 0, &rawQuery) == ERROR_SUCCESS && rawQuery != NULL) {
        // Store the raw handle in the unique_ptr wrapper
        m_hQuery = UniquePdhQuery(rawQuery);
        if (m_hQuery) {

            // Counter for Avg. Disk Queue Length for the entire physical disk subsystem
            PdhAddCounterA(m_hQuery.get(), "\\PhysicalDisk(_Total)\\Avg. Disk Queue Length", 0, &m_hDiskCounter);
            // Counter for Segments Retransmitted/sec for IPv4 traffic
            PdhAddCounterA(m_hQuery.get(), "\\TCPv4\\Segments Retransmitted/sec", 0, &m_hNetRetransCounter);

            PdhAddCounterW(m_hQuery.get(), L"\\GPU Engine(*)\\Utilization Percentage", 0, &m_hGpuTotalCounter);

            // Collect initial data sample for counters that require two samples (like averages/rates)
            PdhCollectQueryData(m_hQuery.get());
        }
    }
    else {
        logMessage("[WARNING] Failed to open PDH Query for system metrics.");
    }

    if (!com_initializer.Succeeded()) {
        logMessage("[WARNING] Failed to initialize COM for WMI access.");
    }
    #endif
}

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
        std::ostringstream oss;
        oss << "Mode Detection: forceInteractive=" << (forceInteractive ? "true" : "false")
            << ", forceService=" << (forceService ? "true" : "false")
            << ", isServiceLaunch=" << (isServiceLaunch ? "true" : "false");
        logMessage(oss.str());
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
            std::ostringstream oss;
            oss << "StartServiceCtrlDispatcher failed (" << err << "), cannot continue.";
            logMessage(oss.str());
            return static_cast<int>(err);
        }

        std::ostringstream oss;
        oss << "StartServiceCtrlDispatcher failed (" << err << "), falling back to interactive mode.";
        logMessage(oss.str());
    }

    logMessage("Running in interactive mode.");
    startSessionMonitor();
    startSerialBridgePipe();
#ifdef ENABLE_TRAY_APP
    startTrayApp();
#endif
    if (on_start_callback)
        on_start_callback();
    std::cout << "Service running interactively. Press Enter to stop." << std::endl;
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

    PROCESSENTRY32 pe = { 0 };
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
#ifdef ENABLE_C2A
bool WindowsPlatform::enableShutdownPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        logMessage("Failed to open process token for shutdown/restart.");
        return false;
    }

    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
    bool ok = (GetLastError() == ERROR_SUCCESS);
    if (!ok) {
        logMessage("Failed to adjust token privileges for shutdown/restart.");
    }

    CloseHandle(hToken);
    return ok;
}

void WindowsPlatform::shutdownSystem(const std::string& reason)
{
    logMessage("Initiating system shutdown." + (reason.empty() ? "" : (" Reason: " + reason)));

    if (!enableShutdownPrivilege()) {
        return;
    }

    if (!ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER)) {
        logMessage("Failed to initiate system shutdown.");
    }
}

void WindowsPlatform::restartSystem(const std::string& reason)
{
    logMessage("Initiating system restart." + (reason.empty() ? "" : (" Reason: " + reason)));

    if (!enableShutdownPrivilege()) {
        return;
    }

    if (!ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER)) {
        logMessage("Failed to initiate system restart.");
    }
}

void WindowsPlatform::lockActiveSession()
{
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) {
        logMessage("lockActiveSession: no active console session.");
        return;
    }

    // Disconnecting the console session (as opposed to logging it off) locks
    // it: the user's apps and state are preserved, and Windows requires the
    // user to re-enter credentials to reconnect - identical to Win+L.
    if (!WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, sessionId, FALSE)) {
        logMessage("lockActiveSession: WTSDisconnectSession failed, error " + std::to_string(GetLastError()));
    }
}

void WindowsPlatform::logoffActiveSession()
{
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) {
        logMessage("logoffActiveSession: no active console session.");
        return;
    }

    if (!WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, sessionId, FALSE)) {
        logMessage("logoffActiveSession: WTSLogoffSession failed, error " + std::to_string(GetLastError()));
    }
}
#endif

#endif // _WIN32
