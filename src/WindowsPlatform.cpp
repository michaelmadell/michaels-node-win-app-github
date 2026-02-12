#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "Platform.h"
#include <iostream>
#undef min
#undef max
#include <iphlpapi.h>
#include <wtsapi32.h>
#include <setupapi.h>
#include <shellapi.h>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <psapi.h>
#include <tlhelp32.h>
#include <pdh.h>
#include <wbemidl.h>
#include <comutil.h>
#include <shellapi.h>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <chrono>
#include <cctype>
#include "Windows_Addon.h"
#include "MetricCache.h"

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

#ifndef PDH_FMT_FLOAT
#define PDH_FMT_FLOAT 0x00000200
#endif

#ifndef PDH_MORE_DATA
#define PDH_MORE_DATA ((PDH_STATUS)0x800007D2)
#endif

static const wchar_t* const LOG_DIR_PATH = L"C:\\ProgramData\\ahk";
static const wchar_t* const LOG_FILE_PATH = L"C:\\ProgramData\\ahk\\node-win-app.log";
static const char* const TRAY_PIPE_NAME = "\\\\.\\pipe\\corestation_tray";
static const UINT WM_TRAY_UPDATE = WM_APP + 1;

static ULONGLONG FileTimeToInt64(const FILETIME& ft) {
    return ((ULONGLONG)ft.dwHighDateTime) << 32 | ((ULONGLONG)ft.dwLowDateTime);
}

std::string WideToUtf8(const std::wstring &wstr)
{
    if (wstr.empty())
        return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

typedef LONG(WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

// Forward declaration so TrayApp can hold a pointer
class WindowsPlatform;

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

class TrayApp;

class TrayApp {
public:
    explicit TrayApp(WindowsPlatform* platform);
    ~TrayApp();

    bool Start();
    void Stop();
    void UpdateData(const std::string& hostname, const std::string& ip, const std::string& uptime);

private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void UiThreadProc();
    void PipeThreadProc();
    void ApplyTooltip();
    void Log(const std::string& msg);

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
    std::atomic<bool> stop_{false};
    HANDLE stopEvent_ = nullptr;
    std::wstring windowClassName_ = L"NodeWinTrayWindow";
};

// --- 1. DEFINE THE CLASS FIRST ---
// The class definition must come before it is used.
class WindowsPlatform : public Platform
{
public:
    WindowsPlatform();
    ~WindowsPlatform();

    std::vector<NetworkInterface> getNetworkInterfaces() override;
    std::string getHostname() override;
    std::string getLoggedInUser() override;
    std::string getOsVersion() override;
    std::string getOsBuild() override;
    bool openSerialPort(const std::string &portName, int baudrate) override;
    void closeSerialPort() override;
    bool writeSerial(const std::string &data) override;
    bool readSerial(std::string &readData) override;
    void logMessage(const std::string &message) override;
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
        int argc, char *argv[],
        VoidCallback on_start,
        VoidCallback on_stop,
        PowerStateCallback power_cb,
        SessionStateCallback session_cb) override;

    // Helper methods for the service
    void reportStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint);
    void registerServiceHandler();
    HANDLE getStopEvent();
    void startService();
    void stopService();
    std::string getCurrentSessionState();

private:
    UniqueHandle hSerial = UniqueHandle(INVALID_HANDLE_VALUE);
    VoidCallback on_start_callback;
    VoidCallback on_stop_callback;
    PowerStateCallback power_callback;
    SessionStateCallback session_callback;
    SERVICE_STATUS g_service_status = {};
    SERVICE_STATUS_HANDLE g_status_handle = nullptr;
    UniqueHandle g_stop_event = nullptr;
    ULONGLONG m_previousIdleTime = 0;
    ULONGLONG m_previousKernelTime = 0;
    ULONGLONG m_previousUserTime = 0;
    UniquePdhQuery m_hQuery = nullptr;
    PDH_HCOUNTER m_hDiskCounter = NULL;
    PDH_HCOUNTER m_hNetRetransCounter = NULL;
    PDH_HCOUNTER m_hGpuTotalCounter = NULL;

    ComInitializer com_initializer;

    std::unique_ptr<TrayApp> tray_app_;

    void updateCpuTimes();
    std::string getProcessName(HANDLE hProcess);
    void startTrayApp();
    void stopTrayApp();

    bool hasSwitch(int argc, char* argv[], const char* sw);
    bool hasSwitchCmd(const wchar_t* sw);
    bool runningUnderServiceControlManager();

    std::chrono::steady_clock::time_point lastSerialAttempt_;
    const int SERIAL_RETRY_DELAY_MS = 5000;

	std::mutex platformMutex_;

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

    HWND sessionMonitorWindow_ = nullptr;
    std::thread sessionMonitorThread_;
    std::atomic<bool> sessionMonitorActive_{ false };

    void startSessionMonitor();
    void stopSessionMonitor();
    void sessionMonitorThreadProc();
    static LRESULT CALLBACK SessionMonitorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void handleSessionChange(DWORD sessionChangeType, DWORD sessionId);
};

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

void WindowsPlatform::startSessionMonitor() {
    sessionMonitorActive_ = true;
    sessionMonitorThread_ = std::thread([this]() {sessionMonitorThreadProc(); });
    logMessage("Session state monitor started");
}

void WindowsPlatform::stopSessionMonitor() {
    sessionMonitorActive_ = false;
    if (sessionMonitorWindow_) {
        PostMessage(sessionMonitorWindow_, WM_CLOSE, 0, 0);
    }

    if (sessionMonitorThread_.joinable()) {
        sessionMonitorThread_.join();
    }

    logMessage("Session state monitor stopped");
}

void WindowsPlatform::sessionMonitorThreadProc() {
    HINSTANCE hInstance = GetModuleHandle(NULL);

    WNDCLASSEXW wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.lpfnWndProc = WindowsPlatform::SessionMonitorWndProc;
    wcex.hInstance = hInstance;
    wcex.lpszClassName = L"SessionMonitorWindow";

    RegisterClassExW(&wcex);

    sessionMonitorWindow_ = CreateWindowExW(
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

    if (!sessionMonitorWindow_) {
        logMessage("ERROR: Failed to create session monitor window");
        return;
    }

    if (!WTSRegisterSessionNotification(sessionMonitorWindow_, NOTIFY_FOR_THIS_SESSION)) {
        DWORD err = GetLastError();
        logMessage("ERROR: WTSRegisterSessionNotification failed, error: " + std::to_string(err));
        DestroyWindow(sessionMonitorWindow_);
        return;
    }

    logMessage("Session monitor registered successfully");

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0 && sessionMonitorActive_) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    WTSUnRegisterSessionNotification(sessionMonitorWindow_);
    DestroyWindow(sessionMonitorWindow_);
    sessionMonitorWindow_ = nullptr;
}

LRESULT CALLBACK WindowsPlatform::SessionMonitorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    WindowsPlatform* self = nullptr;

    if (msg == WM_CREATE) {
        auto createStruct = reinterpret_cast<LPCREATESTRUCT>(lParam);
        self = reinterpret_cast<WindowsPlatform*>(createStruct->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    else {
        self = reinterpret_cast<WindowsPlatform*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }

    switch (msg) {
    case WM_WTSSESSION_CHANGE:
        if (self) {
            DWORD sessionChangeType = wParam;
            DWORD sessionId = lParam;
            self->handleSessionChange(sessionChangeType, sessionId);
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

void WindowsPlatform::handleSessionChange(DWORD sessionChangeType, DWORD sessionId) {
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

    default:
        eventName = "Unknown";
        stateValue = std::to_string(sessionChangeType);
        break;
    }

    logMessage("Session State Change: " + eventName + " (Type: " + stateValue + ", Session ID: " + std::to_string(sessionId) + ")");

    if (session_callback) {
        session_callback(stateValue);
    }
}

std::string WindowsPlatform::getCurrentSessionState() {
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) {
        logMessage("No active console session detected");
        return "0";
    }

    HDESK hDesk = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (hDesk == NULL) {
        logMessage("Workstation appears to be locked");
        CloseDesktop(hDesk);
        return "7";
    }

    char desktopName[256] = { 0 };
    DWORD needed = 0;
    if (GetUserObjectInformation(hDesk, UOI_NAME, desktopName, sizeof(desktopName), &needed)) {
        std::string deskName(desktopName);
        logMessage("Current Desktop: " + deskName);

        if (deskName.find("Winlogon") != std::string::npos) {
            CloseDesktop(hDesk);
            logMessage("Desktop is Winlogon - workstation is locked");
            return "7";
        }
    }
    CloseDesktop(hDesk);

    if (GetSystemMetrics(SM_REMOTESESSION)) {
        logMessage("Running in RDP Session");
        return "3";
    }

    LPWSTR pBuffer = NULL;
    DWORD bytesReturned = 0;

    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSConnectState, &pBuffer, &bytesReturned)) {
        WTS_CONNECTSTATE_CLASS state = *((WTS_CONNECTSTATE_CLASS*)pBuffer);
        WTSFreeMemory(pBuffer);

        switch (state) {
        case WTSActive:
            logMessage("Session is active and connected");
            return "5";

        case WTSConnected:
            logMessage("Session is connected");
            return "1";

        case WTSDisconnected:
            logMessage("Session is Disconnected");
            return "2";

        case WTSIdle:
            logMessage("Session is Idle");
            return "5";

        default:
            logMessage("Session state: " + std::to_string(state));
            return "6";
        }
    }

    std::string username = getLoggedInUser();
    if (username.empty() || username == "none" || username == "SYSTEM") {
        logMessage("No user logged in");
        return "6";
    }

    logMessage("User logged in: " + username);
    return "5";
}

void WindowsPlatform::updateCpuTimes() {
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        m_previousIdleTime = FileTimeToInt64(idleTime);
        m_previousKernelTime = FileTimeToInt64(kernelTime) - m_previousIdleTime;
        m_previousUserTime = FileTimeToInt64(userTime);
    }
}

// --- 2. DEFINE GLOBALS AND HANDLERS THAT USE THE CLASS ---
static WindowsPlatform *g_platform_instance = nullptr;

void WINAPI ServiceMain(DWORD, LPTSTR *)
{
    if (!g_platform_instance)
        return;
    g_platform_instance->registerServiceHandler();
    g_platform_instance->reportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    g_platform_instance->startService();
    g_platform_instance->reportStatus(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(g_platform_instance->getStopEvent(), INFINITE);
    g_platform_instance->reportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode)
{
    switch (ctrlCode)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        if (g_platform_instance)
        {
            g_platform_instance->reportStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
            g_platform_instance->stopService();
        }
        break;
    }
}

// --- 3. IMPLEMENT THE FACTORY FUNCTION AND CLASS METHODS ---
std::unique_ptr<Platform> createPlatform()
{
    return std::make_unique<WindowsPlatform>();
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
        hwndReadyCv_.wait_for(lock, std::chrono::seconds(5), [this]() { return hwnd_ != nullptr || stop_.load(); });
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
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(createStruct->lpCreateParams));
        }
    }

    auto self = reinterpret_cast<TrayApp*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));

    switch (msg) {
    case WM_TRAY_UPDATE:
        if (self) {
            self->ApplyTooltip();
        }
        return 0;
    case WM_DESTROY:
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

    WNDCLASSEXW wcex = {0};
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
    nid_.uFlags = NIF_ICON | NIF_TIP;
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
    } else {
        nid_.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &nid_);
        ApplyTooltip();
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
            HANDLE handles[2] = {ovConnect.hEvent, stopEvent_};
            DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0 + 1) {
                CancelIoEx(hPipe, &ovConnect);
            } else {
                connected = TRUE;
            }
        } else if (!connected && err == ERROR_PIPE_CONNECTED) {
            connected = TRUE;
        }

        if (connected && !stop_.load()) {
            for (;;) {
                char buffer[512] = {0};
                DWORD bytesRead = 0;
                OVERLAPPED ovRead = {};
                ovRead.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

                BOOL readOk = ReadFile(hPipe, buffer, sizeof(buffer) - 1, NULL, &ovRead);
                if (!readOk) {
                    DWORD readErr = GetLastError();
                    if (readErr == ERROR_IO_PENDING) {
                        HANDLE handles[2] = {ovRead.hEvent, stopEvent_};
                        DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
                        if (wait == WAIT_OBJECT_0 + 1) {
                            CancelIoEx(hPipe, &ovRead);
                            CloseHandle(ovRead.hEvent);
                            break;
                        }
                        GetOverlappedResult(hPipe, &ovRead, &bytesRead, FALSE);
                    } else {
                        CloseHandle(ovRead.hEvent);
                        break;
                    }
                } else {
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
                    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    if (key == "hostname") {
                        host = value;
                    } else if (key == "ip" || key == "ipaddress" || key == "address") {
                        ip = value;
                    } else if (key == "uptime") {
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

WindowsPlatform::WindowsPlatform()
{
    g_platform_instance = this;
    g_stop_event = UniqueHandle(CreateEvent(NULL, TRUE, FALSE, NULL));
    
    startSessionMonitor();
    updateCpuTimes();

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
}

WindowsPlatform::~WindowsPlatform()
{
    stopSessionMonitor();
}

int WindowsPlatform::run(
    int argc, char *argv[],
    VoidCallback on_start,
    VoidCallback on_stop,
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

    // Only go to SCM when truly launched by it or explicitly forced
    if (!forceInteractive && (forceService || isServiceLaunch))
    {
        SERVICE_TABLE_ENTRYW ServiceTable[] = {
            { (LPWSTR)L"CoreStationHXAgent", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
            { NULL, NULL }
        };

        if (StartServiceCtrlDispatcherW(ServiceTable))
            return 0;

        DWORD err = GetLastError();
        std::ostringstream oss;
        oss << "StartServiceCtrlDispatcher failed (" << err << "), falling back to interactive mode.";
        logMessage(oss.str());
    }

    logMessage("Running in interactive mode.");
    startTrayApp();
    if (on_start_callback)
        on_start_callback();
    std::cout << "Service running interactively. Press Enter to stop." << std::endl;
    std::cin.get();
    if (on_stop_callback)
        on_stop_callback();
    stopTrayApp();
    return 0;
}

void WindowsPlatform::startTrayApp()
{
    if (!tray_app_)
    {
        tray_app_ = std::make_unique<TrayApp>(this);
        tray_app_->Start();
    }
}

void WindowsPlatform::stopTrayApp()
{
    if (tray_app_)
    {
        tray_app_->Stop();
        tray_app_.reset();
    }
}

// Implementations for the core virtual methods
std::vector<NetworkInterface> WindowsPlatform::getNetworkInterfaces()
{
    std::vector<NetworkInterface> interfaces;
    ULONG bufferSize = 0;

    // First call to get the required buffer size
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufferSize);

    if (bufferSize == 0)
    {
        return interfaces;
    }

    std::vector<BYTE> buffer(bufferSize);
    IP_ADAPTER_ADDRESSES *pAdapterAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());

    // Second call to get the actual data
    DWORD result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAdapterAddresses, &bufferSize);

    if (result == NO_ERROR)
    {
        for (IP_ADAPTER_ADDRESSES* pAdapter = pAdapterAddresses; pAdapter; pAdapter = pAdapter->Next)
        {
            // We only care about Ethernet interfaces
            if (pAdapter->IfType != IF_TYPE_ETHERNET_CSMACD)
            {
                continue;
            }

            NetworkInterface iface;

            // Format MAC address
            std::ostringstream macStream;
            for (ULONG i = 0; i < pAdapter->PhysicalAddressLength; i++)
            {
                if (i != 0)
                    macStream << ":";
                macStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pAdapter->PhysicalAddress[i]);
            }
            iface.macAddress = macStream.str();

            if (iface.macAddress.compare(0, 5, "00:17") == 0 || iface.macAddress.compare(0, 5, "00:13") == 0)
            {
                iface.name = pAdapter->FriendlyName ? WideToUtf8(pAdapter->FriendlyName) : "Unknown";
                iface.linkStatus = (pAdapter->OperStatus == IfOperStatusUp) ? "up" : "down";
                iface.dhcp = (pAdapter->Flags & IP_ADAPTER_DHCP_ENABLED) ? "dhcp" : "static";
                iface.ipv4 = "none";
                iface.ipv6 = "none";

                // Get IP addresses
                for (IP_ADAPTER_UNICAST_ADDRESS* pUnicast = pAdapter->FirstUnicastAddress; pUnicast; pUnicast = pUnicast->Next)
                {
                    char ipBuffer[INET6_ADDRSTRLEN] = { 0 };
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                    {
                        sockaddr_in* pSockAddr = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                        inet_ntop(AF_INET, &(pSockAddr->sin_addr), ipBuffer, sizeof(ipBuffer));
                        iface.ipv4 = ipBuffer;
                    }
                    else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
                    {
                        sockaddr_in6* pSockAddr6 = reinterpret_cast<sockaddr_in6*>(pUnicast->Address.lpSockaddr);
                        inet_ntop(AF_INET6, &(pSockAddr6->sin6_addr), ipBuffer, sizeof(ipBuffer));
                        iface.ipv6 = ipBuffer;
                    }
                }
                interfaces.push_back(iface);
            }
        }
    }
    return interfaces;
}
std::string WindowsPlatform::getHostname()
{
    char hostnameChar[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD hostnameLen = sizeof(hostnameChar);
    if (GetComputerNameA(hostnameChar, &hostnameLen))
    {
        return std::string(hostnameChar);
    }
    return "Unknown Host";
}
std::string WindowsPlatform::getLoggedInUser()
{
    PWTS_SESSION_INFOW pSessionInfo = NULL;
    DWORD sessionCount = 0;
    std::string username = "none";

    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount))
    {
        for (DWORD i = 0; i < sessionCount; ++i)
        {
            if (pSessionInfo[i].State == WTSActive)
            {
                LPWSTR pBuffer = NULL;
                DWORD bytesReturned = 0;
                if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, pSessionInfo[i].SessionId, WTSUserName, &pBuffer, &bytesReturned) && pBuffer)
                {
                    username = WideToUtf8(std::wstring(pBuffer));
                    WTSFreeMemory(pBuffer);
                    break; // Found the first active user
                }
            }
        }
        WTSFreeMemory(pSessionInfo);
    }
    return username;
}

std::string WindowsPlatform::getOsVersion()
{
    // First, get the raw version info to check the build number
    HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
    if (!hMod) return "Unknown Windows Version";

    RtlGetVersionPtr fn = (RtlGetVersionPtr)::GetProcAddress(hMod, "RtlGetVersion");
    if (!fn) return "Unknown Windows Version";

    RTL_OSVERSIONINFOW rovi = {0};
    rovi.dwOSVersionInfoSize = sizeof(rovi);
    if (fn(&rovi) != 0) return "Unknown Windows Version";

    // Now, query the registry for the friendly name
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        // Fallback to build number if registry fails
        std::ostringstream version;
        version << rovi.dwMajorVersion << "." << rovi.dwMinorVersion << "." << rovi.dwBuildNumber;
        return version.str();
    }

    char productName[255];
    DWORD productNameSize = sizeof(productName);
    if (RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)productName, &productNameSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "Unknown Windows Version";
    }

    std::string finalProductName = productName;

    // Correct the product name if the build number indicates Windows 11
    if (rovi.dwBuildNumber >= 22000) {
        size_t pos = finalProductName.find("10");
        if (pos != std::string::npos) {
            finalProductName.replace(pos, 2, "11");
        }
    }

    char displayVersion[255];
    DWORD displayVersionSize = sizeof(displayVersion);
    if (RegQueryValueExA(hKey, "DisplayVersion", NULL, NULL, (LPBYTE)displayVersion, &displayVersionSize) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return finalProductName + " " + std::string(displayVersion);
    }
    
    RegCloseKey(hKey);
    return finalProductName;
}

std::string WindowsPlatform::getOsBuild()
{
    HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
    if (!hMod) return "Unknown Build (ntdll.dll)";

    RtlGetVersionPtr fn = (RtlGetVersionPtr)::GetProcAddress(hMod, "RtlGetVersion");
    if (!fn) return "Unknown Build (RtlGetVersion)";

    RTL_OSVERSIONINFOW rovi = {0};
    rovi.dwOSVersionInfoSize = sizeof(rovi);
    
    if (fn(&rovi) != 0) return "Unknown Build (RtlGetVersion failed)";

    // Format the version as a string: Major.Minor.Build
    std::ostringstream version;
    version << rovi.dwMajorVersion << "." << rovi.dwMinorVersion << "." << rovi.dwBuildNumber;
    
    return version.str();
}

bool WindowsPlatform::openSerialPort(const std::string &portName, int baudrate)
{
    HANDLE rawHandle = CreateFileA(
        portName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (rawHandle == INVALID_HANDLE_VALUE) 
    {
        DWORD err = GetLastError();
		std::ostringstream oss;
		oss << "CreateFileA failed for " << portName << " with error " << err;
        logMessage(oss.str());
		return false;
    }

    hSerial.reset(rawHandle);

    if (hSerial.get() == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DCB dcbSerialParams = {0};
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);

    if (!GetCommState(hSerial.get(), &dcbSerialParams))
    {
        hSerial.reset(INVALID_HANDLE_VALUE);
        return false;
    }

    dcbSerialParams.BaudRate = CBR_115200; // You can use the 'baudrate' parameter
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;

    if (!SetCommState(hSerial.get(), &dcbSerialParams))
    {
        hSerial.reset();
        return false;
    }

    // Set timeouts
    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 5;
    timeouts.ReadTotalTimeoutConstant = 5;
    timeouts.ReadTotalTimeoutMultiplier = 1;
    timeouts.WriteTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutMultiplier = 10;

    if (!SetCommTimeouts(hSerial.get(), &timeouts))
    {
        hSerial.reset();
        return false;
    }

    return true;
}

void WindowsPlatform::closeSerialPort()
{
    hSerial.reset(INVALID_HANDLE_VALUE);
}

bool WindowsPlatform::writeSerial(const std::string &data)
{
    if (hSerial.get() == INVALID_HANDLE_VALUE) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - lastSerialAttempt_).count();

        if (elapsed >= SERIAL_RETRY_DELAY_MS) {
            lastSerialAttempt_ = now;
            logMessage("Attempting to reconnect serial port...");
            if (openSerialPort("COM3", 115200)) {
                logMessage("Serial port reconnected successfully");
            }
        }
        return false;
    }

    DWORD bytesWritten = 0;
    if (WriteFile(hSerial.get(), data.c_str(), (DWORD)data.length(), &bytesWritten, NULL)) {
        DWORD err = GetLastError();
        logMessage("WriteFile failed (Error " + std::to_string(err) + "), closing serial port");
        closeSerialPort();
        return false;
    }

    if (bytesWritten != data.length()) {
        logMessage("Partial write detected (" + std::to_string(bytesWritten) + " of " + std::to_string(data.length()) + " bytes)");
        return false;
    }
    return true;
}

bool WindowsPlatform::readSerial(std::string &readData) {
    if (!hSerial) {
        return false;
    }

    char buffer[256];
    DWORD bytesRead = 0;

    if (ReadFile(hSerial.get(), buffer, sizeof(buffer) -1, &bytesRead, NULL)) {
        if (bytesRead > 0) {
            readData.append(buffer, bytesRead);
            return true;
        }
    }
    else {
		DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
			logMessage("Error reading from serial port: " + std::to_string(err));
        }
    }
    return false;
}

void WindowsPlatform::showMessageDialog(const std::string& title, const std::string& message) {
    std::wstring wTitle(title.begin(), title.end());
    std::wstring wMessage(message.begin(), message.end());

    MessageBoxW(
        NULL,
        wMessage.c_str(),
        wTitle.c_str(),
        MB_OK | MB_ICONINFORMATION
    );
}

void WindowsPlatform::logMessage(const std::string &message)
{
    const size_t MAX_LOG_SIZE = 10 * 1024 * 1024;

    std::ifstream checkSize(LOG_FILE_PATH, std::ios::ate | std::ios::binary);
    if (checkSize.is_open()) {
        size_t fileSize = checkSize.tellg();
        checkSize.close();

        if (fileSize >= MAX_LOG_SIZE) {
            std::wstring backupPath = std::wstring(LOG_FILE_PATH) + L".old";
            DeleteFileW(backupPath.c_str());
            MoveFileW(LOG_FILE_PATH, backupPath.c_str());
        }
    }

    DWORD fileAttr = GetFileAttributesW(LOG_DIR_PATH);
    if (fileAttr == INVALID_FILE_ATTRIBUTES)
    {
        CreateDirectoryW(LOG_DIR_PATH, NULL);
    }

    std::ofstream logFile(LOG_FILE_PATH, std::ios::app);
    if (logFile.is_open())
    {
        SYSTEMTIME time;
        GetLocalTime(&time);

        logFile << "[" << time.wYear << "-"
            << std::setfill('0') << std::setw(2) << time.wMonth << "-"
            << std::setfill('0') << std::setw(2) << time.wDay << " "
            << std::setfill('0') << std::setw(2) << time.wHour << ":"
            << std::setfill('0') << std::setw(2) << time.wMinute << ":"
            << std::setfill('0') << std::setw(2) << time.wSecond << "."
            << std::setfill('0') << std::setw(3) << time.wMilliseconds << "] "
            << message << std::endl;
        logFile.close();
    }
}

int WindowsPlatform::getCpuUsagePercent() {
    return cpuCache_.get([this]() {return getCpuUsagePercentImpl();  });
}

int WindowsPlatform::getCpuUsagePercentImpl()
{
    // NOTE: This now relies on updatePdhMetrics being called right before it
    // The previous times were updated in updatePdhMetrics.

    FILETIME idleTime, kernelTime, userTime;
    if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        return 0;
    }

    ULONGLONG currentIdleTime = FileTimeToInt64(idleTime);
    ULONGLONG currentKernelTime = FileTimeToInt64(kernelTime) - currentIdleTime;
    ULONGLONG currentUserTime = FileTimeToInt64(userTime);

    // Calculate delta times based on the previous sample taken in updatePdhMetrics
    ULONGLONG idleTimeDelta = currentIdleTime - m_previousIdleTime;
    ULONGLONG kernelTimeDelta = currentKernelTime - m_previousKernelTime;
    ULONGLONG userTimeDelta = currentUserTime - m_previousUserTime;

    // No need to update previous times here, that is done in updatePdhMetrics

    ULONGLONG totalTimeDelta = kernelTimeDelta + userTimeDelta;

    if (totalTimeDelta == 0) {
        return 0;
    }

    // CPU Usage = (Total Time - Idle Time) / Total Time * 100
    int cpuUsage = (int)((totalTimeDelta - idleTimeDelta) * 100 / totalTimeDelta);

    if (cpuUsage < 0) return 0;
    if (cpuUsage > 100) return 100;

    return cpuUsage;
}

int WindowsPlatform::getRamUsagePercent() {
    return ramCache_.get([this]() { return getRamUsagePercentImpl(); });
}

int WindowsPlatform::getRamUsagePercentImpl() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);

    if (GlobalMemoryStatusEx(&statex)) {
        return (int)statex.dwMemoryLoad;
    }
    
    return 0;
}

std::string WindowsPlatform::getFreeDiskSpaceGB(const std::string& drivePath) {
	return diskSpaceCache_.get([this, drivePath]() { return getFreeDiskSpaceGBImpl(drivePath); });
}

std::string WindowsPlatform::getFreeDiskSpaceGBImpl(const std::string& drivePath) {
    ULARGE_INTEGER freeBytesAvailableToCaller;
    ULARGE_INTEGER totalNumberOfBytes;
    ULARGE_INTEGER totalNumberOfFreeBytes;
    
    std::wstring wDrivePath = L"C:\\";
    if (!drivePath.empty()) {
        std::string path = drivePath;
        if (path.size() == 2 && path[1] == ':') path += "\\";
        wDrivePath = std::wstring(path.begin(), path.end());
    }

    if (GetDiskFreeSpaceExW(
        wDrivePath.c_str(),
        &freeBytesAvailableToCaller,
        &totalNumberOfBytes,
        &totalNumberOfFreeBytes
    ))
    {
        double freeGB = (double)freeBytesAvailableToCaller.QuadPart / (1024.0 * 1024.0 * 1024.0);
        std::stringstream ss;
        ss << std::fixed << std::setprecision(1) << freeGB;
        return ss.str();
    }
    return "Unknown";
}

std::string WindowsPlatform::getWindowsUpdateState() {
    return windowsUpdateCache_.get([this]() { return getWindowsUpdateStateImpl(); });
}

std::string WindowsPlatform::getWindowsUpdateStateImpl() {
    HKEY hKey;

    const REGSAM samDesired = KEY_READ | KEY_WOW64_64KEY;

    LONG lResult = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired",
        0,
        samDesired,
        &hKey
    );

    if (lResult == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "Pending Reboot";
    }

    lResult = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending",
        0,
        samDesired,
        &hKey
    );

    if (lResult == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "Pending Reboot";
    }

    return "Up to Date or Unknown";
}

void WindowsPlatform::updatePdhMetrics() {
	std::lock_guard<std::mutex> lock(platformMutex_);
    
    if (m_hQuery.get()) {
        PdhCollectQueryData((PDH_HQUERY)m_hQuery.get());
    }
    updateCpuTimes();
}

float WindowsPlatform::getDiskQueueLength() {
	return diskQueueCache_.get([this]() { return getDiskQueueLengthImpl(); });
}

float WindowsPlatform::getDiskQueueLengthImpl()
{
    if (m_hQuery.get() == NULL || m_hDiskCounter == NULL) return 0.0f;

    PDH_FMT_COUNTERVALUE value;
    // PdhCollectQueryData is now called externally in updatePdhMetrics()
    if (PdhGetFormattedCounterValue(m_hDiskCounter, PDH_FMT_FLOAT, NULL, &value) == ERROR_SUCCESS) {
        return (float)value.doubleValue;
    }
    return 0.0f;
}

float WindowsPlatform::getNetworkRetransRate() {
    return netRetransCache_.get([this]() { return getNetworkRetransRateImpl(); });
}

float WindowsPlatform::getNetworkRetransRateImpl()
{
    if (m_hQuery.get() == NULL || m_hNetRetransCounter == NULL) return 0.0f;

    PDH_FMT_COUNTERVALUE value;
    // PdhCollectQueryData is now called externally in updatePdhMetrics()
    if (PdhGetFormattedCounterValue(m_hNetRetransCounter, PDH_FMT_FLOAT, NULL, &value) == ERROR_SUCCESS) {
        return (float)value.doubleValue;
    }
    return 0.0f;
}

// Helper methods for the service
void WindowsPlatform::reportStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint)
{
    if (g_status_handle == nullptr)
        return;
    g_service_status.dwCurrentState = currentState;
    g_service_status.dwWin32ExitCode = win32ExitCode;
    g_service_status.dwWaitHint = waitHint;
    SetServiceStatus(g_status_handle, &g_service_status);
}

std::string WindowsPlatform::getSystemUptime() {
	return uptimeCache_.get([this]() { return getSystemUptimeImpl(); });
}

std::string WindowsPlatform::getSystemUptimeImpl()
{
    // Get the system tick count in milliseconds
    ULONGLONG ms = GetTickCount64();

    // Convert milliseconds to days, hours, minutes, seconds
    ULONGLONG seconds = ms / 1000;
    ULONGLONG minutes = seconds / 60;
    ULONGLONG hours = minutes / 60;
    ULONGLONG days = hours / 24;

    seconds %= 60;
    minutes %= 60;
    hours %= 24;

    std::stringstream ss;
    ss << days << "d ";
    ss << std::setw(2) << std::setfill('0') << hours << "h ";
    ss << std::setw(2) << std::setfill('0') << minutes << "m ";
    ss << std::setw(2) << std::setfill('0') << seconds << "s";

    return ss.str();
}

std::string WindowsPlatform::getGpuDriverInfo() {
	return gpuDriverCache_.get([this]() { return getGpuDriverInfoImpl(); });
}

std::string WindowsPlatform::getGpuDriverInfoImpl() {
    std::string result = "GPU: Not Found.";
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc
    );

    if (FAILED(hr)) goto cleanup;

    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        0,
        0,
        0,
        &pSvc
    );

    if (FAILED(hr)) goto cleanup;

    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hr)) goto cleanup;

    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT Name, DriverVersion FROM Win32_VideoController"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) goto cleanup;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) break;

        VARIANT vtPropName, vtPropVersion;
        HRESULT hrGet1 = pclsObj->Get(L"Name", 0, &vtPropName, 0, 0);
        HRESULT hrGet2 = pclsObj->Get(L"DriverVersion", 0, &vtPropVersion, 0, 0);

        if (hrGet1 == S_OK && hrGet2 == S_OK) {
            std::string name = WideToUtf8(vtPropName.bstrVal ? vtPropName.bstrVal : L"Unknown GPU");
            std::string version = WideToUtf8(vtPropVersion.bstrVal ? vtPropVersion.bstrVal : L"Unknown Version");

            if (name.find("Intel") != std::string::npos ||
                name.find("HD Graphics") != std::string::npos ||
                name.find("UHD Graphics") != std::string::npos ||
                name.find("Xe Graphics") != std::string::npos) {
                result = "GPU: " + name + " | Driver: " + version;
                VariantClear(&vtPropName);
                VariantClear(&vtPropVersion);
                pclsObj->Release();
                pclsObj = NULL;
                goto cleanup;
            }
        }
        VariantClear(&vtPropName);
        VariantClear(&vtPropVersion);
        pclsObj->Release();
        pclsObj = NULL;
    }

cleanup:
    if (pclsObj) pclsObj->Release();
    if (pEnumerator) pEnumerator->Release();
    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();

    return result;
}

float WindowsPlatform::getGpuUsagePercent() {
    return gpuUsageCache_.get([this]() { return getGpuUsagePercentImpl(); });
}

float WindowsPlatform::getGpuUsagePercentImpl() {
    if (m_hQuery.get() == NULL | m_hGpuTotalCounter == NULL) return 0.0f;

    PDH_FMT_COUNTERVALUE_ITEM_W* items = nullptr;
    DWORD bufferSize = 0;
    DWORD item_count = 0;
    float totalUsage = 0.0f;
    PDH_STATUS status;

    status = PdhGetFormattedCounterArrayW(m_hGpuTotalCounter, PDH_FMT_FLOAT, &bufferSize, &item_count, nullptr);

    if (status != PDH_MORE_DATA && status != ERROR_SUCCESS) {
        return 0.0f;
    }

    std::vector<BYTE> buffer(bufferSize);
    items = (PDH_FMT_COUNTERVALUE_ITEM_W*)buffer.data();

    status = PdhGetFormattedCounterArrayW(m_hGpuTotalCounter, PDH_FMT_FLOAT, &bufferSize, &item_count, items);

    if (status == ERROR_SUCCESS) {
        for (DWORD i = 0; i < item_count; i++) {
            totalUsage += (float)items[i].FmtValue.doubleValue;
        }
    }

    return (totalUsage > 100.0f ? 100.0f : totalUsage);
}

std::string WindowsPlatform::getProcessName(HANDLE hProcess) {
    wchar_t szProcessPath[MAX_PATH];
    DWORD pathSize = MAX_PATH;

    if (QueryFullProcessImageNameW(hProcess, 0, szProcessPath, &pathSize)) {
        std::wstring wsPath = szProcessPath;
        size_t lastSlash = wsPath.find_last_of(L"\\");
        if (lastSlash != std::wstring::npos) {
            return WideToUtf8(wsPath.substr(lastSlash + 1));
        }

        return WideToUtf8(wsPath);
    }

    TCHAR szProcessName[MAX_PATH] = TEXT("unknown");
    DWORD bufferSize = sizeof(szProcessName) / sizeof(TCHAR);

    if (GetModuleBaseName(hProcess, NULL, szProcessName, bufferSize)) {
        return WideToUtf8(std::wstring(reinterpret_cast<const wchar_t*>(szProcessName)));
    }

    return "unknown";
}

std::string WindowsPlatform::getHighRamProcesses() {
    return highRamProcsCache_.get([this]() { return getHighRamProcessesImpl(); });
}

std::string WindowsPlatform::getHighRamProcessesImpl() {
    const ULONGLONG HIGH_RAM_THRESHOLD_MB = 500;
    const ULONGLONG HIGH_RAM_THRESHOLD_BYTES = HIGH_RAM_THRESHOLD_MB * 1024 * 1024;

    DWORD aProcesses[2048];
    DWORD cbNeeded;
    DWORD cProcesses;
    std::stringstream ss;
    bool first = true;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return "error: EnumProcesses failed";
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < cProcesses; i++) {
        if (aProcesses[i] == 0) continue;

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 
            FALSE, 
            aProcesses[i]
        );

        if (hProcess == NULL) continue;

        PROCESS_MEMORY_COUNTERS pmc;

        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            if (pmc.PagefileUsage >= HIGH_RAM_THRESHOLD_BYTES) {
                std::string name = getProcessName(hProcess);

                ULONGLONG ram_mb = pmc.PagefileUsage / (1024 * 1024);

                if (!first) {
                    ss << "|";
                }

                ss << name << "(" << aProcesses[i] << ")=" << ram_mb  << "MB";
                first = false;
            }
        }

        CloseHandle(hProcess);
    }

    std::string result = ss.str();
    return result.empty() ? "None" : result;
}

void WindowsPlatform::registerServiceHandler()
{
    g_status_handle = RegisterServiceCtrlHandlerW(L"CoreStationHXAgent", ServiceCtrlHandler);
    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    reportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
}

HANDLE WindowsPlatform::getStopEvent()
{
    return g_stop_event.get();
}

void WindowsPlatform::startService()
{
    startSessionMonitor();
    if (on_start_callback)
        on_start_callback();
}

void WindowsPlatform::stopService()
{
    stopSessionMonitor();
    if (on_stop_callback)
        on_stop_callback();
    SetEvent(g_stop_event.get());
}

#endif // _WIN32
