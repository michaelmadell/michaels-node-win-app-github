#ifdef _WIN32
#ifdef ENABLE_VNC

#include "VncSession.h"
#include <userenv.h>
#include <wtsapi32.h>
#include <chrono>

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "wtsapi32.lib")

VncSession::VncSession(std::function<void(const std::string&)> logger)
    : log_(std::move(logger)) {
}

VncSession::~VncSession() {
    Stop();
}

void VncSession::Start() {
    stop_ = false;
    SpawnHelper();
    watchThread_ = std::thread([this]() { WatchThread(); });
}

void VncSession::Stop() {
    stop_ = true;
    {
        std::lock_guard<std::mutex> lock(helperMutex_);
        KillHelper();
    }
    if (watchThread_.joinable()) {
        watchThread_.join();
    }
}

void VncSession::OnSessionLogon() {
    std::thread([this]() {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        {
            std::lock_guard<std::mutex> lock(helperMutex_);
            KillHelper();
        }
        SpawnHelper();
        log_("[VNC] Helper respawned after session logon.");
    }).detach();
}

void VncSession::OnSessionLogoff() {
    std::lock_guard<std::mutex> lock(helperMutex_);
    KillHelper();
    log_("[VNC] Helper terminated after session logoff.");
}

void VncSession::SpawnHelper() {
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) {
        log_("[VNC] No active console session.");
        return;
    }

    HANDLE hToken = NULL;
    if (!WTSQueryUserToken(sessionId, &hToken)) {
        log_("[VNC] WTSQueryUserToken failed: " + std::to_string(GetLastError()));
        return;
    }

    HANDLE hPrimary = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &hPrimary)) {
        log_("[VNC] DuplicateTokenEx failed: " + std::to_string(GetLastError()));
        CloseHandle(hToken);
        return;
    }
    CloseHandle(hToken);

    LPVOID pEnv = NULL;
    CreateEnvironmentBlock(&pEnv, hPrimary, FALSE);

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring cmdLine = L"\"" + std::wstring(exePath) + L"\" --vnc-only --parent-pid " +
                           std::to_wstring(GetCurrentProcessId());

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessAsUserW(
        hPrimary, NULL,
        const_cast<LPWSTR>(cmdLine.c_str()),
        NULL, NULL, FALSE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        pEnv, NULL, &si, &pi);

    if (pEnv) DestroyEnvironmentBlock(pEnv);
    CloseHandle(hPrimary);

    if (!ok) {
        log_("[VNC] CreateProcessAsUser failed: " + std::to_string(GetLastError()));
        return;
    }

    CloseHandle(pi.hThread);
    {
        std::lock_guard<std::mutex> lock(helperMutex_);
        if (hHelper_ != INVALID_HANDLE_VALUE) CloseHandle(hHelper_);
        hHelper_ = pi.hProcess;
    }
    log_("[VNC] Helper spawned in session " + std::to_string(sessionId) +
         ", PID=" + std::to_string(pi.dwProcessId) + ", port=5900");
}

void VncSession::KillHelper() {
    // Caller must hold helperMutex_
    if (hHelper_ != INVALID_HANDLE_VALUE) {
        TerminateProcess(hHelper_, 0);
        CloseHandle(hHelper_);
        hHelper_ = INVALID_HANDLE_VALUE;
    }
}

void VncSession::WatchThread() {
    // Respawn the helper if it exits unexpectedly (e.g. crash) while a
    // user session is still active.
    while (!stop_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        if (stop_.load()) break;

        bool needsRespawn = false;
        {
            std::lock_guard<std::mutex> lock(helperMutex_);
            if (hHelper_ != INVALID_HANDLE_VALUE) {
                DWORD exitCode = 0;
                if (GetExitCodeProcess(hHelper_, &exitCode) && exitCode != STILL_ACTIVE) {
                    CloseHandle(hHelper_);
                    hHelper_ = INVALID_HANDLE_VALUE;
                    log_("[VNC] Helper exited unexpectedly (code=" + std::to_string(exitCode) + "), respawning.");
                    needsRespawn = true;
                }
            }
        } // lock released before SpawnHelper (which acquires it internally)

        if (needsRespawn && !stop_.load()) {
            SpawnHelper();
        }
    }
}

#endif // ENABLE_VNC
#endif // _WIN32
