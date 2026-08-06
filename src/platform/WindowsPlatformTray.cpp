// System-tray integration: starting the tray app directly in a user session,
// or spawning/killing a helper process into the active user session when
// running as a Session 0 service (where a service can't show UI directly).
#ifdef _WIN32
#include <windows.h>
#include "WindowsPlatform.h"
#include <wtsapi32.h>
#include <userenv.h>
#include <mutex>
#include <string>

#ifdef ENABLE_TRAY_APP
#include "../modules/tray/TrayApp.h"
#endif

void WindowsPlatform::startTrayApp()
{
#ifdef ENABLE_TRAY_APP
    DWORD mySession = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &mySession);

    if (mySession == 0) {
        // Session 0 (SYSTEM service) — tray must live in the user session
        spawnTrayHelper();
    } else {
        // User session — create TrayApp directly in this process
        if (!tray_app_) {
            tray_app_ = std::make_unique<TrayApp>(this);
            tray_app_->Start();
            logMessage("Tray App Started.");
        }
    }
#endif
}

void WindowsPlatform::killTrayHelper()
{
    // Caller must hold trayHelperMutex_
    if (hTrayHelperProcess_ != INVALID_HANDLE_VALUE) {
        TerminateProcess(hTrayHelperProcess_, 0);
        CloseHandle(hTrayHelperProcess_);
        hTrayHelperProcess_ = INVALID_HANDLE_VALUE;
    }
}

void WindowsPlatform::stopTrayApp()
{
#ifdef ENABLE_TRAY_APP
    if (tray_app_) {
        tray_app_->Stop();
        tray_app_.reset();
        logMessage("Tray App Stopped.");
    }
    {
        std::lock_guard<std::mutex> lock(trayHelperMutex_);
        killTrayHelper();
    }
    logMessage("[Tray] Helper process terminated.");
#endif
}

void WindowsPlatform::spawnTrayHelper()
{
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) {
        logMessage("[Tray] No active console session — cannot spawn tray helper.");
        return;
    }

    HANDLE hToken = NULL;
    if (!WTSQueryUserToken(sessionId, &hToken)) {
        logMessage("[Tray] WTSQueryUserToken failed: " + std::to_string(GetLastError()));
        return;
    }

    HANDLE hPrimary = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &hPrimary)) {
        logMessage("[Tray] DuplicateTokenEx failed: " + std::to_string(GetLastError()));
        CloseHandle(hToken);
        return;
    }
    CloseHandle(hToken);

    LPVOID pEnv = NULL;
    CreateEnvironmentBlock(&pEnv, hPrimary, FALSE);

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring cmdLine = L"\"" + std::wstring(exePath) + L"\" --tray-only --parent-pid " +
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
        logMessage("[Tray] CreateProcessAsUser failed: " + std::to_string(GetLastError()));
        return;
    }

    CloseHandle(pi.hThread);
    {
        std::lock_guard<std::mutex> lock(trayHelperMutex_);
        if (hTrayHelperProcess_ != INVALID_HANDLE_VALUE) {
            CloseHandle(hTrayHelperProcess_);
        }
        hTrayHelperProcess_ = pi.hProcess;
    }
    logMessage("[Tray] Helper spawned in session " + std::to_string(sessionId) +
               ", PID=" + std::to_string(pi.dwProcessId));
}

int WindowsPlatform::runAsTrayHelper(DWORD parentPid)
{
    logMessage("[Tray] Running as tray helper, parentPid=" + std::to_string(parentPid));

#ifdef ENABLE_TRAY_APP
    // We are already in the user session — startTrayApp() takes the direct path
    startTrayApp();

    // Block until the service process exits
    HANDLE hParent = (parentPid != 0)
        ? OpenProcess(SYNCHRONIZE, FALSE, parentPid)
        : NULL;

    if (hParent) {
        WaitForSingleObject(hParent, INFINITE);
        CloseHandle(hParent);
        logMessage("[Tray] Parent service exited — shutting down tray helper.");
    } else {
        // No parent handle available — wait on stop event
        WaitForSingleObject(g_stop_event.get(), INFINITE);
    }

    stopTrayApp();
#endif
    return 0;
}

#endif // _WIN32
