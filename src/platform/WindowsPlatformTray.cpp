// System-tray integration: starting the tray app directly in a user session,
// or spawning/killing a helper process into the active user session when
// running as a Session 0 service (where a service can't show UI directly).
#ifdef _WIN32
#include <windows.h>
#include "WindowsPlatform.h"
#include <wtsapi32.h>
#include <userenv.h>
#include <format>
#include <mutex>
#include <string>
#include "../core/Logging.h"

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
    // Called at start-up and on session changes; at boot there's often no
    // console session yet, so only log to Event Viewer when the error changes.
    auto sessionId = activeConsoleSessionId();
    if (!sessionId) {
        reportErrorOnChange(core::kMsgIDPlatform, "trayHelper", "[Tray] Cannot spawn tray helper", sessionId.error());
        return;
    }

    auto pi = launchTrayHelper(*sessionId);
    if (!pi) {
        reportErrorOnChange(core::kMsgIDPlatform, "trayHelper", "[Tray] Cannot spawn tray helper", pi.error());
        return;
    }
    clearReportedError("trayHelper");

    CloseHandle(pi->hThread);
    {
        std::lock_guard<std::mutex> lock(trayHelperMutex_);
        if (hTrayHelperProcess_ != INVALID_HANDLE_VALUE) {
            CloseHandle(hTrayHelperProcess_);
        }
        hTrayHelperProcess_ = pi->hProcess;
    }
    logMessage(std::format("[Tray] Helper spawned in session {}, PID={}", *sessionId, pi->dwProcessId));
}

std::expected<PROCESS_INFORMATION, core::PlatformError> WindowsPlatform::launchTrayHelper(DWORD sessionId)
{
    auto launchFailed = [](const char* what, DWORD err) {
        return std::unexpected(core::PlatformError{
            .code = core::CoreError::Code::Internal,
            .sub_code = core::PlatformError::SubCode::ProcessLaunchFailed,
            .message = std::format("{} failed", what),
            .platform_error = err,
        });
    };

    HANDLE rawToken = NULL;
    if (!WTSQueryUserToken(sessionId, &rawToken)) {
        return launchFailed("WTSQueryUserToken", GetLastError());
    }
    UniqueHandle hToken(rawToken);

    HANDLE rawPrimary = NULL;
    if (!DuplicateTokenEx(hToken.get(), MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &rawPrimary)) {
        return launchFailed("DuplicateTokenEx", GetLastError());
    }
    UniqueHandle hPrimary(rawPrimary);

    LPVOID pEnv = NULL;
    CreateEnvironmentBlock(&pEnv, hPrimary.get(), FALSE);

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring cmdLine = L"\"" + std::wstring(exePath) + L"\" --tray-only --parent-pid " +
                           std::to_wstring(GetCurrentProcessId());

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessAsUserW(
        hPrimary.get(), NULL,
        const_cast<LPWSTR>(cmdLine.c_str()),
        NULL, NULL, FALSE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        pEnv, NULL, &si, &pi);
    DWORD err = GetLastError();

    if (pEnv) DestroyEnvironmentBlock(pEnv);

    if (!ok) {
        return launchFailed("CreateProcessAsUser", err);
    }
    return pi;
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
