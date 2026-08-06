// Session-change (logon/lock/logoff) monitoring glue: starts/stops the
// SessionMonitor module and reacts to session-state changes by
// respawning/killing the tray helper as appropriate.
#ifdef _WIN32
#include <windows.h>
#include "WindowsPlatform.h"
#include <thread>
#include <mutex>
#include <chrono>
#include <string>

#include "../modules/session/SessionMonitor.h"

void WindowsPlatform::startSessionMonitor() {
#ifdef ENABLE_SESSION_MONITOR
    auto wrappedCallback = [this](const std::string& state) {
        // Forward to the application-level session callback first
        if (session_callback) session_callback(state);

#ifdef ENABLE_TRAY_APP
        DWORD mySession = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &mySession);
        if (mySession != 0) return; // Only relevant when running as Session 0 service

        // Logon / console-connect / RDP-connect: always kill any stale helper
        // and spawn a fresh one. Delay 2s so the user desktop is ready.
        if (state == "5" || state == "1" || state == "3") {
            std::thread([this]() {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                {
                    std::lock_guard<std::mutex> lock(trayHelperMutex_);
                    killTrayHelper();
                }
                spawnTrayHelper();
                logMessage("[Tray] Helper respawned after session logon.");
            }).detach();
        }
        // Unlock: only spawn if the helper is not already running (e.g. after
        // reboot where the initial spawn failed because the shell wasn't ready).
        else if (state == "8") {
            bool needsSpawn = false;
            {
                std::lock_guard<std::mutex> lock(trayHelperMutex_);
                if (hTrayHelperProcess_ == INVALID_HANDLE_VALUE) {
                    needsSpawn = true;
                } else {
                    DWORD exitCode = 0;
                    if (!GetExitCodeProcess(hTrayHelperProcess_, &exitCode) ||
                        exitCode != STILL_ACTIVE) {
                        CloseHandle(hTrayHelperProcess_);
                        hTrayHelperProcess_ = INVALID_HANDLE_VALUE;
                        needsSpawn = true;
                    }
                }
            }
            if (needsSpawn) {
                std::thread([this]() {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    spawnTrayHelper();
                    logMessage("[Tray] Helper spawned after session unlock.");
                }).detach();
            }
        }
        // Logoff / disconnect / terminate: kill the helper.
        else if (state == "6" || state == "2" || state == "4" || state == "11") {
            std::lock_guard<std::mutex> lock(trayHelperMutex_);
            killTrayHelper();
            logMessage("[Tray] Helper terminated after session logoff/disconnect.");
        }
#endif
    };

    session_monitor_ = std::make_unique<SessionMonitor>(this, wrappedCallback);
    session_monitor_->Start();
#endif
}

void WindowsPlatform::stopSessionMonitor() {
#ifdef ENABLE_SESSION_MONITOR
    if (session_monitor_) {
        session_monitor_->Stop();
        session_monitor_.reset();
    }
#endif
}

std::string WindowsPlatform::getCurrentSessionState() {
#ifdef ENABLE_SESSION_MONITOR
    if (session_monitor_) {
        return session_monitor_->GetCurrentSessionState();
    }
#endif
    return "0";
}

#endif // _WIN32
