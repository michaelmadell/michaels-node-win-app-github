#ifdef __linux__
#include "LinuxPlatform.h"
#include <iostream>
#include <memory>
#include <cstdio>
#include <csignal>
#include <unistd.h>
#include <syslog.h>
#include <atomic>
#include <thread>

extern std::atomic<bool> g_terminate;

// Defined in LinuxPlatformDbus.cpp - set here in run(), read by dbusThread().
extern SessionStateCallback g_session_callback;
void dbusThread();

std::string executeCommand(const std::string& cmd) {
    char buffer[128];
    std::string result = "";

    std::unique_ptr<FILE, int(*)(FILE*)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return "";

    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
        result += buffer;
    }

    result.erase(result.find_last_not_of("\n\r") + 1);
    return result;
}

static LinuxPlatform* g_linux_instance = nullptr;

void signal_handler(int /*signum*/) {
    g_terminate = true;
}

LinuxPlatform::LinuxPlatform() {
    g_linux_instance = this;
    getCpuTimes(m_prev_total_time, m_prev_idle_time);
#ifdef ENABLE_METRICS
    updatePdhMetrics();
#endif
}

std::unique_ptr<Platform> createPlatform() {
    return std::make_unique<LinuxPlatform>();
}

int LinuxPlatform::run(
    int /*argc*/, char* /*argv*/[],
    VoidCallback on_start,
    StringCallback on_stop,
    PowerStateCallback power_cb,
    SessionStateCallback session_cb
) {
    g_session_callback = session_cb;

    std::cout << "[DEBUG] Running in foreground mode as root." << std::endl;

    openlog("CoreStationHXAgent", LOG_PID, LOG_DAEMON);

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    m_dbus_thread = std::thread(dbusThread);
    m_dbus_thread.detach();

    if (on_start) {
        on_start();
    }

    while (!g_terminate.load()) {
        sleep(1);
    }

    logMessage("Termination signal received. Shutting Down.");
    if (power_cb) {
        power_cb("controlShutdown");
    }

    if (on_stop) {
        on_stop("shutdown");
    }
    std::cout << "[DEBUG] Application terminating cleanly." << std::endl;
    closelog();
    return 0;
}

#ifdef ENABLE_C2A
void LinuxPlatform::shutdownSystem(const std::string& reason) {
    logMessage("Shutdown requested via LinuxPlatform::shutdownSystem()." +
        (reason.empty() ? "" : (" Reason: " + reason)));
    executeCommand("systemctl poweroff");
}

void LinuxPlatform::restartSystem(const std::string& reason) {
    logMessage("Restart requested via LinuxPlatform::restartSystem()." +
        (reason.empty() ? "" : (" Reason: " + reason)));
    executeCommand("systemctl reboot");
}

// Finds the session id of the active graphical/console user session, using
// the same Class=user filtering getLoggedInUser() uses (loginctl sessions
// can include greeter/service sessions that aren't the interactive user).
static std::string getActiveUserSessionId() {
    std::string sessionId = executeCommand(
        "for s in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do "
        "c=$(loginctl show-session \"$s\" -p Class --value 2>/dev/null); "
        "if [ \"$c\" = \"user\" ]; then echo \"$s\"; break; fi; "
        "done"
    );
    sessionId.erase(sessionId.find_last_not_of("\n\r \t") + 1);
    return sessionId;
}

void LinuxPlatform::lockActiveSession() {
    std::string sessionId = getActiveUserSessionId();
    if (sessionId.empty()) {
        logMessage("lockActiveSession: no active user session found.");
        return;
    }
    executeCommand("loginctl lock-session " + sessionId);
}

void LinuxPlatform::logoffActiveSession() {
    std::string sessionId = getActiveUserSessionId();
    if (sessionId.empty()) {
        logMessage("logoffActiveSession: no active user session found.");
        return;
    }
    executeCommand("loginctl terminate-session " + sessionId);
}
#endif

#endif
