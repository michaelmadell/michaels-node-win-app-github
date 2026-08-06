// Session-change monitoring via systemd-logind's D-Bus interface: watches
// for lock/unlock (via the Session's LockedHint property, since many desktop
// screen lockers don't emit logind's Lock/Unlock signals directly) and
// session add/remove, and reports the current session's lock state.
#ifdef __linux__
#include "LinuxPlatform.h"
#include <dbus/dbus.h>
#include <syslog.h>
#include <cstring>
#include <atomic>

extern std::atomic<bool> g_terminate;

// Set by LinuxPlatform::run(), read here.
SessionStateCallback g_session_callback;

void dbusThread() {
    DBusError err;
    dbus_error_init(&err);
    DBusConnection* conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (dbus_error_is_set(&err)) {
        syslog(LOG_ERR, "D-Bus connection error: %s", err.message);
        dbus_error_free(&err);
        return;
    }

    // Lock/Unlock signals are only emitted by logind when something calls
    // back into logind itself (e.g. loginctl lock-session). Many desktop
    // screen lockers (GNOME, KDE, light-locker, etc.) lock the screen
    // locally without notifying logind, so the Lock signal is unreliable.
    // The LockedHint property on the session object is kept in sync by
    // logind regardless of how the screen got locked/unlocked, so watch
    // PropertiesChanged for it instead.
    const char* match_rule = "type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged',arg0='org.freedesktop.login1.Session'";
    const char* match_rule3 = "type='signal',interface='org.freedesktop.login1.Manager',member='SessionNew'";
    const char* match_rule4 = "type='signal',interface='org.freedesktop.login1.Manager',member='SessionRemoved'";
    dbus_bus_add_match(conn, match_rule, &err);
    dbus_bus_add_match(conn, match_rule3, &err);
    dbus_bus_add_match(conn, match_rule4, &err);

    syslog(LOG_INFO, "D-Bus thread started and listening for session signals.");

    while (!g_terminate.load()) {
        dbus_connection_read_write_dispatch(conn, 200);
        DBusMessage* msg = dbus_connection_pop_message(conn);
        if (msg == NULL) continue;

        if (dbus_message_is_signal(msg, "org.freedesktop.DBus.Properties", "PropertiesChanged")) {
            DBusMessageIter args;
            if (dbus_message_iter_init(msg, &args) &&
                dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_STRING) {
                const char* changedInterface = nullptr;
                dbus_message_iter_get_basic(&args, &changedInterface);

                if (changedInterface && strcmp(changedInterface, "org.freedesktop.login1.Session") == 0 &&
                    dbus_message_iter_next(&args) &&
                    dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_ARRAY) {
                    DBusMessageIter dictIter;
                    dbus_message_iter_recurse(&args, &dictIter);

                    while (dbus_message_iter_get_arg_type(&dictIter) == DBUS_TYPE_DICT_ENTRY) {
                        DBusMessageIter entryIter;
                        dbus_message_iter_recurse(&dictIter, &entryIter);

                        const char* propName = nullptr;
                        dbus_message_iter_get_basic(&entryIter, &propName);

                        if (propName && strcmp(propName, "LockedHint") == 0 &&
                            dbus_message_iter_next(&entryIter) &&
                            dbus_message_iter_get_arg_type(&entryIter) == DBUS_TYPE_VARIANT) {
                            DBusMessageIter variantIter;
                            dbus_message_iter_recurse(&entryIter, &variantIter);

                            if (dbus_message_iter_get_arg_type(&variantIter) == DBUS_TYPE_BOOLEAN) {
                                dbus_bool_t lockedHint = FALSE;
                                dbus_message_iter_get_basic(&variantIter, &lockedHint);
                                if (g_session_callback) g_session_callback(lockedHint ? "7" : "8");
                            }
                        }
                        dbus_message_iter_next(&dictIter);
                    }
                }
            }
        } else if (dbus_message_is_signal(msg, "org.freedesktop.login1.Manager", "SessionNew")) {
            if (g_session_callback) g_session_callback("5");
        } else if (dbus_message_is_signal(msg, "org.freedesktop.login1.Manager", "SessionRemoved")) {
            if (g_session_callback) g_session_callback("6");
        }
        dbus_message_unref(msg);
    }

    syslog(LOG_INFO, "D-Bus thread terminating.");
    dbus_connection_unref(conn);
}

std::string LinuxPlatform::getCurrentSessionState() {
    std::string sessionId = executeCommand(
        "loginctl list-sessions --no-legend 2>/dev/null | awk 'NR==1{print $1}'"
    );

    if (sessionId.empty()) {
        return "unknown";
    }
    std::string locked = executeCommand(
        "loginctl show-session " + sessionId + " -p LockedHint --value 2>/dev/null"
    );

    locked.erase(locked.find_last_not_of("\n\r \t") + 1);

    if (locked == "yes") {
        return "7"; // Locked
    }

    return "5";
}

#endif // __linux__
