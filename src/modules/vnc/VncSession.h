#pragma once

#ifdef _WIN32
#ifdef ENABLE_VNC

#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>

// Manages the VNC helper process in the active user session.
// The service (Session 0) instantiates this; it spawns the same exe
// with --vnc-only into the user session and monitors it.
class VncSession {
public:
    explicit VncSession(std::function<void(const std::string&)> logger);
    ~VncSession();

    void Start();
    void Stop();

    // Call when a session logon/unlock occurs so the helper can be respawned.
    void OnSessionLogon();

    // Call when a session logoff/disconnect occurs.
    void OnSessionLogoff();

    VncSession(const VncSession&) = delete;
    VncSession& operator=(const VncSession&) = delete;

private:
    void SpawnHelper();
    void KillHelper();
    void WatchThread();

    std::function<void(const std::string&)> log_;
    HANDLE hHelper_  = INVALID_HANDLE_VALUE;
    std::thread watchThread_;
    std::atomic<bool> stop_{ false };
    std::mutex helperMutex_;
};

#endif // ENABLE_VNC
#endif // _WIN32
