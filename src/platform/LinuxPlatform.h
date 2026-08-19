#pragma once

#ifdef __linux__
#include "../core/Platform.h"
#include <thread>
#include <string>
#include <memory>

// Forward declaration -- full definition only needed by LinuxPlatformSerialBridge.cpp.
class SerialBridgeSocket;

// Internal helpers shared across the LinuxPlatform*.cpp translation units.
// Defined in LinuxPlatform.cpp.
std::string executeCommand(const std::string& cmd);
// Defined in LinuxPlatformMetrics.cpp.
void getCpuTimes(unsigned long long& total_time, unsigned long long& idle_time);

class LinuxPlatform : public Platform {
public:
    LinuxPlatform();
    // Declared here, defined out-of-line in LinuxPlatformSerialBridge.cpp
    // (as `= default`, not inline) -- required because serial_bridge_socket_
    // is a unique_ptr<SerialBridgeSocket> and SerialBridgeSocket is only
    // forward-declared in this header. An inline `= default` destructor
    // here would need SerialBridgeSocket's complete type to instantiate
    // std::default_delete, and fail with "invalid application of 'sizeof'
    // to incomplete type" wherever this header is included (confirmed --
    // this exact error was hit compiling LinuxPlatform.cpp on Linux).
    ~LinuxPlatform();

    // --- Core Platform Methods (Already Implemented Down Below) ---
    std::vector<NetworkInterface> getNetworkInterfaces() override;
    std::string getHostname() override;
    std::string getCurrentSessionState() override;
    std::string getLoggedInUser() override;
    std::string getOsVersion() override;
    std::string getOsBuild() override;
    void logMessage(const std::string& message) override;

    // IPC bridge glue (Unix domain socket counterpart of WindowsPlatform's
    // named-pipe bridge). See ENABLE_SERIAL_BRIDGE_PIPE / BUILD_SERIAL_BRIDGE_PIPE.
    void setSerialBridgeHandler(SerialBridgeHandler handler) override;
    bool forwardSerialBridgeMessage(const std::string& data) override;
#ifdef ENABLE_SERIAL_BRIDGE_PIPE
    void startSerialBridgeSocket();
    void stopSerialBridgeSocket();
#endif

    // Cheap, dependency-free system stats - always available (see Platform.h).
    int getCpuUsagePercent() override;
    int getRamUsagePercent() override;
    std::string getSystemUptime() override;

#ifdef ENABLE_METRICS
    // --- Performance Metrics ---
    std::string getFreeDiskSpaceGB(const std::string& drivePath) override;
    std::string getWindowsUpdateState() override;
    float getDiskQueueLength() override;
    float getNetworkRetransRate() override;
    void updatePdhMetrics() override;

    // --- GPU/Process Methods ---
    std::string getGpuDriverInfo() override;
    float getGpuUsagePercent() override;
    std::string getHighRamProcesses() override;
#endif

#ifdef ENABLE_C2A
    // --- C2A support methods ---
    void showMessageDialog(const std::string& title, const std::string& message) override;
    void shutdownSystem(const std::string& reason = "") override;
    void restartSystem(const std::string& reason = "") override;
    void lockActiveSession() override;
    void logoffActiveSession() override;
#endif

    int run(
        int argc, char* argv[],
        VoidCallback on_start,
        StringCallback on_stop,
        PowerStateCallback power_cb,
        SessionStateCallback session_cb
    ) override;

private:
    std::thread m_dbus_thread;

    unsigned long long m_prev_total_time = 0;
    unsigned long long m_prev_idle_time = 0;

    unsigned long long m_prev_tcp_out = 0;
    unsigned long long m_prev_tcp_retrans = 0;

    // IPC bridge glue. LinuxPlatform owns its own handler storage --
    // Platform::setSerialBridgeHandler's base implementation is a no-op, and
    // WindowsPlatform's stored handler is private to that class, so this
    // cannot be shared between the two platform implementations.
    SerialBridgeHandler serial_bridge_handler_;
#ifdef ENABLE_SERIAL_BRIDGE_PIPE
    std::unique_ptr<SerialBridgeSocket> serial_bridge_socket_;
#endif
};

#endif // __linux__
