#pragma once

#include "SystemState.h"
#include <string>
#include <vector>
#include <functional>
#include <memory>

using PowerStateCallback = std::function<void(const std::string&)>;
using SessionStateCallback = std::function<void(const std::string&)>;
using VoidCallback = std::function<void()>;
using StringCallback = std::function<void(const std::string&)>;

class Platform{
    public:
    virtual ~Platform() = default;

    virtual std::vector<NetworkInterface> getNetworkInterfaces() = 0;
    virtual std::string getHostname() = 0;
	virtual std::string getCurrentSessionState() = 0;
    virtual std::string getLoggedInUser() = 0;
    virtual std::string getOsVersion() = 0;
    virtual std::string getOsBuild() = 0;

    virtual void logMessage(const std::string& message) = 0;

    virtual int getCpuUsagePercent() = 0;
    virtual int getRamUsagePercent() = 0;
    virtual std::string getFreeDiskSpaceGB(const std::string& drivePath) = 0;
    virtual std::string getWindowsUpdateState() = 0;
    virtual float getDiskQueueLength() = 0;
    virtual float getNetworkRetransRate() = 0;
    virtual std::string getSystemUptime() = 0;
    virtual void updatePdhMetrics() = 0;

    virtual std::string getGpuDriverInfo() = 0;
    virtual float getGpuUsagePercent() = 0;
    virtual std::string getHighRamProcesses() = 0;

    virtual void showMessageDialog(const std::string& title, const std::string& message) = 0;

    virtual void shutdownSystem() = 0;

    virtual int run(
        int argc, char* argv[], 
        VoidCallback on_start,
        StringCallback on_stop,
        PowerStateCallback powerCb, 
        SessionStateCallback sessionCb) = 0;
};

// Replace the declaration with the correct std::unique_ptr usage
std::unique_ptr<Platform> createPlatform();
