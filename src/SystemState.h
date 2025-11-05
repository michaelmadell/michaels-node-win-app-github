#pragma once

#include <string>
#include <tuple>
#include <vector>

struct NetworkInterface {
    std::string name;
    std::string ipv4;
    std::string ipv6;
    std::string dhcp;
    std::string linkStatus;
    std::string macAddress;

    bool operator!=(const NetworkInterface& other) const {
        return std::tie(name, ipv4, ipv6, dhcp, linkStatus, macAddress) !=
               std::tie(other.name, other.ipv4, other.ipv6, other.dhcp, other.linkStatus, other.macAddress);
    }

    bool operator==(const NetworkInterface& other) const {
        return std::tie(name, ipv4, ipv6, dhcp, linkStatus, macAddress) ==
               std::tie(other.name, other.ipv4, other.ipv6, other.dhcp, other.linkStatus, other.macAddress);
    }
};

struct SystemState {
    std::vector<NetworkInterface> networkInterfaces;
    std::string hostname;
    std::string powerState;
    std::string sessionState;
    std::string username;
    int cpuUsagePercent = 0;
    int ramUsagePercent = 0;
    std::string freeDiskSpaceGB;
    std::string windowsUpdateState = "Unknown";
    float diskQueueLength = 0.0f;
    float networkRetransRate = 0.0f;
    std::string systemUptime;
    std::string gpuDriverInfo = "Unknown";
    float gpuUsagePercent = 0.0f;
    std::string highRamProcesses = "none";

    bool operator!=(const SystemState& other) const {
        return std::tie(networkInterfaces, hostname, powerState, sessionState, username, cpuUsagePercent, ramUsagePercent, freeDiskSpaceGB, windowsUpdateState, diskQueueLength, networkRetransRate, systemUptime, gpuDriverInfo, gpuUsagePercent, highRamProcesses) !=
               std::tie(other.networkInterfaces, other.hostname, other.powerState, other.sessionState, other.username, other.cpuUsagePercent, other.ramUsagePercent, other.freeDiskSpaceGB, other.windowsUpdateState, other.diskQueueLength, other.networkRetransRate, other.systemUptime, other.gpuDriverInfo, other.gpuUsagePercent, other.highRamProcesses);
    }
};