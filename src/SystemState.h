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

    bool operator!=(const SystemState& other) const {
        return std::tie(networkInterfaces, hostname, powerState, sessionState, username) !=
               std::tie(other.networkInterfaces, other.hostname, other.powerState, other.sessionState, other.username);
    }
};