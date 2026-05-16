#pragma once
// Windows network interface and OS version discovery (read-only, no retained handles).
#ifdef _WIN32
#include "core/SystemState.h"
#include <string>
#include <vector>

class WindowsNetworkProvider {
public:
    std::vector<NetworkInterface> getNetworkInterfaces();
    std::string getHostname();
    std::string getLoggedInUser();
    std::string getOsVersion();
    std::string getOsBuild();
};

#endif // _WIN32
