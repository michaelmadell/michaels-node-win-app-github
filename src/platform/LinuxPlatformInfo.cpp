// System information getters: hostname, logged-in user, OS version/build,
// network interfaces, message dialogs, and syslog logging.
#ifdef __linux__
#include "LinuxPlatform.h"
#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <syslog.h>
#include <unistd.h>

#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netpacket/packet.h> // For MAC addresses
#include <net/if.h>           // For interface flags
#include <sys/utsname.h>

std::string getDhcpStatus(const std::string& interfaceName) {
    try {
        std::string addrCmd = "ip -4 -o addr show dev " + interfaceName;
        std::string addrOutput = executeCommand(addrCmd);

        if (addrOutput.find(" dynamic ") != std::string::npos) {
            return "dhcp";
        }

        std::string routeCmd = "ip -4 -o route show dev " + interfaceName;
        std::string routeOutput = executeCommand(routeCmd);

        if (routeOutput.find("proto dhcp") != std::string::npos) {
            return "dhcp";
        }
    } catch (const std::exception& e) {
        std::cerr << "Error checking interface: " << e.what() << std::endl;
        return "static";
    }

    return "static";
}

std::vector<NetworkInterface> LinuxPlatform::getNetworkInterfaces() {
    std::map<std::string, NetworkInterface> interfaces_map;

    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        logMessage("getifaddrs failed.");
        return {};
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        std::string name = ifa->ifa_name;

        std::string carrierPath = "/sys/class/net/" + name + "/operstate";
        std::ifstream carrierFile(carrierPath);
        std::string operstate;

        if ( (ifa->ifa_flags & IFF_LOOPBACK) ) {
            continue;
        }

        if (interfaces_map.find(name) == interfaces_map.end()) {
            interfaces_map[name].name = name;

            if (carrierFile >> operstate && operstate == "up") {
                interfaces_map[name].linkStatus = "up";
            } else {
                interfaces_map[name].linkStatus = "down";
            }

            interfaces_map[name].ipv4 = "none";
            interfaces_map[name].ipv6 = "none";
            interfaces_map[name].macAddress = "none";
            interfaces_map[name].dhcp = getDhcpStatus(name);
        }

        int family = ifa->ifa_addr->sa_family;
        if (family == AF_PACKET && ifa->ifa_data != NULL) {
            struct sockaddr_ll* s = (struct sockaddr_ll*)ifa->ifa_addr;
            std::stringstream ss;
            for (int i = 0; i < s->sll_halen; i++) {
                ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)s->sll_addr[i];
                if (i < s->sll_halen - 1) ss << ":";
            }

            interfaces_map[name].macAddress = ss.str();
        } else if (family == AF_INET) {
            char host[NI_MAXHOST];
            getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            interfaces_map[name].ipv4 = host;
        } else if (family == AF_INET6) {
            char host[NI_MAXHOST];
            getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (std::string(host).rfind("fe80::", 0) != 0) {
                interfaces_map[name].ipv6 = host;
            }
        }
    }

    freeifaddrs(ifaddr);

    std::vector<NetworkInterface> result_vector;
    for (auto const& [name, iface] : interfaces_map) {
        const std::string& mac = iface.macAddress;
        if (mac.compare(0, 8, "00:17:FD") == 0 || // Amulet Hotkey
            mac.compare(0, 8, "00:13:95") == 0 || // Congatec
            mac.compare(0, 8, "00:07:32") == 0) { // AAEON
            result_vector.push_back(iface);
        }
    }
    return result_vector;
}

std::string LinuxPlatform::getOsVersion() {
    std::ifstream file("/etc/os-release");
    std::string line, version;
    while (std::getline(file, line)) {
        if (line.rfind("PRETTY_NAME=", 0) == 0) {
            version = line.substr(13);
            version.erase(std::remove(version.begin(), version.end(), '"'), version.end());
            return version;
        }
    }
    return "Unknown Linux";
}

std::string LinuxPlatform::getOsBuild() {
    struct utsname buffer;
    if (uname(&buffer) == 0) {
        return std::string(buffer.release);
    }
    return "Unknown Build";
}

#ifdef ENABLE_C2A
void LinuxPlatform::showMessageDialog(const std::string& title, const std::string& message) {
    // Placeholder implementation
    logMessage("ShowMessageDialog called with title: " + title + " and message: " + message);
}
#endif

static int SyslogPriorityFor(const std::string& message) {
    std::string upper = message;
    std::transform(upper.begin(), upper.end(), upper.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    if (upper.find("FATAL") != std::string::npos || upper.find("ERROR") != std::string::npos) {
        return LOG_ERR;
    }
    if (upper.find("WARNING") != std::string::npos) {
        return LOG_WARNING;
    }
    return LOG_INFO;
}

void LinuxPlatform::logMessage(const std::string& message) {
    syslog(SyslogPriorityFor(message), "%s", message.c_str());
}

std::string LinuxPlatform::getHostname() {
    char hostname[1024];
    hostname[1023] = '\0';
    ::gethostname(hostname, 1023);
    return std::string(hostname);
}

std::string LinuxPlatform::getLoggedInUser() {
    // `who` filters on tty/pts naming, but graphical sessions (X via a
    // display manager, Wayland seats) often show up with a tty field like
    // ":0" instead of "tty*"/"pts/*", so the filter misses them and this
    // always returned "none" on graphical logins. loginctl reports the
    // session owner regardless of session type, so prefer that.
    //
    // After logout the display manager spawns a fresh greeter session
    // (Class=greeter, owned by gdm/lightdm/sddm etc). Just taking the
    // first session in the list picked up that service account instead
    // of "none", so filter to Class=user sessions only.
    std::string name = executeCommand(
        "for s in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do "
        "c=$(loginctl show-session \"$s\" -p Class --value 2>/dev/null); "
        "if [ \"$c\" = \"user\" ]; then loginctl show-session \"$s\" -p Name --value 2>/dev/null; break; fi; "
        "done"
    );
    name.erase(name.find_last_not_of("\n\r \t") + 1);
    if (!name.empty()) {
        return name;
    }

    const char* cmd = "who | awk '$2~/^tty|pts/ {print $1}' | sort -u | head -n 1";
    char buffer[128] = {0};
    std::string result = "none";

    FILE* pipe = popen(cmd, "r");
    if (!pipe) return "none";

    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result = std::string(buffer);
        result.erase(result.find_last_not_of("\n\r") + 1);
    }
    pclose(pipe);

    return result.empty() ? "none" : result;
}

#endif // __linux__
