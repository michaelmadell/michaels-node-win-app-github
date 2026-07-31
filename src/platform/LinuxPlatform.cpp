#ifdef __linux__
#include "../core/Platform.h"
#include <iostream>
#include <fstream>
#include <memory>
#include <algorithm>
#include <vector>
#include <map>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <thread>
#include <stdexcept>
#include <cmath>
#include <chrono>
#include <cctype>

// Linux Headers
#include <atomic>
#include <csignal>
#include <unistd.h>
#include <sys/stat.h>
#include <syslog.h>
#include <dbus/dbus.h>

// Headers for network interfaces
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netpacket/packet.h> // For MAC addresses
#include <net/if.h>           // For interface flags

#include <sys/utsname.h>
#include <sys/statvfs.h>
#include <utmp.h>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <limits>

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

void getCpuTimes(unsigned long long& total_time, unsigned long long& idle_time) {
    total_time = 0;
    idle_time = 0;
    std::ifstream file("/proc/stat");
    std::string line;
    if (std::getline(file, line)) {
        if (line.substr(0, 3) == "cpu") {
            unsigned long long user, nice, system, iowait, irq, softirq, steal, guest;
            std::stringstream ss(line.substr(4));
            if (ss >> user >> nice >> system >> idle_time >> iowait >> irq >> softirq >> steal >> guest) {
                total_time = user + nice + system + idle_time + iowait + irq + softirq + steal + guest;
            }
        }
    }
}

unsigned long long getTcpValue(int index) {
    std::string cmd = "cat /proc/net/snmp | grep -A 1 'Tcp:' | tail -n 1 | awk '{print $" + std::to_string(index) + "}' 2>/dev/null";
    std::string result = executeCommand(cmd);

    unsigned long long value = 0;
    try {
        if (!result.empty()) {
            value = std::stoull(result);
        }
    } catch (const std::exception& e) {
        // Handle any conversion errors if necessary
        syslog(LOG_ERR, "Error converting TCP value: %s", e.what());
    }
    return value;
}

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

class LinuxPlatform;
static LinuxPlatform* g_linux_instance = nullptr;
extern std::atomic<bool> g_terminate;
static SessionStateCallback g_session_callback;

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

void signal_handler(int signum) {
    g_terminate = true;
}

class LinuxPlatform : public Platform {
public:
    LinuxPlatform() { 
        g_linux_instance = this;
        getCpuTimes(m_prev_total_time, m_prev_idle_time);
        updatePdhMetrics();
    }
    ~LinuxPlatform() = default;

    // --- Core Platform Methods (Already Implemented Down Below) ---
    std::vector<NetworkInterface> getNetworkInterfaces() override;
    std::string getHostname() override;
    std::string getCurrentSessionState() override;
    std::string getLoggedInUser() override;
    std::string getOsVersion() override;
    std::string getOsBuild() override;
    void logMessage(const std::string& message) override;

    // --- Performance Metrics (Need Stubs or Linux Implementation) ---
    int getCpuUsagePercent() override;
    int getRamUsagePercent() override;
    std::string getFreeDiskSpaceGB(const std::string& drivePath) override;
    std::string getWindowsUpdateState() override;
    float getDiskQueueLength() override;
    float getNetworkRetransRate() override;
    std::string getSystemUptime() override;
    void updatePdhMetrics() override; // Windows PDH stub

    // --- GPU/Process Methods (Need Stubs) ---
    std::string getGpuDriverInfo() override;
    float getGpuUsagePercent() override;
    std::string getHighRamProcesses() override;
    
    // --- Utility Methods (Need Stubs or Implementation) ---
    void showMessageDialog(const std::string& title, const std::string& message) override;
    void shutdownSystem() override;

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
};

std::unique_ptr<Platform> createPlatform() {
    return std::make_unique<LinuxPlatform>();
}

int LinuxPlatform::run(
    int argc, char* argv[],
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

std::string LinuxPlatform::getSystemUptime() {
    std::ifstream file("/proc/uptime");
    double uptime_seconds;
    if (file >> uptime_seconds) {
        long long seconds = (long long)uptime_seconds;
        long long minutes = seconds / 60;
        long long hours = minutes / 60;
        long long days = hours / 24;

        seconds %= 60;
        minutes %= 60;
        hours %= 24;

        std::stringstream ss;
        ss << days << "d "
           << std::setw(2) << std::setfill('0') << hours << "h "
           << std::setw(2) << std::setfill('0') << minutes << "m "
           << std::setw(2) << std::setfill('0') << seconds << "s";
        return ss.str();
    }
    return "Unknown";
}

int LinuxPlatform::getCpuUsagePercent() {
    unsigned long long total_time, idle_time;
    getCpuTimes(total_time, idle_time);

    unsigned long long total_diff = total_time - m_prev_total_time;
    unsigned long long idle_diff = idle_time - m_prev_idle_time;

    m_prev_total_time = total_time;
    m_prev_idle_time = idle_time;

    if (total_diff == 0) return 0;

    int usage = static_cast<int>(std::round((1.0 - (double)idle_diff / total_diff) * 100.0));
    return std::max(0, std::min(100, usage));
}

int LinuxPlatform::getRamUsagePercent() {
    long long total_mem = 0;
    long long free_mem = 0;

    std::ifstream file("/proc/meminfo");
    std::string line;

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string key;
        long long value;
        std::string unit;

        if (ss >> key >> value >> unit) {
            if (key == "MemTotal:") {
                total_mem = value;
            } else if (key == "MemAvailable:") {
                free_mem = value;
            }
        }
    }
    if (total_mem > 0) {
        long long used_mem = total_mem - free_mem;
        int usage_percent = static_cast<int>(std::round((double)used_mem / total_mem * 100.0));
        return std::max(0, std::min(100, usage_percent));
    }
    return 0;
}

std::string LinuxPlatform::getFreeDiskSpaceGB(const std::string& drivePath) {
    struct statvfs vfs;
    // Use the root directory if drivePath is empty or irrelevant (like a Windows drive letter)
    std::string path = (drivePath.empty() || (drivePath.size() == 2 && drivePath[1] == ':')) ? "/" : drivePath;
    
    if (statvfs(path.c_str(), &vfs) != 0) {
        return "Error";
    }

    // Calculation: (Free blocks available to non-super user) * (Fundamental block size)
    unsigned long long free_bytes = (unsigned long long)vfs.f_bavail * vfs.f_frsize;
    
    // Convert bytes to GB and format to 1 decimal place
    double freeGB = (double)free_bytes / (1024.0 * 1024.0 * 1024.0);
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << freeGB;
    return ss.str();
}

float LinuxPlatform::getDiskQueueLength() {
    // Sum the "in_flight" (field 12) column of /proc/diskstats across whole-disk
    // block devices only (skip partitions and loop/ram devices) as an analog to
    // Windows' "Avg. Disk Queue Length" counter.
    std::ifstream file("/proc/diskstats");
    std::string line;
    float total_in_flight = 0.0f;

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string major, minor, devName;
        unsigned long long fields[10] = {0};

        ss >> major >> minor >> devName;
        for (int i = 0; i < 10; i++) {
            if (!(ss >> fields[i])) break;
        }

        if (devName.rfind("loop", 0) == 0 || devName.rfind("ram", 0) == 0) {
            continue;
        }

        // Skip partitions: sdXN, vdXN, hdXN have a trailing digit after the
        // letters; nvme/mmcblk whole-disks already end in a digit, so only
        // skip those with a partition suffix ("p<N>" or "n<N>p<N>").
        bool isPartition = false;
        if (devName.rfind("nvme", 0) == 0 || devName.rfind("mmcblk", 0) == 0) {
            isPartition = (devName.find('p', devName.find_first_of("0123456789")) != std::string::npos);
        } else {
            isPartition = !devName.empty() && std::isdigit(static_cast<unsigned char>(devName.back()));
        }
        if (isPartition) {
            continue;
        }

        // fields[8] is in_flight (the 12th whitespace-separated field overall:
        // major, minor, name, then 9 read/write stat fields before in_flight).
        total_in_flight += (float)fields[8];
    }

    return total_in_flight;
}

void LinuxPlatform::updatePdhMetrics() {
    m_prev_tcp_out = getTcpValue(11);
    m_prev_tcp_retrans = getTcpValue(12);
}

float LinuxPlatform::getNetworkRetransRate() {
    unsigned long long current_tcp_out = getTcpValue(11);
    unsigned long long current_tcp_retrans = getTcpValue(12);

    unsigned long long out_diff = current_tcp_out - m_prev_tcp_out;
    unsigned long long retrans_diff = current_tcp_retrans - m_prev_tcp_retrans;

    if (out_diff == 0 || out_diff < retrans_diff) {
        return 0.0f;
    }

    float retrans_rate = (float)retrans_diff / (float)out_diff * 100.0f;
    return retrans_rate;
}

std::string LinuxPlatform::getGpuDriverInfo() {
    // 1. Try to get NVIDIA dedicated GPU driver info (relies on nvidia-smi being installed)
    std::string driver_info = executeCommand("nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null");
    if (!driver_info.empty()) {
        return "NVIDIA Driver: " + driver_info;
    }

    // 2. Check for Intel Integrated Graphics using lsmod (more fundamental than lspci)
    std::string i915_module = executeCommand("lsmod | grep i915");
    if (!i915_module.empty()) {
        // Module is loaded, try to get the driver version
        std::string i915_version = executeCommand("modinfo i915 | grep -E '^version:' | awk '{print $2}'");
        if (!i915_version.empty()) {
            return "Intel Integrated Graphics (i915 Kernel Driver v" + i915_version + ")";
        }
        return "Intel Integrated Graphics Detected (Driver info N/A)";
    }
    
    // 3. Check for AMD
    std::string amdgpu_module = executeCommand("lsmod | grep amdgpu");
    if (!amdgpu_module.empty()) {
         return "AMD/Radeon GPU Detected (amdgpu Kernel Driver)";
    }


    return "Unknown/Unsupported GPU Driver";
}

float LinuxPlatform::getGpuUsagePercent() {
    // 1. Query NVIDIA GPU usage
    std::string usage_str = executeCommand(
        "nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>/dev/null | awk '{sum+=$1} END {print sum/NR}'"
    );

    if (!usage_str.empty()) {
        try {
            return std::stof(usage_str);
        } catch (...) {
            return 0.0f;
        }
    }

    // 2. AMD: amdgpu exposes a direct busy-percent sysfs attribute.
    std::string amdgpu_module = executeCommand("lsmod | grep amdgpu");
    if (!amdgpu_module.empty()) {
        std::string busy = executeCommand(
            "cat /sys/class/drm/card*/device/gpu_busy_percent 2>/dev/null | head -n 1");
        if (!busy.empty()) {
            try {
                return std::stof(busy);
            } catch (...) {
                return 0.0f;
            }
        }
    }

    // 3. Intel integrated graphics: query via intel_gpu_top (igt-gpu-tools, a required
    // package for the .deb build). Capture one JSON sample and read the Render/3D engine
    // busy percentage.
    std::string intel_busy = executeCommand(
        "timeout 2 intel_gpu_top -J -s 1000 -o - 2>/dev/null "
        "| grep -A3 '\"Render/3D' | grep -m1 '\"busy\"' | grep -oE '[0-9]+\\.?[0-9]*'");
    if (!intel_busy.empty()) {
        try {
            return std::stof(intel_busy);
        } catch (...) {
            return 0.0f;
        }
    }

    logMessage("GPU usage (percent) requested. Returning 0.0f: no NVIDIA/AMD/Intel usage source available.");
    return 0.0f;
}
std::string LinuxPlatform::getHighRamProcesses() {
    std::string cmd = "ps ax --sort=-rss -o pid,user,rss,comm --no-headers | head -n 5";
    std::string result = executeCommand(cmd);

    if (result.empty()) {
        return "None or Command Failed";
    }

    // Replace newlines with a separator for better JSON/String transport
    std::replace(result.begin(), result.end(), '\n', '|'); 
    return result;
}

void LinuxPlatform::showMessageDialog(const std::string& title, const std::string& message) {
    // Placeholder implementation
    logMessage("ShowMessageDialog called with title: " + title + " and message: " + message);
}

std::string LinuxPlatform::getWindowsUpdateState() {
    const char* cmd = "apt list --upgradable 2>/dev/null | grep -c 'upgradable'";
    char buffer[128] = {0};
    int package_count = 0;

    FILE* pipe = popen(cmd, "r");
    if (pipe) {
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            try {
            package_count = std::stoi(buffer);
            } catch (const std::invalid_argument& e) {
                logMessage("Invalid argument when parsing package count: " + std::string(e.what()));
            } catch (const std::out_of_range& e) {
                logMessage("Out of range error when parsing package count: " + std::string(e.what()));
            }
        }
        pclose(pipe);
    }

    if (package_count > 0) {
        return "Pending Upgrades (" + std::to_string(package_count) + ")";
    }

    std::ifstream reboot_file("/var/run/reboot-required");
    if (reboot_file.good()) {
        return "Reboot Required";
    }

    return "Up to Date";
}

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

void LinuxPlatform::shutdownSystem() {
    logMessage("Shutdown requested via LinuxPlatform::shutdownSystem().");
    executeCommand("systemctl poweroff");
}

#endif
