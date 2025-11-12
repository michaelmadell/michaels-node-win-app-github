#ifdef __linux__
#include "Platform.h"
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

// Linux Headers
#include <atomic>
#include <csignal>
#include <unistd.h>
#include <termios.h> // For serial port configuration
#include <fcntl.h>   // For file control options
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
    // std::string connectionName;
    // char buffer[256];

    // // Step 1: Find the active connection name for the given device interface
    // std::string cmd1 = "nmcli -t -f GENERAL.CONNECTION dev show " + interfaceName;
    // FILE* pipe1 = popen(cmd1.c_str(), "r");
    // if (!pipe1) return "unknown";
    
    // if (fgets(buffer, sizeof(buffer), pipe1) != nullptr) {
    //     connectionName = std::string(buffer);
    //     // Remove trailing newline
    //     connectionName.erase(connectionName.find_last_not_of("\n\r") + 1);
    //     // The output is "GENERAL.CONNECTION:<name>", so we find the colon and take the rest
    //     size_t colon_pos = connectionName.find(':');
    //     if (colon_pos != std::string::npos) {
    //         connectionName = connectionName.substr(colon_pos + 1);
    //     }
    // }
    // pclose(pipe1);

    // if (connectionName.empty()) {
    //     return "unknown";
    // }

    // // Step 2: Get the ipv4.method for that connection
    // std::string result = "unknown";
    // std::string cmd2 = "nmcli -t -f ipv4.method con show \"" + connectionName + "\"";
    // FILE* pipe2 = popen(cmd2.c_str(), "r");
    // if (!pipe2) return "unknown";

    // if (fgets(buffer, sizeof(buffer), pipe2) != nullptr) {
    //     std::string line(buffer);
    //     if (line.find("auto") != std::string::npos) {
    //         result = "dhcp";
    //     } else if (line.find("manual") != std::string::npos) {
    //         result = "static";
    //     }
    // }
    // pclose(pipe2);
    
    // return result;

    return "unknown"; // Placeholder until a reliable method is implemented
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

    const char* match_rule = "type='signal',interface='org.freedesktop.login1.Session',member='Unlock'";
    const char* match_rule2 = "type='signal',interface='org.freedesktop.login1.Session',member='Lock'";
    dbus_bus_add_match(conn, match_rule, &err);
    dbus_bus_add_match(conn, match_rule2, &err);
    
    syslog(LOG_INFO, "D-Bus thread started and listening for session signals.");

    while (true) {
        dbus_connection_read_write_dispatch(conn, -1);
        DBusMessage* msg = dbus_connection_pop_message(conn);

        if (msg == NULL) continue;

        if (dbus_message_is_signal(msg, "org.freedesktop.login1.Session", "Lock")) {
            if (g_session_callback) g_session_callback("7");
        } else if (dbus_message_is_signal(msg, "org.freedesktop.login1.Session", "Unlock")){
            if (g_session_callback) g_session_callback("8");
        }

        dbus_message_unref(msg);
    }
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
    std::string getLoggedInUser() override;
    std::string getOsVersion() override;
    std::string getOsBuild() override;
    bool openSerialPort(const std::string& portName, int baudrate) override;
    void closeSerialPort() override;
    bool writeSerial(const std::string& data) override;
    void logMessage(const std::string& message) override;

    // --- Performance Metrics (Need Stubs or Linux Implementation) ---
    // Note: readSerial was missing a declaration too, but is implemented below.
    bool readSerial(std::string &readData) override; 
    
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

    int run(
        int argc, char* argv[],
        VoidCallback on_start,
        VoidCallback on_stop,
        PowerStateCallback power_cb,
        SessionStateCallback session_cb
    ) override;

private:
    int serial_fd = -1;
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
    VoidCallback on_stop,
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

    logMessage("Termination signal recieved. Shutting Down.");
    if (power_cb) {
        power_cb("controlShutdown");
    }

    if (on_stop) {
        on_stop();
    }
    std::cout << "[DEBUG] Application terminating cleanly." << std::endl;
    closelog();
    return 0;
}

bool LinuxPlatform::openSerialPort(const std::string& portName, int baudrate) {
    serial_fd = open(portName.c_str(), O_RDWR | O_NOCTTY | O_SYNC);
    if (serial_fd < 0) {
        logMessage("Error opening serial port " + portName);
        return false;
    }

    struct termios tty;
    if (tcgetattr(serial_fd, &tty) != 0) {
        logMessage("Error getting termios attributes");
        return false;
    }

    // Set Baud Rate to 115200
    cfsetospeed(&tty, B115200);
    cfsetispeed(&tty, B115200);

    tty.c_cflag &= ~PARENB;         // No Parity
    tty.c_cflag &= ~CSTOPB;         // 1 stop bit
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tty.c_cflag &= ~CRTSCTS;        // no hardware flow control
    tty.c_cflag |= CREAD | CLOCAL;  // Enable receiver, ignore modem control lines

    // Disable software flow control
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);

    // Set raw input and output
    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_oflag &= ~OPOST;

    // --- CRITICAL FIX: Set VMIN=0 and VTIME=0 for NON-BLOCKING read ---
    tty.c_cc[VMIN] = 0; 
    tty.c_cc[VTIME] = 0; 

    if (tcsetattr(serial_fd, TCSANOW, &tty) != 0) {
        logMessage("Error setting termios attributes.");
        return false;
    }

    return true;
}

void LinuxPlatform::closeSerialPort() {
    if (serial_fd >= 0) {
        close(serial_fd);
        serial_fd = -1;
    }
}

bool LinuxPlatform::writeSerial(const std::string& data) {
    if (serial_fd < 0) {
        // Log that the port isn't even open
        logMessage("[writeSerial] Error: Serial port is not open.");
        return false;
    }

    // Log what we are about to write
    logMessage("[writeSerial] Attempting to write: " + data);
    
    ssize_t bytes_written = write(serial_fd, data.c_str(), data.length());

    if (bytes_written < 0) {
        // An error occurred
        logMessage("[writeSerial] Error on write(): " + std::string(strerror(errno)));
        return false;
    }

    // Log the result
    logMessage("[writeSerial] write() returned: " + std::to_string(bytes_written) + " bytes written.");

    return bytes_written == (ssize_t)data.length();
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

        if ( (ifa->ifa_flags & IFF_LOOPBACK) ) {
            continue;
        }

        if (interfaces_map.find(name) == interfaces_map.end()) {
            interfaces_map[name].name = name;
            interfaces_map[name].linkStatus = "up";
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
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)s->sll_addr[i];
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
        result_vector.push_back(iface);
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

bool LinuxPlatform::readSerial(std::string &readData) {
    if (serial_fd < 0) return false;
    char buffer[256];
    ssize_t bytes_read = read(serial_fd, buffer, sizeof(buffer) - 1); 
    if (bytes_read > 0) {
        readData.append(buffer, bytes_read);
        return true;
    }
    return false;
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
    // Placeholder implementation
    return 0.0f;
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

    // 2. Fallback for Intel Integrated Graphics (guaranteed present, but usage is complex to track)
    // Returning 0.0f is a safe way to prevent crashes when the information is unavailable through simple means.
    logMessage("GPU usage (percent) requested. Returning 0.0f as integrated Intel graphics usage is not tracked via generic commands.");
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

void LinuxPlatform::logMessage(const std::string& message) {
    syslog(LOG_INFO, "%s", message.c_str());
}

std::string LinuxPlatform::getHostname() {
    char hostname[1024];
    hostname[1023] = '\0';
    ::gethostname(hostname, 1023);
    return std::string(hostname);
}

std::string LinuxPlatform::getLoggedInUser() {
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

#endif
