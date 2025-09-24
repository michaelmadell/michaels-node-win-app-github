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


std::string getDhcpStatus(const std::string& interfaceName) {
    std::string connectionName;
    char buffer[256];

    // Step 1: Find the active connection name for the given device interface
    std::string cmd1 = "nmcli -t -f GENERAL.CONNECTION dev show " + interfaceName;
    FILE* pipe1 = popen(cmd1.c_str(), "r");
    if (!pipe1) return "unknown";
    
    if (fgets(buffer, sizeof(buffer), pipe1) != nullptr) {
        connectionName = std::string(buffer);
        // Remove trailing newline
        connectionName.erase(connectionName.find_last_not_of("\n\r") + 1);
        // The output is "GENERAL.CONNECTION:<name>", so we find the colon and take the rest
        size_t colon_pos = connectionName.find(':');
        if (colon_pos != std::string::npos) {
            connectionName = connectionName.substr(colon_pos + 1);
        }
    }
    pclose(pipe1);

    if (connectionName.empty()) {
        return "unknown";
    }

    // Step 2: Get the ipv4.method for that connection
    std::string result = "unknown";
    std::string cmd2 = "nmcli -t -f ipv4.method con show \"" + connectionName + "\"";
    FILE* pipe2 = popen(cmd2.c_str(), "r");
    if (!pipe2) return "unknown";

    if (fgets(buffer, sizeof(buffer), pipe2) != nullptr) {
        std::string line(buffer);
        if (line.find("auto") != std::string::npos) {
            result = "dhcp";
        } else if (line.find("manual") != std::string::npos) {
            result = "static";
        }
    }
    pclose(pipe2);
    
    return result;
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
    LinuxPlatform() { g_linux_instance = this; }
    ~LinuxPlatform() = default;

    std::vector<NetworkInterface> getNetworkInterfaces() override;
    std::string getHostname() override;
    std::string getLoggedInUser() override;
    std::string getOsVersion() override;
    bool openSerialPort(const std::string& portName, int baudrate) override;
    void closeSerialPort() override;
    bool writeSerial(const std::string& data) override;
    void logMessage(const std::string& message) override;

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
    //pid_t pid = fork();
    //if (pid < 0) exit(EXIT_FAILURE);
    //if (pid > 0) exit(EXIT_SUCCESS); // Parent exits, leaving child in background
    //umask(0);
    //if (setsid() < 0) exit(EXIT_FAILURE);

    // --- ADD THIS BLOCK TO CREATE THE PID FILE ---
    //pid_t child_pid = getpid();
    //std::ofstream pid_file("/run/CoreStationHXAgent/CoreStationHXAgent.pid");
    //if (pid_file.is_open()) {
    //    pid_file << child_pid;
    //    pid_file.close();
    //} else {
    //    syslog(LOG_ERR, "Failed to create PID file");
    //    exit(EXIT_FAILURE);
    //}
    
    //close(STDIN_FILENO);
    //close(STDOUT_FILENO);
    //close(STDERR_FILENO);
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
    const char* cmd = "/usr/bin/loginctl list-sessions --no-legend | grep 'seat0' | head -n 1 | awk '{print $3}'";
    char buffer[128];
    std::string result = "none";

    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        logMessage("popen() failed for getLoggedInUser");
        return result;
    }

    std::string raw_output = "[no output]";
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        raw_output = std::string(buffer);
        result = raw_output;
        result.erase(result.find_last_not_of("\n\r") + 1);
    }
    logMessage("[getLoggedInUser] Raw loginctl output: " + raw_output);

    pclose(pipe);

    if (result.empty() || result == "[no output]") {
        return "none";
    }
    return result;
}

#endif
