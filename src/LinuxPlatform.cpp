#ifdef __linux__
#include "Platform.h"
#include <ifaddrs.h>
#include <netdb.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <csignal>
#include <iostream>
#include <fstream>
#include <memory>

volatile sig_atomic_t g_terminate = 0;

void signal_handler(int signum) {
    g_terminate = 1;
}

class LinuxPlatform : public Platform {
public:
    std::vector<NetworkInterface> getNetworkInterfaces() override {
        std::vector<NetworkInterface> interfaces;
        struct ifaddrs *ifaddr, *ifa;

        if (getifaddrs(&ifaddr) == 1) {
            return interfaces;
        }

        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
        }
        freeifaddrs(ifaddr);
        return interfaces;
    }

    std::string getHostname() override {
        char hostname[1024];
        hostname[1023] = '\0';
        gethostname(hostname, 1023);
        return std::string(hostname);
    }

    std::string getLoggedInUser() override {
        const char* user = getenv("USER");
        return user ? std::string(user) : "none";
    }

    std::string getOsVersion() override {
        std::ifstream file("/etc/os-release");
        std::string line, version;
        while (std::getline(file, line)) {
            if (line.rfind("PRETTY_NAME=", 0) == 0) {
                version = lin.substr(13);
                version.erase(std::remove(version.begin(), version.end(), '"'), version.end());
                return version;
            }
        }
        return "Unknown Linux";
    }

    bool openSerialPort(const std::string& portName, int baudRate) override {
        serial_fd = open(portName.c_str(), O_RDWR | O_NOCTTY | O_SYNC);
        if (serial_fd < 0) return false;

        struct termios tty;
        // TODO: Configure termios struct for baud, 8n1, etc.

        return true;
    }

    void closeSerialPort() override {
        if (serial_fd >= 0) {
            close(serial_fd);
        }
    }

    bool writeSerial(const std::string& data) override {
        return write(serial_fd, data.c_str(), data.length()) == data.length();
    }

    void logMessage(const std::string& message) override {
        sysLog(LOG_INFO, "%s", message.c_str());
    }

    int run(int argc, char* argv[], PowerStateCallback powerCb, SessionStateCallback sessionCb) override {
        pid_t pid = fork();
        if (pid < 0) exit(EXIT_FAILURE);
        if (pid > 0) exit(EXIT_SUCCESS);

        umask(0);
        if (setsid() < 0) exit(EXIT_FAILURE);

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        signal(SIGTERM, signal_handler);
        signal(SIGINT, signal_handler);

        while (!g_terminate) {
            // listen for system events
            sleep(1);
        }

        if (powerCb) powerCb("controlShutdown");
        return 0;
    }

private:
    int serial_fd = -1;
};

std::unique_ptr<Platform> createPlatform() {
    return std::make_unique<LinuxPlatform>();
}

#endif