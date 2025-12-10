#ifndef _WIN32
#include "SystemInfo.hpp"
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <cstring>
#include <vector>
#include <iostream>
#include <algorithm>

class LinuxMonitor : public SystemMonitor {
	unsigned long long lastTotalUser, lastTotalUserLow, lastTotalSys, lastTotalIdle;

	void getCpuData(unsigned long long& totalUser, unsigned long long& totalUserLow,
					unsigned long long& totalSys, unsigned long long& totalIdle) {
		std::ifstream file("/proc/stat");
		std::string line;
		if (std::getline(file, line)) {
			std::istringstream iss(line);
			std::string cpu;
			iss >> cpu >> totalUser >> totalUserLow >> totalSys >> totalIdle;
		}
	}

public:
	LinuxMonitor() {
		getCpuData(lastTotalUser, lastTotalUserLow, lastTotalSys, lastTotalIdle);
	}

	double getCpuUsage() override {
		unsigned long long totalUser, totalUserLow, totalSys, totalIdle;
		getCpuData(totalUser, totalUserLow, totalSys, totalIdle);

		unsigned long long total = (totalUser - lastTotalUser) + (totalUserLow - lastTotalUserLow) +
									(totalSys - lastTotalSys);
		unsigned long long percent = total;
		total += (totalIdle - lastTotalIdle);

		lastTotalUser = totalUser;
		lastTotalUserLow = totalUserLow;
		lastTotalSys = totalSys;
		lastTotalIdle = totalIdle;

		return (total > 0) ? ((double)percent / total) * 100.0 : 0.0;
	}

	double getRamUsage() override {
		struct sysinfo memInfo;
		sysinfo(&memInfo);
		long long totalPhysMem = memInfo.totalram;
		totalPhysMem *= memInfo.mem_unit;
		long long physMemUsed = memInfo.totalram - memInfo.freeram;
		physMemUsed *= memInfo.mem_unit;
		return (double)physMemUsed / totalPhysMem * 100;
	}

	std::string getOsName() override {
		struct utsname buffer;
		if (uname(&buffer) != 0) return "Linux Unknown";
		
		// Try to get distribution name from /etc/os-release
		std::ifstream osRelease("/etc/os-release");
		std::string distroName;
		std::string distroVersion;
		std::string line;
		
		if (osRelease.is_open()) {
			while (std::getline(osRelease, line)) {
				if (line.find("PRETTY_NAME=") == 0) {
					distroName = line.substr(12);
					// Remove quotes
					if (!distroName.empty() && distroName.front() == '"') distroName = distroName.substr(1);
					if (!distroName.empty() && distroName.back() == '"') distroName.pop_back();
					break;
				}
			}
		}
		
		if (!distroName.empty()) {
			return distroName + " (Kernel " + std::string(buffer.release) + ")";
		}
		return std::string(buffer.sysname) + " " + std::string(buffer.release);
	}

	std::string getHostname() override {
		char buffer[256];
		if (gethostname(buffer, sizeof(buffer)) == 0) {
			buffer[sizeof(buffer) - 1] = '\0'; // Ensure null termination
			return std::string(buffer);
		}
		
		// Fallback: try reading /etc/hostname
		std::ifstream hostnameFile("/etc/hostname");
		if (hostnameFile.is_open()) {
			std::string hostname;
			if (std::getline(hostnameFile, hostname) && !hostname.empty()) {
				return hostname;
			}
		}
		
		return "UNKNOWN";
	}

	std::string getCurrentUser() override {
		// Try to get username from environment
		const char* user = getenv("USER");
		if (!user) user = getenv("LOGNAME");
		
		if (user) {
			return std::string(user);
		}
		
		// Fallback: get from uid
		uid_t uid = getuid();
		if (uid == 0) {
			return "root";
		}
		
		// Try to read from /etc/passwd
		std::ifstream passwd("/etc/passwd");
		if (passwd.is_open()) {
			std::string line;
			while (std::getline(passwd, line)) {
				std::istringstream iss(line);
				std::string username, x, uidStr;
				if (std::getline(iss, username, ':') && 
					std::getline(iss, x, ':') && 
					std::getline(iss, uidStr, ':')) {
					if (static_cast<uid_t>(std::stoi(uidStr)) == uid) {
						return username;
					}
				}
			}
		}
		
		return "unknown";
	}

	int getSessionState() override {
		// Check if X11 or Wayland display is available
		const char* display = getenv("DISPLAY");
		const char* waylandDisplay = getenv("WAYLAND_DISPLAY");
		
		if (display || waylandDisplay) {
			return 1; // Active session
		}
		
		// Check for systemd login sessions
		std::ifstream sessions("/proc/self/sessionid");
		if (sessions.is_open()) {
			int sessionId;
			sessions >> sessionId;
			if (sessionId > 0) {
				return 1; // Active session
			}
		}
		
		// Check if SSH session
		const char* sshConnection = getenv("SSH_CONNECTION");
		const char* sshClient = getenv("SSH_CLIENT");
		if (sshConnection || sshClient) {
			return 1; // Active remote session
		}
		
		// Check if running in a terminal
		if (isatty(STDIN_FILENO)) {
			return 1; // Active terminal session
		}
		
		return 0; // No active session (likely background service)
	}

	std::vector<NetworkInterface> getFilteredInterfaces(const std::vector<std::string>& mac_prefixes) override {
		std::vector<NetworkInterface> result;
		struct ifaddrs* ifaddr, * ifa;

		if (getifaddrs(&ifaddr) == -1) return result;

		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr == NULL) continue;
			if (ifa->ifa_addr->sa_family != AF_INET) continue;

			std::string ifaceName(ifa->ifa_name);

			std::ifstream macFile("/sys/class/net/" + ifaceName + "/address");
			std::string macStr;
			if (std::getline(macFile, macStr)) {
				std::replace(macStr.begin(), macStr.end(), ':', '-');
				std::string upperMac = macStr;
				std::transform(upperMac.begin(), upperMac.end(), upperMac.begin(), ::toupper);

				bool match = false;
				for (const auto& prefix : mac_prefixes) {
					if (upperMac.find(prefix) == 0) match = true;
				}

				if (match) {
					NetworkInterface ni;
					ni.name = ifaceName;
					ni.mac_address = upperMac;

					char ipStr[INET_ADDRSTRLEN];
					sockaddr_in* sa = (sockaddr_in*)ifa->ifa_addr;
					inet_ntop(AF_INET, &(sa->sin_addr), ipStr, INET_ADDRSTRLEN);
					ni.ip_address = ipStr;

					std::ifstream operFile("/sys/class/net/" + ifaceName + "/operstate");
					std::string state;
					std::getline(operFile, state);
					ni.is_up = (state == "up");
					ni.dhcp_enabled = false;
					ni.speed_mbps = 1000;

					result.push_back(ni);
				}
			}
		}
		freeifaddrs(ifaddr);
		return result;
	}
};

std::unique_ptr<SystemMonitor> SystemMonitor::Create() {
	return std::make_unique<LinuxMonitor>();
}

#endif