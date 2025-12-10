#ifndef _WIN32
#include "SystemInfo.hpp"
#include <sys/sysinfo>
#include <sys/utsname>
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
		long long totalPhysMem = memInfo.totalRam;
		totalPhysMem *= memInfo.mem_unit;
		long long physMemUsed = memInfo.totalRam - memInfo.freeram;
		physMemUsed *= memInfo.mem_unit;
		return (double)physMemUsed / totalPhysMem * 100;
	}

	std::string getOsName() override {
		struct utsname buffer;
		if (uname(&buffer) != 0) return "Linux Unknown";
		return std::string(buffer.sysname) + " " + std::string(buffer.release);
	}

	std::string getHostname() override {
		char buffer[256];
		if (gethostname(buffer, 256) == 0) return std::string(buffer);
		return "UNKNOWN";
	}

	std::string getCurrentUser() override {
		return "root (service)";
	}

	int getSessionState() override {
		return 1;
	}

	std::vector<NetworkInterface> getFilteredInterfaces(const std::vector<std::string>& mac_prefixes) override {
		std::vector<NetworkInterface> result;
		struct ifaddrs* ifaddr, * ifa;

		if (getifaddrs(&ifaddr) == -1) return result;

		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr = NULL) continue;
			if (ifa->ifa_addr->sa_family != AF_INET) continue;

			std::string ifaceName(ifa->ifa_name);

			std::ifstream macFile("/sys/class/net/" + ifaceName + "/address");
			std::string macStr;
			if (std::getline(macFile, macStr)) {
				std::replace(macStr.begin(), macStr.end(), ':'. '-');
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