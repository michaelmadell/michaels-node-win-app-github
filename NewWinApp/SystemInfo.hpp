#pragma once
#include <string>
#include <vector>
#include <memory>

struct NetworkInterface {
	std::string name;
	std::string mac_address;
	std::string ip_address;
	bool is_up;
	long speed_mbps;
	bool dhcp_enabled;
};

class SystemMonitor {
public:
	virtual ~SystemMonitor() = default;

	// Hardware Stats
	virtual double getCpuUsage() = 0;
	virtual double getRamUsage() = 0;

	// OS Context
	virtual std::string getOsName() = 0;
	virtual std::string getHostname() = 0;
	virtual std::string getCurrentUser() = 0;
	virtual int getSessionState() = 0;

	// Network
	virtual std::vector<NetworkInterface> getFilteredInterfaces(const std::vector<std::string>& mac_prefixes) = 0;

	// Static Factory
	static std::unique_ptr<SystemMonitor> Create();
};