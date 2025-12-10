#ifdef _WIN32
#include "winsock2.h"
#include <netioapi.h> // Ensure this is included before using MIB_IF_ROW2
#include <windows.h>
#include "SystemInfo.hpp"
#include <iphlpapi.h>
#include <Pdh.h>
#include <lmcons.h>
#include <wtsapi32.h>
#include <iostream>
#include <algorithm>
#include <ws2tcpip.h>
#include <cstring>

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Wtsapi32.lib")

class WindowsMonitor : public SystemMonitor {
	PDH_HQUERY cpuQuery;
	PDH_HCOUNTER cpuTotal;

public:
	WindowsMonitor() {
		if (PdhOpenQuery(NULL, 0, &cpuQuery) == ERROR_SUCCESS) {
			PdhAddEnglishCounter(cpuQuery, L"\\Processor(_Total)\\% Processor Time", 0, &cpuTotal);
			PdhCollectQueryData(cpuQuery);
		}
	}

	~WindowsMonitor() {
		PdhCloseQuery(cpuQuery);
	}

	double getCpuUsage() override {
		PDH_FMT_COUNTERVALUE counterVal;
		PdhCollectQueryData(cpuQuery);
		PdhGetFormattedCounterValue(cpuTotal, PDH_FMT_DOUBLE, NULL, &counterVal);
		return counterVal.doubleValue;
	}

	double getRamUsage() override {
		MEMORYSTATUSEX memInfo;
		memInfo.dwLength = sizeof(MEMORYSTATUSEX);
		GlobalMemoryStatusEx(&memInfo);
		DWORDLONG totalPhysMem = memInfo.ullTotalPhys;
		DWORDLONG physMemUsed = memInfo.ullTotalPhys - memInfo.ullAvailPhys;
		return (double)physMemUsed / totalPhysMem * 100.0;
	}

	std::string getOsName() override {
		const char* subKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
		std::string product;

		HKEY hKey = nullptr;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
			char buf[256] = { 0 };
			DWORD bufSize = static_cast<DWORD>(sizeof(buf));
			if (RegQueryValueExA(hKey, "ProductName", nullptr, nullptr, reinterpret_cast<LPBYTE>(buf), &bufSize) == ERROR_SUCCESS) {
				product = buf;
			}

			char buildBuf[64] = { 0 };
			DWORD buildSize = static_cast<DWORD>(sizeof(buildBuf));
			if (RegQueryValueExA(hKey, "DisplayVersion", nullptr, nullptr, reinterpret_cast<LPBYTE>(buildBuf), &buildSize) != ERROR_SUCCESS) {
				buildSize = static_cast<DWORD>(sizeof(buildBuf));
				if (RegQueryValueExA(hKey, "CurrentBuildNumber", nullptr, nullptr, reinterpret_cast<LPBYTE>(buildBuf), &buildSize) != ERROR_SUCCESS) {
					buildBuf[0] = '\0';
				}
			}

			if (product.empty()) product = "Windows (Unknown)";
			if (buildBuf[0] != '\0') {
				product += " (";
				product += buildBuf;
				product += ")";
			}

			RegCloseKey(hKey);
		}
		else {
			product = "Windows (Unknown)";
		}

		return product;
	}

	std::string getHostname() override {
		char buffer[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD size = sizeof(buffer);
		if (GetComputerNameA(buffer, &size)) return std::string(buffer);
		return "UNKNOWN";
	}

	std::string getCurrentUser() override {
		char* pUserName = nullptr;
		DWORD bytesReturned;
		if (WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSUserName, &pUserName, &bytesReturned)) {
			std::string user(pUserName);
			WTSFreeMemory(pUserName);
			return user;
		}
		return "No User";
	}

	int getSessionState() override {
		WTS_CONNECTSTATE_CLASS* pState = nullptr;
		DWORD bytesReturned;
		if (WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSSessionInfo, (LPSTR*)&pState, &bytesReturned)) {
			int state = (int)*pState;
			WTSFreeMemory(pState);
			return state;
		}
		return -1;
	}

	std::vector<NetworkInterface> getFilteredInterfaces(const std::vector<std::string>& mac_prefixes) override {
		std::vector<NetworkInterface> result;
		ULONG outBufLen = 15000;
		PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);

		if (pAddresses == nullptr) return result;

		if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
			free(pAddresses);
			pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
			if (pAddresses == nullptr) return result;
		}

		if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen) == NO_ERROR) {
			PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
			while (pCurrAddresses) {
				if (pCurrAddresses->PhysicalAddressLength >= 6) {
					char macStr[32];
					sprintf_s(macStr, "%02X-%02X-%02X-%02X-%02X-%02X",
						pCurrAddresses->PhysicalAddress[0], pCurrAddresses->PhysicalAddress[1],
						pCurrAddresses->PhysicalAddress[2], pCurrAddresses->PhysicalAddress[3],
						pCurrAddresses->PhysicalAddress[4], pCurrAddresses->PhysicalAddress[5]);

					std::string sMac(macStr);

					bool match = false;
					for (const auto& prefix : mac_prefixes) {
						if (sMac.find(prefix) == 0) match = true;
					}

					if (match) {
						NetworkInterface ni;

						if (pCurrAddresses->FriendlyName != nullptr) {
							char nameBuff[256];
							size_t convertedChars = 0;
							// Use _TRUNCATE to prevent crash if string > 256
							wcstombs_s(&convertedChars, nameBuff, sizeof(nameBuff), pCurrAddresses->FriendlyName, _TRUNCATE);
							ni.name = nameBuff;
						}
						else {
							ni.name = "Unknown Adapter";
						}

						ni.mac_address = sMac;
						ni.is_up = (pCurrAddresses->OperStatus == IfOperStatusUp);

						ni.speed_mbps = 0;
						MIB_IF_ROW2 row;
						std::memset(&row, 0, sizeof(row));
						row.InterfaceIndex = pCurrAddresses->IfIndex;
						if (GetIfEntry2(&row) == NO_ERROR) {
							unsigned long long link_bps = (row.TransmitLinkSpeed || row.ReceiveLinkSpeed)
								? max(row.TransmitLinkSpeed, row.ReceiveLinkSpeed)
								: 0;
							if (link_bps) {
								ni.speed_mbps = static_cast<int>(link_bps / 1000000ULL);
							}
						}
						else {
							ni.speed_mbps = 0;
						}

						ni.dhcp_enabled = (pCurrAddresses->DdnsEnabled);

						PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
						if (pUnicast) {
							char ipStr[INET_ADDRSTRLEN];
							sockaddr_in* sa = (sockaddr_in*)pUnicast->Address.lpSockaddr;
							if (sa) {
								inet_ntop(AF_INET, &(sa->sin_addr), ipStr, INET_ADDRSTRLEN);
								ni.ip_address = ipStr;
							}
						}

						result.push_back(ni);
					}
				}
				pCurrAddresses = pCurrAddresses->Next;
			}
		}
		free(pAddresses);
		return result;
	}
};

std::unique_ptr<SystemMonitor> SystemMonitor::Create() {
	return std::make_unique<WindowsMonitor>();
}

#endif