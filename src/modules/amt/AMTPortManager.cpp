#include <winreg.h>
#include <thread>
#include <chrono>
#include <string>
#include <winerror.h>
#include <iostream>

#include "../../core/Platform.h"
#include "AMTPortManager.h"

extern std::unique_ptr<Platform> platform;

// Known AMT SOL serial device HWIDs under HKLM\SYSTEM\CurrentControlSet\Enum\PCI
static const wchar_t* kAMTDeviceHwids[] = {
    L"VEN_8086&DEV_7773&SUBSYS_72708086&REV_00",
    L"VEN_8086&DEV_7E73&SUBSYS_72708086&REV_20",
    nullptr
};


// Find the first AMT device full instance ID by enumerating PCI\Enum directly.
// Works regardless of whether the device is currently enabled or disabled.
static std::wstring GetAMTInstanceId() {
#ifdef _WIN32
    for (int i = 0; kAMTDeviceHwids[i] != nullptr; ++i) {
        std::wstring devKeyPath = std::wstring(L"SYSTEM\\CurrentControlSet\\Enum\\PCI\\") + kAMTDeviceHwids[i];
        HKEY hDevKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, devKeyPath.c_str(), 0, KEY_READ, &hDevKey) != ERROR_SUCCESS) {
            continue;
        }
        wchar_t instanceName[256];
        DWORD instanceNameSize = _countof(instanceName);
        if (RegEnumKeyExW(hDevKey, 0, instanceName, &instanceNameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            RegCloseKey(hDevKey);
            return std::wstring(L"PCI\\") + kAMTDeviceHwids[i] + L"\\" + instanceName;
        }
        RegCloseKey(hDevKey);
    }
    return L"";
    #endif
}

// Read the current COM port assignment for the AMT serial device from
// Device Parameters\PortName in the registry — avoids PowerShell round-trips
// and works correctly after a disable/enable cycle.
AMTPortInfo GetAMTComPort() {
#ifdef _WIN32
    for (int i = 0; kAMTDeviceHwids[i] != nullptr; ++i) {
        std::wstring devKeyPath = std::wstring(L"SYSTEM\\CurrentControlSet\\Enum\\PCI\\") + kAMTDeviceHwids[i];
        HKEY hDevKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, devKeyPath.c_str(), 0, KEY_READ, &hDevKey) != ERROR_SUCCESS) {
            continue;
        }
        DWORD index = 0;
        wchar_t instanceName[256];
        DWORD instanceNameSize = _countof(instanceName);
        while (RegEnumKeyExW(hDevKey, index, instanceName, &instanceNameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::wstring paramPath = devKeyPath + L"\\" + instanceName + L"\\Device Parameters";
            HKEY hParamKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paramPath.c_str(), 0, KEY_READ, &hParamKey) == ERROR_SUCCESS) {
                wchar_t portName[64] = {};
                DWORD portNameSize = sizeof(portName);
                if (RegQueryValueExW(hParamKey, L"PortName", nullptr, nullptr, (LPBYTE)portName, &portNameSize) == ERROR_SUCCESS) {
                    RegCloseKey(hParamKey);
                    RegCloseKey(hDevKey);
                    std::wstring fullId = std::wstring(L"PCI\\") + kAMTDeviceHwids[i] + L"\\" + instanceName;
                    return {std::wstring(portName), fullId};
                }
                RegCloseKey(hParamKey);
            }
            ++index;
            instanceNameSize = _countof(instanceName);
        }
        RegCloseKey(hDevKey);
    }
    return {L"", L""};
#endif
}

bool disableAMTComPort() {
#ifdef _WIN32
    std::wstring instanceId = GetAMTInstanceId();
    if (instanceId.empty()) {
        platform->logMessage("disableAMTComPort: AMT device not found in PCI enum.");
        return false;
    }

    std::string pshDisableCmd = "powershell -Command \"Disable-PnpDevice -InstanceId '" + std::string(instanceId.begin(), instanceId.end()) + "' -Confirm:0\"";
    int result = system(pshDisableCmd.c_str());
    if (result != 0) {
        std::cerr << "[ERROR] Failed to disable AMT Serial Port. Command: " << pshDisableCmd << std::endl;
        platform->logMessage("Failed to disable AMT Serial Port.");
        return false;
    }
    return true;
#endif
}

bool enableAMTComPort() {
#ifdef _WIN32
    std::wstring instanceId = GetAMTInstanceId();
    if (instanceId.empty()) {
        platform->logMessage("enableAMTComPort: AMT device not found in PCI enum.");
        return false;
    }

    std::string pshEnableCmd = "powershell -Command \"Enable-PnpDevice -InstanceId '" + std::string(instanceId.begin(), instanceId.end()) + "' -Confirm:0\"";
    int result = system(pshEnableCmd.c_str());
    if (result != 0) {
        std::cerr << "[ERROR] Failed to enable AMT Serial Port. Command: " << pshEnableCmd << std::endl;
        platform->logMessage("Failed to enable AMT Serial Port.");
        return false;
    }
    return true;
#endif

}

// Directly implements the PS COM port assignment script:
//   1. Reserves COM4 in the COM Name Arbiter (ComDB byte[0] |= 0x08)
//   2. Writes PortName=COM4 into Device Parameters for every AMT SOL instance
//   3. Writes FriendlyName on each instance key
//   4. Cycles the device (disable → enable) so the driver picks up the new PortName
bool reassignComPort() {
#ifdef _WIN32
    platform->logMessage("reassignComPort: Beginning COM4 assignment.");

    // --- Step 1: COM Name Arbiter — reserve COM4 ---
    // ComDB is a binary bitmask. COM N occupies bit (N-1) in byte floor((N-1)/8).
    // COM4 = bit index 3 → byte[0] bit 3 → mask 0x08
    {
        HKEY hArbiter = nullptr;
        const wchar_t* arbPath = L"SYSTEM\\CurrentControlSet\\Control\\COM Name Arbiter";
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, arbPath, 0, KEY_READ | KEY_WRITE, &hArbiter) == ERROR_SUCCESS) {
            BYTE comDb[8] = {};
            DWORD dbSize = sizeof(comDb);
            RegQueryValueExW(hArbiter, L"ComDB", nullptr, nullptr, comDb, &dbSize);
            if (!(comDb[0] & 0x08)) {
                comDb[0] |= 0x08;
                RegSetValueExW(hArbiter, L"ComDB", 0, REG_BINARY, comDb, sizeof(comDb));
                platform->logMessage("COM Name Arbiter: COM4 reserved.");
            } else {
                platform->logMessage("COM Name Arbiter: COM4 was already reserved.");
            }
            RegCloseKey(hArbiter);
        } else {
            platform->logMessage("WARNING: Could not open COM Name Arbiter — continuing anyway.");
        }
    }

    // --- Step 2: Write PortName and FriendlyName for all matching device instances ---
    const wchar_t* targetPort    = L"COM4";
    const wchar_t* friendlyName  = L"Intel(R) Active Management Technology - SOL (COM4)";
    bool anyDeviceFound = false;

    for (int i = 0; kAMTDeviceHwids[i] != nullptr; ++i) {
        std::wstring devKeyPath = std::wstring(L"SYSTEM\\CurrentControlSet\\Enum\\PCI\\") + kAMTDeviceHwids[i];
        HKEY hDevKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, devKeyPath.c_str(), 0, KEY_READ, &hDevKey) != ERROR_SUCCESS) {
            platform->logMessage("Device not present on this machine, skipping: " + std::string(devKeyPath.begin(), devKeyPath.end()));
            continue;
        }

        DWORD index = 0;
        wchar_t instanceName[256];
        DWORD instanceNameSize = _countof(instanceName);
        while (RegEnumKeyExW(hDevKey, index, instanceName, &instanceNameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            anyDeviceFound = true;
            std::wstring instancePath = devKeyPath + L"\\" + instanceName;

            // Set FriendlyName on the instance key
            HKEY hInstanceKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, instancePath.c_str(), 0, KEY_SET_VALUE, &hInstanceKey) == ERROR_SUCCESS) {
                RegSetValueExW(hInstanceKey, L"FriendlyName", 0, REG_SZ,
                    (LPBYTE)friendlyName,
                    (DWORD)((wcslen(friendlyName) + 1) * sizeof(wchar_t)));
                RegCloseKey(hInstanceKey);
            }

            // Create (if absent) or open Device Parameters and set PortName
            std::wstring paramPath = instancePath + L"\\Device Parameters";
            HKEY hParamKey = nullptr;
            DWORD disposition = 0;
            LONG ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, paramPath.c_str(), 0, nullptr,
                REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hParamKey, &disposition);
            if (ret == ERROR_SUCCESS) {
                ret = RegSetValueExW(hParamKey, L"PortName", 0, REG_SZ,
                    (LPBYTE)targetPort,
                    (DWORD)((wcslen(targetPort) + 1) * sizeof(wchar_t)));
                if (ret == ERROR_SUCCESS) {
                    platform->logMessage("Set PortName=COM4 for: " + std::string(instancePath.begin(), instancePath.end()));
                } else {
                    platform->logMessage("ERROR: Failed to write PortName for: " + std::string(instancePath.begin(), instancePath.end()));
                }
                RegCloseKey(hParamKey);
            } else {
                platform->logMessage("ERROR: Failed to open/create Device Parameters for: " + std::string(instancePath.begin(), instancePath.end()));
            }

            ++index;
            instanceNameSize = _countof(instanceName);
        }
        RegCloseKey(hDevKey);
    }

    if (!anyDeviceFound) {
        platform->logMessage("reassignComPort: No AMT device instances found in PCI enum.");
        return false;
    }

    // --- Step 3: Cycle the device so the serial driver reloads with the new PortName ---
    if (!disableAMTComPort()) {
        platform->logMessage("reassignComPort: Failed to disable device for port cycle.");
        return false;
    }
    if (!enableAMTComPort()) {
        platform->logMessage("reassignComPort: Failed to re-enable device after port cycle.");
        return false;
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));

    // --- Step 4: Verify ---
    AMTPortInfo newInfo = GetAMTComPort();
    if (newInfo.comPort.empty()) {
        platform->logMessage("reassignComPort: Device not found after cycle — cannot verify assignment.");
        return false;
    }
    if (newInfo.comPort == L"COM3") {
        platform->logMessage("reassignComPort: Device is still on COM3 after reassignment attempt.");
        return false;
    }

    platform->logMessage("reassignComPort: Successfully assigned AMT Serial Port to "
        + std::string(newInfo.comPort.begin(), newInfo.comPort.end()));
    return true;
#endif
}