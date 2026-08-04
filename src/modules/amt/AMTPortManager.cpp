#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winreg.h>
#include <winerror.h>
#endif

#include <thread>
#include <chrono>
#include <string>
#include <vector>
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

    return L"";
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

    return {L"", L""};
}

#ifdef _WIN32
// Doubling an embedded ' is PowerShell's own escape for a literal quote
// inside a single-quoted string, so this prevents instanceId from breaking
// out of the -InstanceId argument no matter what it contains.
static std::wstring EscapePowerShellSingleQuoted(const std::wstring& input) {
    std::wstring result;
    result.reserve(input.size());
    for (wchar_t c : input) {
        if (c == L'\'') {
            result += L"''";
        } else {
            result += c;
        }
    }
    return result;
}

// Launches powershell.exe directly via CreateProcessW (no cmd.exe / system()
// in the path), so shell metacharacters in the script are never reinterpreted
// by an intermediate shell.
static bool RunPowerShellCommand(const std::wstring& script) {
    std::wstring cmdLine = L"powershell.exe -NoProfile -NonInteractive -Command \"" + script + L"\"";

    std::vector<wchar_t> buffer(cmdLine.begin(), cmdLine.end());
    buffer.push_back(L'\0');

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(NULL, buffer.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode == 0;
}
#endif

bool disableAMTComPort() {
#ifdef _WIN32
    std::wstring instanceId = GetAMTInstanceId();
    if (instanceId.empty()) {
        platform->logMessage("disableAMTComPort: AMT device not found in PCI enum.");
        return false;
    }

    std::wstring script = L"Disable-PnpDevice -InstanceId '" + EscapePowerShellSingleQuoted(instanceId) + L"' -Confirm:0";
    if (!RunPowerShellCommand(script)) {
        std::cerr << "[ERROR] Failed to disable AMT Serial Port." << std::endl;
        platform->logMessage("Failed to disable AMT Serial Port.");
        return false;
    }
    return true;
#endif

    return false;
}

bool enableAMTComPort() {
#ifdef _WIN32
    std::wstring instanceId = GetAMTInstanceId();
    if (instanceId.empty()) {
        platform->logMessage("enableAMTComPort: AMT device not found in PCI enum.");
        return false;
    }

    std::wstring script = L"Enable-PnpDevice -InstanceId '" + EscapePowerShellSingleQuoted(instanceId) + L"' -Confirm:0";
    if (!RunPowerShellCommand(script)) {
        std::cerr << "[ERROR] Failed to enable AMT Serial Port." << std::endl;
        platform->logMessage("Failed to enable AMT Serial Port.");
        return false;
    }
    return true;
#endif

    return false;
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

    return false;
}