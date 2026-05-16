#ifdef _WIN32
#define _WINSOCKAPI_
#include <windows.h>
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <wbemidl.h>
#include <comdef.h>
#include <cstdio>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#endif

#include "core/Platform.h"
#include "core/SystemState.h"
#include "modules/serial/SerialManager.h"
#include "modules/3kcheck/3kcheck.h"
#ifdef ENABLE_METRICS
#include "modules/metrics/MetricsCollector.h"
#endif
#ifdef _WIN32
#include "modules/regedits/Regedit.h"
#endif
#include "version.h"

#include <iostream>
#include <thread>
#include <chrono>
#include <memory>
#include <mutex>
#include <atomic>
#include <sstream>
#include <string>
#include <vector>

std::unique_ptr<Platform> platform;
std::unique_ptr<SerialManager> serialManager;
#ifdef ENABLE_METRICS
std::unique_ptr<MetricsCollector> metricsCollector;
#endif
#ifdef _WIN32
std::unique_ptr<Regedit> regedit;
#endif

SystemState currentState;
std::mutex stateMutex;
std::atomic<bool> g_terminate{false};
std::atomic<bool> g_stop_request_sent{false};

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

void sendLineToBmc(const std::string& output_string) {
    if (!serialManager) return;

    // --- ADD THIS LINE ---
    std::cout << "[SENDING] " << output_string << std::endl;

    platform->logMessage(output_string);
    serialManager->Write(output_string + "\r\n\0");
}

void notifyStopRequested(const std::string& stopReason) {
    if (g_stop_request_sent.exchange(true)) {
        return;
    }

    if (!serialManager || !serialManager->IsOpen()) {
        platform->logMessage("Stop requested before serial port was available: " + stopReason);
        return;
    }

    sendLineToBmc("appStopRequested, " + stopReason);
}

void heartbeatThread() {
    platform->logMessage("Heartbeat thread started.");

    const auto heartbeatInterval = std::chrono::seconds(30);
    auto lastHeartbeat = std::chrono::steady_clock::now();

    while (!g_terminate.load()) {
        auto now = std::chrono::steady_clock::now();

        if (now - lastHeartbeat >= heartbeatInterval) {
            lastHeartbeat = now;

            if (g_terminate.load()) break;
#ifdef ENABLE_METRICS
            if (metricsCollector) {
                metricsCollector->UpdateCounters();
            }
#endif
            try {
#ifdef ENABLE_METRICS
                auto metrics = metricsCollector->CollectAll();
                {
                    std::lock_guard<std::mutex> lock(stateMutex);

                    currentState.cpuUsagePercent = metrics.performance.cpuUsage;
                    currentState.ramUsagePercent = metrics.performance.ramUsage;
                    currentState.freeDiskSpaceGB = metrics.performance.freeDiskSpace;
                    currentState.windowsUpdateState = metrics.updates.state;
                    currentState.diskQueueLength = metrics.performance.diskQueue;
                    currentState.networkRetransRate = metrics.performance.netRetrans;
                    currentState.systemUptime = metrics.performance.uptime;
                    currentState.gpuDriverInfo = metrics.gpu.driverInfo;
                    currentState.gpuUsagePercent = metrics.gpu.usage;
                    currentState.highRamProcesses = metrics.processes.highRamProcesses;

                    sendLineToBmc("cpuUsage, " + std::to_string(metrics.performance.cpuUsage) + "%");
                    sendLineToBmc("ramUsage, " + std::to_string(metrics.performance.ramUsage) + "%");
                    sendLineToBmc("freeDisk, " + metrics.performance.freeDiskSpace + "GB");
                    sendLineToBmc("wuState, " + metrics.updates.state);
                    sendLineToBmc("diskQueue, " + std::to_string(metrics.performance.diskQueue));
                    sendLineToBmc("netRetrans, " + std::to_string(metrics.performance.netRetrans) + "/s");
                    sendLineToBmc("uptime, " + metrics.performance.uptime);
                    sendLineToBmc("gpuInfo, " + metrics.gpu.driverInfo);
                    sendLineToBmc("gpuUsage, " + std::to_string(metrics.gpu.usage) + "%");
                    sendLineToBmc("highRamProcs, " + metrics.processes.highRamProcesses);

                    std::stringstream logMsg;
                    logMsg << "Metrics: CPU=" << metrics.performance.cpuUsage << "%, "
                        << "RAM = " << metrics.performance.ramUsage << "%, "
                        << "Disk = " << metrics.performance.freeDiskSpace << "GB, "
                        << "WU = " << metrics.updates.state << ", "
                        << "DiskQ=" << metrics.performance.diskQueue << ", "
                        << "NetR = " << metrics.performance.netRetrans << " / s, "
                        << "Uptime = " << metrics.performance.uptime << " | "
                        << "GPU=" << metrics.gpu.usage << "% | "
                        << metrics.gpu.driverInfo << " | "
                        << "HighRam={" << metrics.processes.highRamProcesses << "}";
                    platform->logMessage(logMsg.str());
                }
#endif

                sendLineToBmc("HB");
            } catch (const std::exception& e) {
                std::cerr << "[ERROR] Exception in heartbeatThread: " << e.what() << std::endl;
                platform->logMessage("[ERROR] Exception in heartbeatThread: " + std::string(e.what()));
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    platform->logMessage("Heartbeat thread finished");
}

// =============================================================================
// === AMT COM Port Management =================================================
// =============================================================================
// Intel AMT Serial-over-LAN (SOL) uses a virtual COM port managed by the
// Windows PnP driver. On HX2000 hardware, AMT defaults to COM3, which
// conflicts with the CoreStation BMC serial connection. The functions below
// detect, disable, and reassign the AMT COM port at startup.

// Target COM port for the CoreStation BMC serial link.
static constexpr char kBmcComPort[]    = "COM3";
// kBmcComPort in wide-string form for comparison with Win32 registry values.
static constexpr wchar_t kBmcComPortW[] = L"COM3";
// COM port AMT SOL is reassigned to when it conflicts with kBmcComPort.
static constexpr char kAmtTargetPort[] = "COM4";
// kAmtTargetPort in wide-string form for Win32 registry calls.
static constexpr wchar_t kAmtTargetPortW[] = L"COM4";
// AMT SOL device display name written to the registry after reassignment.
static constexpr wchar_t kAmtFriendlyName[] = L"Intel(R) Active Management Technology - SOL (COM4)";
// COM Name Arbiter ComDB bitmask for COM4.
// ComDB is a binary array; COM N occupies bit (N-1) in byte floor((N-1)/8).
// COM4 = bit index 3 → byte[0] bit 3 → 0x08.
static constexpr BYTE kComDbCom4Bit = 0x08;
// Registry path for the COM Name Arbiter database (includes value name at end).
static constexpr char kComArbiterPath[] =
    "SYSTEM\\CurrentControlSet\\Control\\COM Name Arbiter\\ComDB";

struct AMTPortInfo {
    std::wstring comPort;
    std::wstring instanceId;
};

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
                // Build narrow path — HWID and instance IDs are ASCII-safe for conversion.
                std::string narrowDevKey(devKeyPath.begin(), devKeyPath.end());
                std::string narrowInstance(instanceName, instanceName + wcslen(instanceName));
                std::string portPath = narrowDevKey + "\\" + narrowInstance + "\\Device Parameters\\PortName";

                std::string portNameA;
                if (regedit->Read(portPath, portNameA, HKEY_LOCAL_MACHINE)) {
                    RegCloseKey(hDevKey);
                    std::wstring portNameW(portNameA.begin(), portNameA.end());
                    std::wstring fullId = std::wstring(L"PCI\\") + kAMTDeviceHwids[i] + L"\\" + instanceName;
                    return {portNameW, fullId};
                }
            ++index;
            instanceNameSize = _countof(instanceName);
        }
        RegCloseKey(hDevKey);
    }
    return {L"", L""};
#endif
}

// Launch powershell.exe directly via CreateProcessW — avoids system() and the
// shell-injection risk that comes with it. The command line is built from a
// known-safe instance ID that was read from the registry, not from user input.
static bool runPowerShellPnpCommand(const std::wstring& verb, const std::wstring& instanceId) {
#ifdef _WIN32
    // Build: powershell.exe -NoProfile -NonInteractive -Command "<verb>-PnpDevice ..."
    std::wstring cmdLine =
        L"powershell.exe -NoProfile -NonInteractive -Command \""
        + verb + L"-PnpDevice -InstanceId '" + instanceId + L"' -Confirm:$false\"";

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    // CreateProcessW requires a mutable buffer for lpCommandLine.
    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(L'\0');

    if (!CreateProcessW(
            nullptr,      // use PATH lookup — no hard-coded powershell path
            buf.data(),
            nullptr, nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr, nullptr,
            &si, &pi)) {
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode == 0;
#else
    (void)verb; (void)instanceId;
    return false;
#endif
}

bool disableAMTComPort() {
#ifdef _WIN32
    std::wstring instanceId = GetAMTInstanceId();
    if (instanceId.empty()) {
        platform->logMessage("disableAMTComPort: AMT device not found in PCI enum.");
        return false;
    }

    if (!runPowerShellPnpCommand(L"Disable", instanceId)) {
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

    if (!runPowerShellPnpCommand(L"Enable", instanceId)) {
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
    // COM4 = bit index 3 → byte[0] bit 3 → kComDbCom4Bit (0x08)
    {
        std::vector<BYTE> comDb;
        if (regedit->ReadBinary(kComArbiterPath, comDb, HKEY_LOCAL_MACHINE)) {
            if (comDb.size() < 1) comDb.resize(8, 0);
            if (!(comDb[0] & kComDbCom4Bit)) {
                comDb[0] |= kComDbCom4Bit;
                regedit->WriteBinary(kComArbiterPath, comDb, HKEY_LOCAL_MACHINE);
                platform->logMessage("COM Name Arbiter: COM4 reserved.");
            } else {
                platform->logMessage("COM Name Arbiter: COM4 was already reserved.");
            }
        } else {
            platform->logMessage("WARNING: Could not read COM Name Arbiter — continuing anyway.");
        }
    }

    // --- Step 2: Write PortName and FriendlyName for all matching device instances ---
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

            // Build narrow key paths — HWID and instance IDs are ASCII-safe for conversion.
            std::string narrowDevKey(devKeyPath.begin(), devKeyPath.end());
            std::string narrowInstance(instanceName, instanceName + wcslen(instanceName));
            std::string friendlyPath = narrowDevKey + "\\" + narrowInstance + "\\FriendlyName";
            std::string portPath     = narrowDevKey + "\\" + narrowInstance + "\\Device Parameters\\PortName";

            // Write FriendlyName and PortName via Regedit (creates Device Parameters subkey if absent).
            regedit->Write(friendlyPath, "Intel(R) Active Management Technology - SOL (COM4)", HKEY_LOCAL_MACHINE);
            if (regedit->Write(portPath, kAmtTargetPort, HKEY_LOCAL_MACHINE)) {
                platform->logMessage("Set PortName=COM4 for: " + std::string(instancePath.begin(), instancePath.end()));
            } else {
                platform->logMessage("ERROR: Failed to write PortName for: " + std::string(instancePath.begin(), instancePath.end()));
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
    if (newInfo.comPort == kBmcComPortW) {
        platform->logMessage("reassignComPort: Device is still on COM3 after reassignment attempt.");
        return false;
    }

    platform->logMessage("reassignComPort: Successfully assigned AMT Serial Port to "
        + std::string(newInfo.comPort.begin(), newInfo.comPort.end()));
    return true;
#endif
}

// =============================================================================
// === End AMT COM Port Management =============================================
// =============================================================================


void checkSystemState() {
    static SystemState previousState;

    auto newInterfaces = platform->getNetworkInterfaces();
    auto newHostname = platform->getHostname();
    auto newUsername = platform->getLoggedInUser();

    bool hasChanges = false;

    // Check hostname changes
    if (currentState.hostname != newHostname) {
        std::lock_guard<std::mutex> lock(stateMutex);
        currentState.hostname = newHostname;
        sendLineToBmc("hostname, " + newHostname);
        platform->logMessage("Hostname changed to: " + newHostname);
        hasChanges = true;
    }

    // Check username changes
    if (currentState.username != newUsername) {
        std::lock_guard<std::mutex> lock(stateMutex);
        currentState.username = newUsername;
        sendLineToBmc("username, " + newUsername);
        platform->logMessage("Username changed to: " + newUsername);
        hasChanges = true;
    }

    // Check network interface changes
    if (currentState.networkInterfaces != newInterfaces) {
        std::lock_guard<std::mutex> lock(stateMutex);
        currentState.networkInterfaces = newInterfaces;

        platform->logMessage("Network configuration changed - sending updates");
        for (const auto& iface : newInterfaces) {
            std::stringstream ss;
            ss << "network, " << iface.macAddress << ", " << iface.linkStatus
                << ", " << iface.ipv4 << ", " << iface.ipv6 << ", "
                << iface.dhcp << ", " << iface.name;
            sendLineToBmc(ss.str());
        }
        hasChanges = true;
    }
}

void processIncomingCommand(const std::string& command) {
    const std::string prefix = "c2a, ";

    if (command.size() > prefix.size() && command.substr(0, prefix.size()) == prefix) {
        std::string message = command.substr(prefix.size());
        platform->logMessage("Received C2A Command: " + message);
        std::cout << "[RX] Received C2A Command: " << message << std::endl;
        platform->showMessageDialog("Command from BMC", message);
    }
    else {
        platform->logMessage("Received: " + command);
        std::cout << "[RX] " << command << std::endl;
    }
}

void processIncomingSerialData() {
    static std::string rxBuffer;
    std::string newData;
    platform->readSerial(newData);
    rxBuffer+=newData;
    size_t pos=0;
    while((pos=rxBuffer.find_first_of("\r\n"))!=std::string::npos) {
        std::string line=rxBuffer.substr(0, pos);
        if (!line.empty()) {
            processIncomingCommand(line);
        }
        rxBuffer.erase(0,pos+1);
        if (!rxBuffer.empty()&&(rxBuffer[0]=='\r'||rxBuffer[0]=='\n')) {
            rxBuffer.erase(0, 1);
        }
    }
}

/* NOT CALLED: serialThread() reads incoming data via serialManager->ProcessIncomingData()
   and platform->readSerial() directly. This worker stub was never wired into any thread.

void readSerialPortWorker() {
    platform->logMessage("Serial worker thread started.");
    std::string readData;
    // ... other variables

    while (!g_terminate.load()) {

        // This call is now NON-BLOCKING (returns immediately if no data is ready)
        if (platform->readSerial(readData)) {
            // --- SUCCESSFUL READ / Data Processing ---
            // ... your processing logic
        }

        else {
            // --- FAILED READ / No Data Available ---

            // CRITICAL: Check exit flag immediately
            if (g_terminate.load()) {
                break;
            }

            // CRITICAL: Sleep briefly to prevent 100% CPU spin when no data is available
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    platform->logMessage("Serial worker thread finished cleanly.");
}
*/

void serialThread() {
    std::cout << "[DEBUG] serialThread has started." << std::endl;

#ifdef _WIN32
    std::string portName = SERIAL_PORT;
    CPUInfo cpuInfo = GetCpuInfo();
    std::cout << "[DEBUG] CPUInfo: " << cpuInfo.manufacturer << " " << cpuInfo.model << " " << cpuInfo.clockspeed << std::endl;
    if (IsHX2KCPU(&cpuInfo)) {
        std::cout << "[DEBUG] Detected HX2000 CPU. Setting port to COM3..." << std::endl;
        platform->logMessage("Detected HX2000 CPU. Setting port to COM3...");
        portName = "COM3";
    } else {
        std::cout << "[DEBUG] No HX2000 CPU detected. Using COM1..." << std::endl;
        platform->logMessage("No HX2000 CPU detected. Using COM1...");
        portName = "COM1";
    }
#else
    const std::string portName = "/dev/ttyS2";
#endif

    std::cout << "[DEBUG] Attempting to open serial port: " << portName << std::endl;
    platform->logMessage("Serial Thread Started. Attempting to open port " + portName);

    serialManager = std::make_unique<SerialManager>(
        [](const std::string& command) {
            processIncomingCommand(command);
        }
    );

    if (!serialManager->Open(portName, 115200)) {
        std::cerr << "[DEBUG] FATAL: platform->openSerialPort() returned false. Thread is exiting." << std::endl;
        platform->logMessage("FATAL: Failed to Open Serial Port: " + portName);
#ifdef _WIN32
        OutputDebugStringW(L"[FATAL] Failed to Open Serial Port.\n");
#endif
        return;
    }

    std::cout << "[DEBUG] Serial Port opened successfully." << std::endl;
    platform->logMessage("Serial Port opened successfully");

    // Send initial system info
    std::stringstream versionStream;
    versionStream << VERSION_MAJOR << "." << VERSION_MINOR << "." << VERSION_RELEASE << "." << VERSION_BUILD;
    if (std::string(VERSION_EXTRAVERSION) == "rc") {
        versionStream << "_" << VERSION_EXTRAVERSION << VERSION_RC_NO;
    }
    else {
        versionStream << "_" << VERSION_EXTRAVERSION;
    }

    std::cout << "[DEBUG] Sending initial messages..." << std::endl;
    sendLineToBmc("appVersion, " + versionStream.str());
    sendLineToBmc("winVersion, " + platform->getOsVersion());
    sendLineToBmc("osBuild, " + platform->getOsBuild());

    std::string initialSessionState = platform->getCurrentSessionState();
    sendLineToBmc("sessionState, " + initialSessionState);  // Initial state

    // Send initial username
    {
        std::lock_guard<std::mutex> lock(stateMutex);
        currentState.username = platform->getLoggedInUser();
        sendLineToBmc("username, " + currentState.username);

        // Send initial network state
        currentState.networkInterfaces = platform->getNetworkInterfaces();
        for (const auto& iface : currentState.networkInterfaces) {
            std::stringstream ss;
            ss << "network, " << iface.macAddress << ", " << iface.linkStatus
                << ", " << iface.ipv4 << ", " << iface.ipv6 << ", "
                << iface.dhcp << ", " << iface.name;
            sendLineToBmc(ss.str());
        }
    }

    std::cout << "[DEBUG] Initial messages sent." << std::endl;

    // Periodic check timer for network and hostname
    auto lastNetworkCheck = std::chrono::steady_clock::now();
    const auto networkCheckInterval = std::chrono::seconds(30);

    while (!g_terminate.load()) {
        // Process incoming serial data
        serialManager->ProcessIncomingData();

        // Try to reconnect if disconnected
        if (!serialManager->IsOpen()) {
            serialManager->TryReconnect();
        }

        // Periodic network and hostname check
        auto now = std::chrono::steady_clock::now();
        if (now - lastNetworkCheck >= networkCheckInterval) {
            checkSystemState();
            lastNetworkCheck = now;
        }

        // Short sleep for serial responsiveness
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    sendLineToBmc("appExit, shutting down serial thread...");
    serialManager->Close();
    platform->logMessage("Serial thread finished.");
}

int main(int argc, char* argv[]) {
    // This message should always appear
    std::cout << "[DEBUG] Application starting. Creating platform object." << std::endl;
    
    platform = createPlatform();
#ifdef _WIN32
    // Regedit is always initialized on Windows — used by AMT COM port management below.
    regedit = std::make_unique<Regedit>([](const std::string& msg) {
        platform->logMessage(msg);
    });
#endif

    std::cout << "[DEBUG] Checking current COM assignment for AMT Serial Port" << std::endl;
    #ifdef _WIN32

    AMTPortInfo AMTInfo = GetAMTComPort();

    if (!AMTInfo.comPort.empty()) {
        std::wcout << L"[DEBUG] AMT Serial Port is currently assigned to: " << AMTInfo.comPort << std::endl;
        platform->logMessage("AMT Serial Port COM assignment: " + std::string(AMTInfo.comPort.begin(), AMTInfo.comPort.end()));
    } else {
        std::cout << "[DEBUG] No AMT Serial Port COM assignment found." << std::endl;
        platform->logMessage("No AMT Serial Port COM assignment found.");
    }

    if (AMTInfo.comPort == kBmcComPortW) {
        std::cout << "[DEBUG] AMT Serial Port is on COM3. Attempting to disable it to free COM3 for our use." << std::endl;
        platform->logMessage("AMT Serial Port is on COM3. Attempting to disable it.");
        if (disableAMTComPort()) {
            std::cout << "[DEBUG] Successfully disabled AMT Serial Port." << std::endl;
            platform->logMessage("Successfully disabled AMT Serial Port.");
            if (enableAMTComPort()) {
                std::cout << "[DEBUG] Successfully re-enabled AMT Serial Port after disabling." << std::endl;
                platform->logMessage("Successfully re-enabled AMT Serial Port after disabling.");
                std::this_thread::sleep_for(std::chrono::seconds(2));
                AMTPortInfo amtPortInfo = GetAMTComPort();
                if (!amtPortInfo.comPort.empty() && amtPortInfo.comPort != kBmcComPortW) {
                    std::cout << "[DEBUG] Verified AMT Serial Port is not back on COM3 after re-enabling." << std::endl;
                    platform->logMessage("Verified AMT Serial Port is not back on COM3 after re-enabling.");
                } else {
                    std::cerr << "[ERROR] After re-enabling, AMT Serial Port is back on COM3, falling back to manual reassignment." << std::endl;
                    platform->logMessage("After re-enabling, AMT Serial Port is back on COM3, falling back to manual reassignment.");
                    if (reassignComPort()) {
                        std::cout << "[DEBUG] Successfully reassigned AMT Serial Port to a different COM port." << std::endl;
                        platform->logMessage("Successfully reassigned AMT Serial Port to a different COM port.");
                    } else {
                        std::cerr << "[ERROR] Failed to reassign AMT Serial Port. COM3 may still be occupied." << std::endl;
                        platform->logMessage("Failed to reassign AMT Serial Port. COM3 may still be occupied.");
                        exit(1);
                    }
                }
            }
        } else {
            std::cerr << "[ERROR] Failed to disable AMT Serial Port. This may cause issues if COM3 is not available." << std::endl;
            platform->logMessage("Failed to disable AMT Serial Port. COM3 may not be available.");
            exit(1);
        }
    }
#endif

#ifdef ENABLE_METRICS
    metricsCollector = std::make_unique<MetricsCollector>(platform.get());
#endif

    std::thread workerThread;
    std::thread hbThread;

    std::cout << "[DEBUG] Calling platform->run(). Waiting for on_start callback..." << std::endl;

    platform->run(argc, argv, 
        // on_start callback
        [&]() {
            // If we see this message, we know the service/daemon started correctly
            std::cout << "[DEBUG] on_start callback EXECUTED. Launching serialThread." << std::endl;
            workerThread = std::thread(serialThread);
            hbThread = std::thread(heartbeatThread);
        },
        // on_stop callback
        [&](const std::string& stopReason) {
            std::cout << "[DEBUG] on_stop callback EXECUTED. Stopping serialThread. Reason: " << stopReason << std::endl;
#ifdef _WIN32
			OutputDebugStringW(L"on_stop callback EXECUTED. Stopping serial Thread.\n");
#endif
            notifyStopRequested(stopReason);
            g_terminate = true;

            if (workerThread.joinable()) {
                workerThread.join();
            }
            if (hbThread.joinable()) {
                hbThread.join();
            }

            if (serialManager) {
                serialManager->Close();
            }
        },
        // powerState callback
        [](const std::string& powerState) {
            std::lock_guard<std::mutex> lock(stateMutex);
            if (currentState.powerState != powerState) {
                currentState.powerState = powerState;
                sendLineToBmc("powerState, " + powerState);
            }
        },
        // sessionState callback
        [](const std::string& sessionState) {
            std::lock_guard<std::mutex> lock(stateMutex);
            if (currentState.sessionState != sessionState) {
                currentState.sessionState = sessionState;
                sendLineToBmc("sessionState, " + sessionState);

                // When user logs off, set username to "none"
                if (sessionState == "6") { // WTS_SESSION_LOGOFF
                    if (currentState.username != "none") {
                        currentState.username = "none";
                        sendLineToBmc("username, none");
                    }
                }
                // When user logs on, update username
                else if (sessionState == "5") { // WTS_SESSION_LOGON
                    std::string newUsername = platform->getLoggedInUser();
                    if (currentState.username != newUsername) {
                        currentState.username = newUsername;
                        sendLineToBmc("username, " + currentState.username);
                    }
                }
            }
        }
    );

    std::cout << "[DEBUG] platform->run() has exited. Application terminating." << std::endl;
    return 0;
}


