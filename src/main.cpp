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
#include "modules/amt/AMTPortManager.h"
#include "modules/serial/SerialManager.h"
#include "modules/3kcheck/3kcheck.h"
#ifdef ENABLE_METRICS
#include "modules/metrics/MetricsCollector.h"
#endif
#ifdef ENABLE_REGEDIT
#include "modules/regedits/Regedit.h"
#endif
#ifdef ENABLE_TRAY_APP
#include "platform/WinHandles.h"
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
#include <fstream>
#include <vector>
#include "platform/WindowsPlatform.h"

std::unique_ptr<Platform> platform;
std::unique_ptr<SerialManager> serialManager;
#ifdef ENABLE_METRICS
std::unique_ptr<MetricsCollector> metricsCollector;
#endif
#ifdef ENABLE_REGEDIT
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

    std::cout << "[SENDING] " << output_string << std::endl;

    platform->logMessage(output_string);
    serialManager->Write(output_string + "\r\n");
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

        // Sample c2a command dispatch. Add new commands here; anything that
        // doesn't match a known command falls back to the original behavior
        // of showing it as a message dialog.
        if (message == "ping") {
            sendLineToBmc("pong");
        }
        else if (message == "status") {
            sendLineToBmc("status, cpu=" + std::to_string(platform->getCpuUsagePercent()) + "%, "
                + "ram=" + std::to_string(platform->getRamUsagePercent()) + "%, "
                + "uptime=" + platform->getSystemUptime());
        }
        else if (message == "shutdown") {
            platform->logMessage("Received shutdown command from BMC. Initiating shutdown.");
            platform->shutdownSystem();
        }
        else {
            platform->showMessageDialog("Command from BMC", message);
        }
    }
    else {
        platform->logMessage("Received: " + command);
        std::cout << "[RX] " << command << std::endl;
    }
}

void serialThread() {
    std::cout << "[DEBUG] serialThread has started." << std::endl;

#ifdef _WIN32
    std::string portName;
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
    // HX2000 boards expose AMT SOL on ttyS2; HX3000 boards on ttyS0.
    static const std::vector<std::string> hx2kCpus = {
        "Intel(R) Core(TM) Ultra 7 165H",
        "Intel(R) Core(TM) Ultra 7 165U",
        "Intel(R) Core(TM) Ultra 9 285H"
    };

    std::string modelName;
    {
        std::ifstream cpuinfo("/proc/cpuinfo");
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.rfind("model name", 0) == 0) {
                size_t colon = line.find(':');
                if (colon != std::string::npos) {
                    modelName = line.substr(colon + 1);
                    size_t start = modelName.find_first_not_of(" \t");
                    modelName = (start != std::string::npos) ? modelName.substr(start) : "";
                }
                break;
            }
        }
    }

    bool isHx2k = false;
    for (const auto& cpu : hx2kCpus) {
        if (modelName.find(cpu) != std::string::npos) {
            isHx2k = true;
            break;
        }
    }

    std::string portName;
    if (isHx2k) {
        std::cout << "[DEBUG] Detected HX2000 CPU. Setting port to /dev/ttyS2..." << std::endl;
        platform->logMessage("Detected HX2000 CPU. Setting port to /dev/ttyS2...");
        portName = "/dev/ttyS2";
    } else {
        std::cout << "[DEBUG] No HX2000 CPU detected. Using /dev/ttyS0..." << std::endl;
        platform->logMessage("No HX2000 CPU detected. Using /dev/ttyS0...");
        portName = "/dev/ttyS0";
    }
#endif

    std::cout << "[DEBUG] Attempting to open serial port: " << portName << std::endl;
    platform->logMessage("Serial Thread Started. Attempting to open port " + portName);

    serialManager = std::make_unique<SerialManager>(
        [](const std::string& command) {
            processIncomingCommand(command);
        }
    );

    platform->setSerialBridgeHandler([](const std::string& data) {
        return serialManager && serialManager->Write(data);
    });

    if (!serialManager->Open(portName, 115200)) {
        std::cerr << "[DEBUG] Failed to open serial port, will retry in background: " << portName << std::endl;
        platform->logMessage("FATAL: Failed to Open Serial Port: " + portName);
#ifdef _WIN32
        OutputDebugStringW(L"[FATAL] Failed to Open Serial Port.\n");
#endif
    }
    else {
        std::cout << "[DEBUG] Serial Port opened successfully." << std::endl;
        platform->logMessage("Serial Port opened successfully");
    }

    auto sendInitialInfo = [&]() {
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
    };

    bool initialInfoSent = false;
    if (serialManager->IsOpen()) {
        sendInitialInfo();
        initialInfoSent = true;
    }

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

        if (!initialInfoSent && serialManager->IsOpen()) {
            sendInitialInfo();
            initialInfoSent = true;
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
#if defined(_WIN32) && defined(ENABLE_TRAY_APP)
    // Tray-helper mode: the service (Session 0) spawns this exe into the user
    // session with --tray-only so the tray icon appears on the user's desktop.
    // Must be checked before any service/AMT logic runs.
    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--tray-only") == 0) {
            DWORD parentPid = 0;
            for (int j = i + 1; j < argc - 1; j++) {
                if (_stricmp(argv[j], "--parent-pid") == 0) {
                    parentPid = static_cast<DWORD>(atoi(argv[j + 1]));
                    break;
                }
            }
            platform = createPlatform();
            return static_cast<WindowsPlatform*>(platform.get())->runAsTrayHelper(parentPid);
        }
    }
#endif

    // This message should always appear
    std::cout << "[DEBUG] Application starting. Creating platform object." << std::endl;

    platform = createPlatform();

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

    if (AMTInfo.comPort == L"COM3") {
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
                if (!amtPortInfo.comPort.empty() && amtPortInfo.comPort != L"COM3") {
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


