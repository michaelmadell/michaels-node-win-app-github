#ifdef _WIN32
#define _WINSOCKAPI_
#include <windows.h>
#endif

#include "core/Platform.h"
#include "core/SystemState.h"
#include "modules/serial/SerialManager.h"
#ifdef ENABLE_METRICS
#include "modules/metrics/MetricsCollector.h"
#endif
#include "modules/regedits/Regedit.h"
#include "version.h"

#include <iostream>
#include <thread>
#include <chrono>
#include <memory>
#include <mutex>
#include <atomic>
#include <sstream>

std::unique_ptr<Platform> platform;
std::unique_ptr<SerialManager> serialManager;
#ifdef ENABLE_METRICS
std::unique_ptr<MetricsCollector> metricsCollector;
#endif
std::unique_ptr<Regedit> regedit;

SystemState currentState;
std::mutex stateMutex;
std::atomic<bool> g_terminate{false};

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

void sendLineToBmc(const std::string& output_string) {
    if (!serialManager) return;

    // --- ADD THIS LINE ---
    std::cout << "[SENDING] " << output_string << std::endl;

    platform->logMessage(output_string);
    serialManager->Write(output_string + "\r\n");
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

void serialThread() {
    std::cout << "[DEBUG] serialThread has started." << std::endl;

#ifdef _WIN32
    const std::string portName = SERIAL_PORT;
#else
    const std::string portName = "/dev/ttyUSB0";
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
        [&]() {
            std::cout << "[DEBUG] on_stop callback EXECUTED. Stopping serialThread." << std::endl;
#ifdef _WIN32
			OutputDebugStringW(L"on_stop callback EXECUTED. Stopping serial Thread.\n");
#endif
            g_terminate = true;

            if (serialManager) {
                serialManager->Close();
            }

            if (workerThread.joinable()) {
                workerThread.join();
            }
            if (hbThread.joinable()) {
                hbThread.join();
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


