#ifdef _WIN32
#define _WINSOCKAPI_
#include <windows.h>
#endif
#include "Platform.h"
#include "SystemState.h"
#include "version.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <memory>
#include <mutex>
#include <atomic>
#include <sstream>


std::unique_ptr<Platform> platform;
std::unique_ptr<Platform> createPlatform();

SystemState currentState;
std::mutex stateMutex;

std::atomic<bool> g_terminate{false};

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

void sendLineToBmc(const std::string& output_string) {
    if (!platform) return;

    // --- ADD THIS LINE ---
    std::cout << "[SENDING] " << output_string << std::endl;

    platform->logMessage(output_string);
    platform->writeSerial(output_string + "\r\n");
}

void heartbeatThread() {
    platform->logMessage("Heartbeat thread started.");
    while (!g_terminate.load()) {
		std::this_thread::sleep_for(std::chrono::seconds(30)); // Heartbeat interval - 30s for Release Candidate
        if (g_terminate.load()) {
            break;
        }

        platform->updatePdhMetrics();

        // --- NEW METRIC COLLECTION & REPORTING ---
        try {
            int cpuUsage = platform->getCpuUsagePercent();
            int ramUsage = platform->getRamUsagePercent();
            std::string freeDisk = platform->getFreeDiskSpaceGB("C:"); // Collects C: drive space
            std::string updateState = platform->getWindowsUpdateState();
            float diskQueue = platform->getDiskQueueLength();
            float netRetrans = platform->getNetworkRetransRate();
            std::string uptime = platform->getSystemUptime();
            std::string gpuInfo = platform->getGpuDriverInfo();
            float gpuUsage = platform->getGpuUsagePercent();
            std::string highRamProcs = platform->getHighRamProcesses();

            {
                std::lock_guard<std::mutex> lock(stateMutex);

                // Update SystemState (not strictly necessary for reporting, but good practice)
                currentState.cpuUsagePercent = cpuUsage;
                currentState.ramUsagePercent = ramUsage;
                currentState.freeDiskSpaceGB = freeDisk;
                currentState.windowsUpdateState = updateState;
                currentState.diskQueueLength = diskQueue;
                currentState.networkRetransRate = netRetrans;
                currentState.systemUptime = uptime;
                currentState.gpuDriverInfo = gpuInfo;
                currentState.gpuUsagePercent = gpuUsage;
                currentState.highRamProcesses = highRamProcs;

                // Send the metrics
                sendLineToBmc("cpuUsage, " + std::to_string(cpuUsage) + "%");
                sendLineToBmc("ramUsage, " + std::to_string(ramUsage) + "%");
                sendLineToBmc("freeDisk, " + freeDisk + "GB");
                sendLineToBmc("wuState, " + updateState);
                sendLineToBmc("diskQueue, " + std::to_string(diskQueue));
                sendLineToBmc("netRetrans, " + std::to_string(netRetrans) + "/s");
                sendLineToBmc("uptime, " + uptime);
                sendLineToBmc("gpuInfo, " + gpuInfo);
                sendLineToBmc("gpuUsage, " + std::to_string(gpuUsage) + "%");
                sendLineToBmc("highRamProcs, " + highRamProcs);

                // Log the metrics for confirmation (ensuring logging is used)
                std::stringstream logMsg;
                logMsg << "Metrics: CPU=" << cpuUsage << "%, RAM=" << ramUsage << "%, Disk=" << freeDisk << "GB, WU=" << updateState;
                logMsg << ", DiskQ=" << diskQueue << ", NetR=" << netRetrans << "/s, Uptime=" << uptime;
                logMsg << " | GPU=" << gpuUsage << "% | " << gpuInfo;
                logMsg << " | HighRam={" << highRamProcs << "}";
                platform->logMessage(logMsg.str());
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[ERROR] Exception in heartbeatThread: " << e.what() << std::endl;
            platform->logMessage("[ERROR] Exception in heartbeatThread: " + std::string(e.what()));
        }
        // --- END NEW METRIC COLLECTION & REPORTING ---

        // Existing Heartbeat (HB) message (kept last)
        sendLineToBmc("HB");
    }
    platform->logMessage("Heartbeat thread finished");
}

void checkSystemState() {
    SystemState previousState;
    {
        std::lock_guard<std::mutex> lock(stateMutex);
        previousState = currentState;
    }

    currentState.networkInterfaces = platform->getNetworkInterfaces();
    currentState.hostname = platform->getHostname();
    currentState.username = platform->getLoggedInUser();

    if (currentState != previousState){
        // check change logic
        if (currentState.hostname != previousState.hostname) {
            sendLineToBmc("hostname, " + currentState.hostname);
		}
        if (currentState.username != previousState.username) {
            sendLineToBmc("username, " + currentState.username);
        }
        if (currentState.networkInterfaces != previousState.networkInterfaces) {
            for (const auto& iface : currentState.networkInterfaces) {
                std::stringstream ss;
                ss << "network, " << iface.macAddress << ", " << iface.linkStatus << ", " << iface.ipv4 << ", " << iface.ipv6 << ", " << iface.dhcp << ", " << iface.name;
                sendLineToBmc(ss.str());
            }
        }
    }
}

void processIncomingCommand(const std::string& command) {
    const std::string prefix = "c2a, ";
    if (command.size() > prefix.size() && command.substr(0, prefix.size()) == prefix) {
        std::string message = command.substr(prefix.size());
        platform->logMessage("Received C2A Command: " + message);
        std::cout << "[DEBUG] Received C2A Command: " << message << std::endl;
        platform->showMessageDialog("Command from BMC", message);
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

    if (!platform->openSerialPort(portName, 115200)) {
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
    std::cout << "[DEBUG] Initial messages sent." << std::endl;

    // Send initial username
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

    // Periodic check timer (network and hostname only - session is event-driven now)
    auto lastNetworkCheck = std::chrono::steady_clock::now();
    const auto networkCheckInterval = std::chrono::seconds(30);  // Check every 30s

    while (!g_terminate.load()) {
        // Process incoming serial data
        processIncomingSerialData();

        // Periodic network and hostname check
        auto now = std::chrono::steady_clock::now();
        if (now - lastNetworkCheck >= networkCheckInterval) {

            // Check hostname changes (rare, but possible)
            std::string newHostname = platform->getHostname();
            if (currentState.hostname != newHostname) {
                std::lock_guard<std::mutex> lock(stateMutex);
                currentState.hostname = newHostname;
                sendLineToBmc("hostname, " + currentState.hostname);
                platform->logMessage("Hostname changed to: " + newHostname);
            }

            // Check network interface changes
            std::vector<NetworkInterface> newInterfaces = platform->getNetworkInterfaces();
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
            }

            lastNetworkCheck = now;
        }

        // Short sleep for serial responsiveness (100ms instead of 5s)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    sendLineToBmc("appExit, shutting down serial thread...");
    platform->closeSerialPort();
    platform->logMessage("Serial thread finished.");
}

int main(int argc, char* argv[]) {
    // This message should always appear
    std::cout << "[DEBUG] Application starting. Creating platform object." << std::endl;
    
    platform = createPlatform();
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
            platform->closeSerialPort();
            g_terminate = true;
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
                    // Get the actual username
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


