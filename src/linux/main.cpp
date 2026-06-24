#include "../core/Platform.h"
#include "../core/SystemState.h"
#include "../modules/serial/SerialManager.h"
#include "../modules/3kcheck/3kcheck.h"
#include "../version.h"

#include <iostream>
#include <thread>
#include <chrono>
#include <memory>
#include <mutex>
#include <atomic>
#include <sstream>
#include <string>

std::unique_ptr<Platform> platform;
std::unique_ptr<SerialManager> serialManager;

SystemState currentState;
std::mutex stateMutex;
std::atomic<bool> g_terminate{false};
std::atomic<bool> g_stop_request_sent{false};

void sendLineToBmc(const std::string& output_string) {
    if (!serialManager) return;

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

            try {
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
    auto newInterfaces = platform->getNetworkInterfaces();
    auto newHostname = platform->getHostname();
    auto newUsername = platform->getLoggedInUser();

    if (currentState.hostname != newHostname) {
        std::lock_guard<std::mutex> lock(stateMutex);
        currentState.hostname = newHostname;
        sendLineToBmc("hostname, " + newHostname);
        platform->logMessage("Hostname changed to: " + newHostname);
    }

    if (currentState.username != newUsername) {
        std::lock_guard<std::mutex> lock(stateMutex);
        currentState.username = newUsername;
        sendLineToBmc("username, " + newUsername);
        platform->logMessage("Username changed to: " + newUsername);
    }

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

void serialThread() {
    std::cout << "[DEBUG] serialThread has started." << std::endl;

    std::string portName = SERIAL_PORT;
    CPUInfo cpuInfo = GetCpuInfo();
    std::cout << "[DEBUG] CPUInfo: " << cpuInfo.manufacturer << " " << cpuInfo.model << " " << cpuInfo.clockspeed << std::endl;
    if (IsHX2KCPU(&cpuInfo)) {
        std::cout << "[DEBUG] Detected HX2000 CPU. Setting port to /dev/ttyS2..." << std::endl;
        platform->logMessage("Detected HX2000 CPU. Setting port to /dev/ttyS2...");
        portName = "/dev/ttyS2";
    } else {
        std::cout << "[DEBUG] No HX2000 CPU detected. Using /dev/ttyS0" << std::endl;
        platform->logMessage("No HX2000 CPU detected. Using /dev/ttyS0");
        portName = "/dev/ttyS0";
    }

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
        sendLineToBmc("sessionState, " + initialSessionState);

        {
            std::lock_guard<std::mutex> lock(stateMutex);
            currentState.username = platform->getLoggedInUser();
            sendLineToBmc("username, " + currentState.username);

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

    auto lastNetworkCheck = std::chrono::steady_clock::now();
    const auto networkCheckInterval = std::chrono::seconds(30);

    while (!g_terminate.load()) {
        serialManager->ProcessIncomingData();

        if (!serialManager->IsOpen()) {
            serialManager->TryReconnect();
        }

        if (!initialInfoSent && serialManager->IsOpen()) {
            sendInitialInfo();
            initialInfoSent = true;
        }

        auto now = std::chrono::steady_clock::now();
        if (now - lastNetworkCheck >= networkCheckInterval) {
            checkSystemState();
            lastNetworkCheck = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    sendLineToBmc("appExit, shutting down serial thread...");
    serialManager->Close();
    platform->logMessage("Serial thread finished.");
}

int main(int argc, char* argv[]) {
    std::cout << "[DEBUG] Application starting. Creating platform object." << std::endl;

    platform = createPlatform();

    std::thread workerThread;
    std::thread hbThread;

    std::cout << "[DEBUG] Calling platform->run(). Waiting for on_start callback..." << std::endl;

    platform->run(argc, argv,
        [&]() {
            std::cout << "[DEBUG] on_start callback EXECUTED. Launching serialThread." << std::endl;
            workerThread = std::thread(serialThread);
            hbThread = std::thread(heartbeatThread);
        },
        [&](const std::string& stopReason) {
            std::cout << "[DEBUG] on_stop callback EXECUTED. Stopping serialThread. Reason: " << stopReason << std::endl;
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
        [](const std::string& powerState) {
            std::lock_guard<std::mutex> lock(stateMutex);
            if (currentState.powerState != powerState) {
                currentState.powerState = powerState;
                sendLineToBmc("powerState, " + powerState);
            }
        },
        [](const std::string& sessionState) {
            std::lock_guard<std::mutex> lock(stateMutex);
            if (currentState.sessionState != sessionState) {
                currentState.sessionState = sessionState;
                sendLineToBmc("sessionState, " + sessionState);

                if (sessionState == "6") {
                    if (currentState.username != "none") {
                        currentState.username = "none";
                        sendLineToBmc("username, none");
                    }
                }
                else if (sessionState == "5") {
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
