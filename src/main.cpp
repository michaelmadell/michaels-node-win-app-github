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

std::atomic<bool> g_terminate = false;

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

void sendLineToBmc(const std::string& output_string) {
    if (!platform) return;

    // --- ADD THIS LINE ---
    std::cout << "[SENDING] " << output_string << std::endl;

    platform->logMessage(output_string);
    platform->writeSerial(output_string + "\r\n");
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
        sendLineToBmc("hostname, " + currentState.hostname);
    }
}

void serialThread() {
    std::cout << "[DEBUG] serialThread has started." << std::endl;

    #ifdef _WIN32
        const std::string portName = SERIAL_PORT;
    #else
        const std::string portName = "/dev/ttyS2"; // Make sure this is your correct port
    #endif

    std::cout << "[DEBUG] Attempting to open serial port: " << portName << std::endl;
    platform->logMessage("Serial Thread Started. Attempting to open port " + portName);

    if (!platform->openSerialPort(portName, 115200)) { 
        std::cerr << "[DEBUG] FATAL: platform->openSerialPort() returned false. Thread is exiting." << std::endl;
        platform->logMessage("FATAL: Failed to Open Serial Port: " + portName);
        return;
    }

    std::cout << "[DEBUG] Serial Port opened successfully." << std::endl;
    platform->logMessage("Serial Port opened successfully");

    std::stringstream versionStream;
    versionStream << VERSION_YEAR << "." << VERSION_MONTH << "." << VERSION_RELEASE;
    if (std::string(VERSION_EXTRAVERSION) == "rc") {
        versionStream << "_" << VERSION_EXTRAVERSION << VERSION_RC_NO;
    } else {
        versionStream << "_" << VERSION_EXTRAVERSION;
    }

    std::cout << "[DEBUG] Sending initial messages..." << std::endl;
    sendLineToBmc("appVersion, " + versionStream.str());
    sendLineToBmc("osVersion, " + platform->getOsVersion());
    sendLineToBmc("sessionState, 0");
    std::cout << "[DEBUG] Initial messages sent." << std::endl;

    currentState.username = platform->getLoggedInUser();
    sendLineToBmc("username, " + currentState.username);

    while (!g_terminate.load()) {
        std::cout << "[DEBUG] Polling for system state..." << std::endl;
        std::string newHostname = platform->getHostname();
        std::string newUsername = platform->getLoggedInUser();
        std::vector<NetworkInterface> newInterfaces = platform->getNetworkInterfaces();

        {
            std::lock_guard<std::mutex> lock(stateMutex);

            if (currentState.hostname != newHostname) {
                currentState.hostname = newHostname;
                sendLineToBmc("hostname, " + currentState.hostname);
            }
            if (currentState.username != newUsername) {
                currentState.username = newUsername;
                sendLineToBmc("username, " + currentState.username);
            }
            if (currentState.networkInterfaces != newInterfaces) {
                currentState.networkInterfaces = newInterfaces;
                for (const auto& iface : newInterfaces) { // Iterate over the new interfaces
                    std::stringstream ss;
                    ss << "network, " << iface.macAddress << ", " << iface.linkStatus << ", " << iface.ipv4 << ", " << iface.ipv6 << ", " << iface.dhcp << ", " << iface.name;
                    sendLineToBmc(ss.str());
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(5)); // Increased for easier debugging
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

    std::cout << "[DEBUG] Calling platform->run(). Waiting for on_start callback..." << std::endl;

    platform->run(argc, argv, 
        // on_start callback
        [&]() {
            // If we see this message, we know the service/daemon started correctly
            std::cout << "[DEBUG] on_start callback EXECUTED. Launching serialThread." << std::endl;
            workerThread = std::thread(serialThread);
        },
        // on_stop callback
        [&]() {
            std::cout << "[DEBUG] on_stop callback EXECUTED. Stopping serialThread." << std::endl;
            g_terminate = true;
            if (workerThread.joinable()) {
                workerThread.join();
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

                if (sessionState == "6") { // WTS_SESSION_LOGOFF
                    if (currentState.username != "none") {
                        currentState.username = "none";
                        sendLineToBmc("username, none");
                    }
                }
            }
        }
    );

    std::cout << "[DEBUG] platform->run() has exited. Application terminating." << std::endl;
    return 0;
}