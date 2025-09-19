#include "Platform.h"
#include "SystemState.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <memory>
#include <mutex>
#include <atomic>
#include <sstream>

// Corrected from shared_ptr to unique_ptr
std::unique_ptr<Platform> platform;

// Forward declaration from platform-specific files
std::unique_ptr<Platform> createPlatform();

SystemState currentState;
std::mutex stateMutex;

std::atomic<bool> g_terminate = false;

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

void sendLineToBmc(const std::string& output_string) {
    if (!platform) return;

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
    #ifdef _WIN32
        const std::string portName = "COM3";
    #else
        const std::string portName = "/dev/ttyS0";
    #endif

    std::cout << "Attempting to open serial port: " << portName << std::endl;

    platform->logMessage("Serial Thread Started. Attempting to open port " + portName);

    if (!platform->openSerialPort(portName, 115200)) { 
        platform->logMessage("FATAL: Failed to Open Serial Port: " + portName);
        std::cerr << "FATAL ERROR: Could not open serial port " << portName <<". Thread exiting." << std::endl;
        return;
    }

    platform->logMessage("Serial Port openned successfully");

    sendLineToBmc("appVersion, 2025.9.1");
    sendLineToBmc("osVersion, " + platform->getOsVersion());
    sendLineToBmc("sessionState, 0");

    // 4. Main polling loop
    while (!g_terminate) {
        
        // --- Poll for state changes ---
        std::string newHostname = platform->getHostname();
        std::string newUsername = platform->getLoggedInUser();
        std::vector<NetworkInterface> newInterfaces = platform->getNetworkInterfaces();

        // --- Lock the mutex to safely compare and update the shared state ---
        {
            std::lock_guard<std::mutex> lock(stateMutex);

            // Check and update hostname
            if (currentState.hostname != newHostname) {
                currentState.hostname = newHostname;
                sendLineToBmc("hostname, " + currentState.hostname);
            }

            // Check and update logged-in user
            if (currentState.username != newUsername) {
                currentState.username = newUsername;
                sendLineToBmc("username, " + (currentState.username.empty() ? "none" : currentState.username));
            }
            
            // Check and update network interfaces (a bit more complex)
            if (currentState.networkInterfaces.size() != newInterfaces.size() || 
                !std::equal(newInterfaces.begin(), newInterfaces.end(), currentState.networkInterfaces.begin(), [](const NetworkInterface& a, const NetworkInterface& b){ return a.macAddress == b.macAddress; })) {
                
                currentState.networkInterfaces = newInterfaces;
                for (const auto& iface : currentState.networkInterfaces) {
                    std::stringstream ss;
                    ss << "network, " << iface.macAddress << ", "
                       << iface.linkStatus << ", " << iface.ipv4 << ", "
                       << iface.ipv6 << ", " << iface.dhcp << ", " << iface.name;
                    sendLineToBmc(ss.str());
                }
            }
        } // Mutex is released here

        // Wait for a reasonable interval before polling again
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    // 5. Cleanup on shutdown
    sendLineToBmc("appExit, shutting down serial thread...");
    platform->closeSerialPort();
    platform->logMessage("Serial thread finished.");
}

int main(int argc, char* argv[]) {
    platform = createPlatform();
    std::thread workerThread;

    platform->run(argc, argv, 
        [&]() {
            workerThread = std::thread(serialThread);
        },
        [&]() {
            g_terminate = true;
            if (workerThread.joinable()) {
                workerThread.join();
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

                // Special case: a logoff event clears the username
                // WTS_SESSION_LOGOFF has a value of 6
                if (sessionState == "6") {
                    if (currentState.username != "none") {
                        currentState.username = "none";
                        sendLineToBmc("username, none");
                    }
                }
            }
        }
    );

    return 0;
}