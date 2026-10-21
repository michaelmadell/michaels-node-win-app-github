#ifdef _WIN32
#define _WINSOCKAPI_
#include <windows.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <wbemidl.h>
#include <comdef.h>
#include <cstdio>
#include <print>
#include <format>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#endif

#include "core/Platform.h"
#include "core/SystemState.h"
#include "modules/amt/AMTPortManager.h"
#include "modules/serial/SerialManager.h"
#ifdef ENABLE_C2A
#include "modules/cmc/CmcCommandHandler.h"
#endif
#include "modules/3kcheck/3kcheck.h"
#ifdef ENABLE_METRICS
#include "modules/metrics/MetricsCollector.h"
#endif
#ifdef ENABLE_TRAY_APP
#include "platform/WinHandles.h"
#endif
#include "core/Logging.h"
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
#ifdef ENABLE_C2A
std::unique_ptr<CmcCommandHandler> cmcHandler;
#endif
#ifdef ENABLE_METRICS
std::unique_ptr<MetricsCollector> metricsCollector;
#endif

SystemState currentState;
std::mutex stateMutex;
std::atomic<bool> g_terminate{false};
std::atomic<bool> g_stop_request_sent{false};

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

void sendLineToBmc(const std::string& output_string) {
    if (!serialManager) return;

    std::this_thread::sleep_for(std::chrono::milliseconds(250)); // Small delay to avoid overwhelming the serial port

    std::print("[SENDING] {}\n", output_string);

    platform->logMessage(output_string);

    if (serialManager->Write(output_string + "\r\n")) {
        std::print("[SENT OK] {}\n", output_string);
    } else {
        std::print("[SEND FAILED] {}\n", output_string);
        platform->logMessage("[ERROR] Failed to write to serial port: " + output_string);
    }
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

// Top-level safety net for the worker threads: anything that escapes
// std::expected handling lands here, gets logged everywhere, and the thread's
// loop carries on.
void reportUnhandledException(const char* where, const char* what) {
    std::string text = std::format("Unhandled exception in {}: {}", where, what);
    std::print("[ERROR] {}\n", text);
    platform->logMessage("[ERROR] " + text);
    core::Log(core::LogLevel::Critical, core::kMsgIDUnhandledException, text);
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

                    platform->logMessage(std::format(
                        "Metrics: CPU={}%, RAM = {}%, Disk = {}GB, WU = {}, DiskQ={}, NetR = {} / s, "
                        "Uptime = {} | GPU={}% | {} | HighRam={{{}}}",
                        metrics.performance.cpuUsage, metrics.performance.ramUsage,
                        metrics.performance.freeDiskSpace, metrics.updates.state,
                        metrics.performance.diskQueue, metrics.performance.netRetrans,
                        metrics.performance.uptime, metrics.gpu.usage, metrics.gpu.driverInfo,
                        metrics.processes.highRamProcesses));
                }
#endif

                sendLineToBmc("HB");
            } catch (const std::exception& e) {
                // Safety net only: fallible operations report through
                // std::expected, so reaching here means something unexpected
                // threw. Log it and keep the heartbeat loop running.
                reportUnhandledException("heartbeatThread", e.what());
            } catch (...) {
                reportUnhandledException("heartbeatThread", "unknown exception");
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    platform->logMessage("Heartbeat thread finished");
}

void resendThread() {
    platform->logMessage("Resend thread started.");

    const auto resendInterval = std::chrono::minutes(5);
    auto lastResend = std::chrono::steady_clock::now();

    while (!g_terminate.load()) {
        auto now = std::chrono::steady_clock::now();
        if (now - lastResend >= resendInterval) {
            lastResend = now;

            if (g_terminate.load()) break;

            try {
                auto sendInitialInfo = [&]() {
                    std::string versionStr = std::format("{}.{}.{}.{}", VERSION_MAJOR, VERSION_MINOR, VERSION_RELEASE, VERSION_BUILD);
                    if (std::string(VERSION_EXTRAVERSION) == "rc") {
                        versionStr += std::format("_{}{}", VERSION_EXTRAVERSION, VERSION_RC_NO);
                    }
                    else {
                        versionStr += std::format("_{}", VERSION_EXTRAVERSION);
                    }

                    std::print("[DEBUG] resending initial messages...\n");
                    sendLineToBmc("appVersion, " + versionStr);

                    // Send initial username
                    {
                        std::lock_guard<std::mutex> lock(stateMutex);
                        currentState.username = platform->getLoggedInUser();
                        sendLineToBmc("username, " + currentState.username);

                        // Send initial network state
                        currentState.networkInterfaces = platform->getNetworkInterfaces();
                        for (const auto& iface : currentState.networkInterfaces) {
                            std::string networkStr = std::format("network, {}, {}, {}, {}, {}, {}", iface.macAddress, iface.linkStatus, iface.ipv4, iface.ipv6, iface.dhcp, iface.name);
                            sendLineToBmc(networkStr);
                        }
                    }

                    std::print("[DEBUG] resent initial messages.\n");
                };

                sendInitialInfo();
            } catch (const std::exception& e) {
                // Safety net only - see heartbeatThread.
                reportUnhandledException("ResendThread", e.what());
            } catch (...) {
                reportUnhandledException("ResendThread", "unknown exception");
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    platform->logMessage("Resend thread finished");
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
            std::string networkStr = std::format("network, {}, {}, {}, {}, {}, {}", iface.macAddress, iface.linkStatus, iface.ipv4, iface.ipv6, iface.dhcp, iface.name);
            sendLineToBmc(networkStr);
        }
        hasChanges = true;
    }
}

#ifdef ENABLE_C2A
void processIncomingCommand(const std::string& command) {
    const std::string prefix = "c2a, ";

    if (command.size() > prefix.size() && command.substr(0, prefix.size()) == prefix) {
        std::string message = command.substr(prefix.size());
        platform->logMessage("Received C2A Command: " + message);
        std::print("[RX] Received C2A Command: {}\n", message);

        if (cmcHandler) {
            cmcHandler->handle(message);
        }
    }
    else {
        platform->logMessage("Received: " + command);
        std::print("[RX] {}\n", command);
    }
}
#endif

void serialThread() {
    std::print("[DEBUG] serialThread has started.\n");

#ifdef _WIN32
    std::string portName;
    CPUInfo cpuInfo = GetCpuInfo();
    std::print("[DEBUG] CPUInfo: {} {} {}\n", cpuInfo.manufacturer, cpuInfo.model, cpuInfo.clockspeed);
    if (IsHX2KCPU(&cpuInfo)) {
        std::print("[DEBUG] Detected HX2000 CPU. Setting port to COM3...\n");
        platform->logMessage("Detected HX2000 CPU. Setting port to COM3...");
        portName = "COM3";
    } else {
        std::print("[DEBUG] No HX2000 CPU detected. Using COM1...\n");
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
        std::print("[DEBUG] Detected HX2000 CPU. Setting port to /dev/ttyS2...\n");
        platform->logMessage("Detected HX2000 CPU. Setting port to /dev/ttyS2...");
        portName = "/dev/ttyS2";
    } else {
        std::print("[DEBUG] No HX2000 CPU detected. Using /dev/ttyS0...\n");
        platform->logMessage("No HX2000 CPU detected. Using /dev/ttyS0...");
        portName = "/dev/ttyS0";
    }
#endif

    std::print("[DEBUG] Attempting to open serial port: {}\n", portName);
    platform->logMessage("Serial Thread Started. Attempting to open port " + portName);

    serialManager = std::make_unique<SerialManager>(
        [](const std::string& command) {
            #ifdef ENABLE_C2A
            processIncomingCommand(command);
            std::print("[RX] %s\n", command.c_str());
            
            #else
            platform->logMessage("Received: " + command);
            platform->logMessage("Not processing C2A commands because ENABLE_C2A is not defined.");
            std::print("[RX] %s\n", command.c_str());
            #endif
        }
    );

#ifdef ENABLE_C2A
    cmcHandler = std::make_unique<CmcCommandHandler>(platform.get(), sendLineToBmc);
#endif

    platform->setSerialBridgeHandler([](const std::string& data) {
        return serialManager && serialManager->Write(data);
    });

    if (!serialManager->Open(portName, 115200)) {
        std::print("[DEBUG] Failed to open serial port, will retry in background: {}\n", portName);
        platform->logMessage("FATAL: Failed to Open Serial Port: " + portName);
#ifdef _WIN32
        OutputDebugStringW(L"[FATAL] Failed to Open Serial Port.\n");
#endif
    }
    else {
        std::print("[DEBUG] Serial Port opened successfully.\n");
        platform->logMessage("Serial Port opened successfully");
    }

    auto sendInitialInfo = [&]() {
        std::string versionStr = std::format("{}.{}.{}.{}", VERSION_MAJOR, VERSION_MINOR, VERSION_RELEASE, VERSION_BUILD);
        if (std::string(VERSION_EXTRAVERSION) == "rc") {
            versionStr += std::format("_{}{}", VERSION_EXTRAVERSION, VERSION_RC_NO);
        }
        else {
            versionStr += std::format("_{}", VERSION_EXTRAVERSION);
        }

        std::print("[DEBUG] Sending initial messages...\n");
        sendLineToBmc("appVersion, " + versionStr);
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
                std::string networkStr = std::format("network, {}, {}, {}, {}, {}, {}", iface.macAddress, iface.linkStatus, iface.ipv4, iface.ipv6, iface.dhcp, iface.name);
                sendLineToBmc(networkStr);
            }
        }

        std::print("[DEBUG] Initial messages sent.\n");
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
#ifdef _WIN32
    // One-shot admin commands for the Event Viewer source (installer/install.ps1
    // writes the same registry key; these are for dev machines).
    for (int i = 1; i < argc; i++) {
        const bool doRegister = _stricmp(argv[i], "--register-event-source") == 0;
        const bool doUnregister = _stricmp(argv[i], "--unregister-event-source") == 0;
        if (!doRegister && !doUnregister) {
            continue;
        }
        auto result = doRegister
            ? core::EventLogger::register_event_source(core::EventLogger::current_module_path())
            : core::EventLogger::unregister_event_source();
        if (!result) {
            std::print(stderr, "[ERROR] {}\n", core::describe(result.error()));
            return 1;
        }
        std::print("[DEBUG] Event source {}.\n", doRegister ? "registered" : "unregistered");
        return 0;
    }
#endif

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
    std::print("[DEBUG] Application starting. Creating platform object.\n");

    platform = createPlatform();

    std::print("[DEBUG] Checking current COM assignment for AMT Serial Port\n");
    #ifdef _WIN32

    // Top-level boundary for the AMT std::expected results: print, file-log
    // and system log.
    auto reportAmtError = [](const std::string& what, const core::PlatformError& error) {
        std::string text = std::format("{}: {}", what, core::describe(error));
        std::print("[ERROR] {}\n", text);
        platform->logMessage(text);
        core::LogError(core::kMsgIDAmt, what, error);
    };

    auto AMTInfo = GetAMTComPort();

    if (AMTInfo) {
        std::wcout << L"[DEBUG] AMT Serial Port is currently assigned to: " << AMTInfo->comPort << std::endl;
        platform->logMessage("AMT Serial Port COM assignment: " + std::string(AMTInfo->comPort.begin(), AMTInfo->comPort.end()));
    } else if (AMTInfo.error().code == core::CoreError::Code::NotFound) {
        // Normal on hardware without AMT - not an error.
        std::print("[DEBUG] No AMT Serial Port COM assignment found.\n");
        platform->logMessage("No AMT Serial Port COM assignment found.");
    } else {
        reportAmtError("Failed to read AMT Serial Port COM assignment", AMTInfo.error());
    }

    if (AMTInfo && AMTInfo->comPort == L"COM3") {
        std::print("[DEBUG] AMT Serial Port is on COM3. Attempting to disable it to free COM3 for our use.\n");
        platform->logMessage("AMT Serial Port is on COM3. Attempting to disable it.");
        if (auto disabled = disableAMTComPort(); !disabled) {
            reportAmtError("Failed to disable AMT Serial Port. COM3 may not be available", disabled.error());
            exit(1);
        }
        std::print("[DEBUG] Successfully disabled AMT Serial Port.\n");
        platform->logMessage("Successfully disabled AMT Serial Port.");

        if (auto enabled = enableAMTComPort(); !enabled) {
            // As before, carry on: COM3 is free, the AMT port just stays disabled.
            reportAmtError("Failed to re-enable AMT Serial Port after disabling", enabled.error());
        } else {
            std::print("[DEBUG] Successfully re-enabled AMT Serial Port after disabling.\n");
            platform->logMessage("Successfully re-enabled AMT Serial Port after disabling.");
            std::this_thread::sleep_for(std::chrono::seconds(2));
            auto amtPortInfo = GetAMTComPort();
            if (amtPortInfo && amtPortInfo->comPort != L"COM3") {
                std::print("[DEBUG] Verified AMT Serial Port is not back on COM3 after re-enabling.\n");
                platform->logMessage("Verified AMT Serial Port is not back on COM3 after re-enabling.");
            } else {
                std::print("[ERROR] After re-enabling, AMT Serial Port is back on COM3, falling back to manual reassignment.\n");
                platform->logMessage("After re-enabling, AMT Serial Port is back on COM3, falling back to manual reassignment.");
                if (auto reassigned = reassignComPort(); !reassigned) {
                    reportAmtError("Failed to reassign AMT Serial Port. COM3 may still be occupied", reassigned.error());
                    exit(1);
                }
                std::print("[DEBUG] Successfully reassigned AMT Serial Port to a different COM port.\n");
                platform->logMessage("Successfully reassigned AMT Serial Port to a different COM port.");
            }
        }
    }
#endif

#ifdef ENABLE_METRICS
    metricsCollector = std::make_unique<MetricsCollector>(platform.get());
#endif

    std::thread workerThread;
    std::thread hbThread;
    std::thread reThread;

    std::print("[DEBUG] Calling platform->run(). Waiting for on_start callback...\n");

    platform->run(argc, argv, 
        // on_start callback
        [&]() {
            // If we see this message, we know the service/daemon started correctly
            std::print("[DEBUG] on_start callback EXECUTED. Launching serialThread.\n");
            workerThread = std::thread(serialThread);
            hbThread = std::thread(heartbeatThread);
            reThread = std::thread(resendThread);
        },
        // on_stop callback
        [&](const std::string& stopReason) {
            std::print("[DEBUG] on_stop callback EXECUTED. Stopping serialThread. Reason: %s\n", stopReason.c_str());
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
            if (reThread.joinable()) {
                reThread.join();
            }

            if (serialManager) {
                serialManager->Close();
            }

#ifdef ENABLE_C2A
            // Cancels and joins any in-flight grace-period thread before exit.
            cmcHandler.reset();
#endif
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

    std::print("[DEBUG] platform->run() has exited. Application terminating.\n");
    return 0;
}


