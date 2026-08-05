#pragma once

#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <chrono>

#include "../../core/Platform.h"

/**
 * @brief Dispatches CMC (chassis-to-system) commands received from the MEC
 * over the c2a serial channel.
 *
 * Shared by both the Windows and Linux entry points so the two don't drift
 * apart. The serial link is a fixed PCB trace to the MEC chip with no
 * user-accessible endpoint, so anything arriving here is treated as trusted
 * chassis input, not untrusted external input.
 */
class CmcCommandHandler {
public:
    using SendFn = std::function<void(const std::string&)>;

    CmcCommandHandler(Platform* platform, SendFn sendToMec);
    ~CmcCommandHandler();

    CmcCommandHandler(const CmcCommandHandler&) = delete;
    CmcCommandHandler& operator=(const CmcCommandHandler&) = delete;

    /**
     * @brief Handle one c2a payload (the text after the "c2a, " prefix).
     */
    void handle(const std::string& message);

private:
    Platform* platform_;
    SendFn sendToMec_;

    std::mutex mutex_;
    std::condition_variable cv_;
    std::thread pendingThread_;
    bool actionPending_ = false;
    bool cancelRequested_ = false;
    std::string pendingVerb_;

    static constexpr std::chrono::seconds kDefaultGracePeriod{15};

    void beginImmediateAction(const std::string& verb, const std::string& reason);
    void beginScheduledAction(const std::string& verb,
        std::chrono::system_clock::time_point deadline, const std::string& reason);
    void runScheduledAction(std::string verb,
        std::chrono::system_clock::time_point deadline, std::string reason);
    void cancelPending();
    void invokeAction(const std::string& verb, const std::string& reason);
};
