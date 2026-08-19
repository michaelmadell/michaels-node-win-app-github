// libFuzzer entry point for CmcCommandHandler::handle() — the parser for
// text commands arriving on the c2a serial channel (see
// src/modules/cmc/CmcCommandHandler.h). This is the richest hand-rolled
// parser in the app (token splitting, duration parsing with stol, mktime-
// based datetime parsing), so it's the highest-value fuzz target.
//
// Builds against the real, unmodified CmcCommandHandler.cpp — only Platform
// is mocked. See fuzz/build_libfuzzer.sh / fuzz/build_afl.sh to build.

#include "../src/modules/cmc/CmcCommandHandler.h"
#include "../src/core/Platform.h"

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace {

// Implements every pure virtual with a no-op / fixed value. None of these
// touch the OS, so the harness runs identically under libFuzzer and AFL++,
// on Linux and under WSL/MSYS on Windows.
class MockPlatform : public Platform {
public:
    std::vector<NetworkInterface> getNetworkInterfaces() override { return {}; }
    std::string getHostname() override { return "fuzz-host"; }
    std::string getCurrentSessionState() override { return "Active"; }
    std::string getLoggedInUser() override { return "fuzz-user"; }
    std::string getOsVersion() override { return "0"; }
    std::string getOsBuild() override { return "0"; }

    void logMessage(const std::string&) override {}

    int getCpuUsagePercent() override { return 0; }
    int getRamUsagePercent() override { return 0; }
    std::string getSystemUptime() override { return "0"; }

#ifdef ENABLE_C2A
    void showMessageDialog(const std::string&, const std::string&) override {}
    void shutdownSystem(const std::string& = "") override {}
    void restartSystem(const std::string& = "") override {}
    void lockActiveSession() override {}
    void logoffActiveSession() override {}
#endif

    int run(int, char*[], VoidCallback, StringCallback, PowerStateCallback, SessionStateCallback) override {
        return 0;
    }
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // handle() takes the payload *after* the "c2a, " prefix has already been
    // stripped by main.cpp's processIncomingCommand() — feed raw fuzzer
    // bytes straight in as that payload.
    std::string message(reinterpret_cast<const char*>(data), size);

    MockPlatform platform;
    // sendToMec_ is a no-op sink; we only care about handle() itself
    // (crashes, UB under ASan/UBSan, hangs from the scheduled-action thread).
    CmcCommandHandler handler(&platform, [](const std::string&) {});
    handler.handle(message);

    // beginScheduledAction() spawns a thread that waits on a condition_variable
    // until the parsed deadline (attacker-controlled, e.g. "shutdown, timeout,
    // 99999h"). handler's destructor sets cancelRequested_ and notifies before
    // joining, so the wait returns immediately regardless of how far out the
    // deadline is — no real sleep, no hang, even for huge durations.
    return 0;
}
