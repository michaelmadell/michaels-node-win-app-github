#pragma once

// gmock implementation of the Platform interface, for testing code that only
// talks to Platform (CmcCommandHandler, MetricsCollector, ...). Mirrors
// Platform.h's ENABLE_METRICS / ENABLE_C2A sections; tests/CMakeLists.txt
// gives the test binary the same feature defines as the app so the vtables
// match the production sources compiled into it.
//
// Use testing::NiceMock<test::MockPlatform> when a test doesn't care about
// uninteresting calls.

#include <gmock/gmock.h>

#include <string>
#include <vector>

#include "core/Platform.h"

namespace test {

class MockPlatform : public Platform {
public:
    MOCK_METHOD(std::vector<NetworkInterface>, getNetworkInterfaces, (), (override));
    MOCK_METHOD(std::string, getHostname, (), (override));
    MOCK_METHOD(std::string, getCurrentSessionState, (), (override));
    MOCK_METHOD(std::string, getLoggedInUser, (), (override));
    MOCK_METHOD(std::string, getOsVersion, (), (override));
    MOCK_METHOD(std::string, getOsBuild, (), (override));
    MOCK_METHOD(void, logMessage, (const std::string&), (override));
    MOCK_METHOD(void, setSerialBridgeHandler, (SerialBridgeHandler), (override));
    MOCK_METHOD(bool, forwardSerialBridgeMessage, (const std::string&), (override));

    MOCK_METHOD(int, getCpuUsagePercent, (), (override));
    MOCK_METHOD(int, getRamUsagePercent, (), (override));
    MOCK_METHOD(std::string, getSystemUptime, (), (override));

#ifdef ENABLE_METRICS
    MOCK_METHOD(std::string, getFreeDiskSpaceGB, (const std::string&), (override));
    MOCK_METHOD(std::string, getWindowsUpdateState, (), (override));
    MOCK_METHOD(float, getDiskQueueLength, (), (override));
    MOCK_METHOD(float, getNetworkRetransRate, (), (override));
    MOCK_METHOD(void, updatePdhMetrics, (), (override));
    MOCK_METHOD(void, invalidateMetricCaches, (), (override));
    MOCK_METHOD(std::string, getGpuDriverInfo, (), (override));
    MOCK_METHOD(float, getGpuUsagePercent, (), (override));
    MOCK_METHOD(std::string, getHighRamProcesses, (), (override));
#endif

#ifdef ENABLE_C2A
    MOCK_METHOD(void, showMessageDialog, (const std::string&, const std::string&), (override));
    MOCK_METHOD(void, shutdownSystem, (const std::string&), (override));
    MOCK_METHOD(void, restartSystem, (const std::string&), (override));
    MOCK_METHOD(void, lockActiveSession, (), (override));
    MOCK_METHOD(void, logoffActiveSession, (), (override));
#endif

    MOCK_METHOD(int, run, (int, char*[], VoidCallback, StringCallback, PowerStateCallback, SessionStateCallback),
                (override));
};

} // namespace test
