// Metric calculations (src/modules/metrics/MetricMath.h), MetricCache TTL
// behaviour driven by a mock clock, and - when built with metrics -
// MetricsCollector against a mock Platform.

#include <gtest/gtest.h>

#include <chrono>
#include <sstream>
#include <string>

#include "modules/metrics/MetricCache.h"
#include "modules/metrics/MetricMath.h"
#include "test_helpers.h"

#ifdef ENABLE_METRICS
#include "modules/metrics/MetricsCollector.h"
#include "mock_platform.h"
#endif

using metrics::CpuTimes;

// --- CPU ---------------------------------------------------------------------------

TEST(CpuBusyPercent, FractionOfElapsedTimeNotIdle) {
    EXPECT_EQ(metrics::CpuBusyPercent({ 1000, 900 }, { 2000, 1650 }), 25);   // 250 busy of 1000
    EXPECT_EQ(metrics::CpuBusyPercent({ 0, 0 }, { 1000, 1000 }), 0);         // fully idle
    EXPECT_EQ(metrics::CpuBusyPercent({ 0, 0 }, { 1000, 0 }), 100);          // fully busy
}

TEST(CpuBusyPercent, RoundsToNearest) {
    EXPECT_EQ(metrics::CpuBusyPercent({ 0, 0 }, { 1000, 994 }), 1);   // 0.6% -> 1
    EXPECT_EQ(metrics::CpuBusyPercent({ 0, 0 }, { 1000, 996 }), 0);   // 0.4% -> 0
    EXPECT_EQ(metrics::CpuBusyPercent({ 0, 0 }, { 3, 2 }), 33);
}

TEST(CpuBusyPercent, NoElapsedTimeOrCounterResetIsZero) {
    EXPECT_EQ(metrics::CpuBusyPercent({ 500, 100 }, { 500, 100 }), 0);   // nothing elapsed
    EXPECT_EQ(metrics::CpuBusyPercent({ 500, 100 }, { 400, 50 }), 0);    // counters went backwards
    EXPECT_EQ(metrics::CpuBusyPercent({ 0, 0 }, { 100, 200 }), 0);       // idle grew faster than total
}

TEST(CpuTimesFromSystemTimes, KernelTimeAlreadyIncludesIdle) {
    // GetSystemTimes: kernel (incl. idle) = 950, user = 50, idle = 900 ->
    // 1000 total, 10% busy. The pre-MetricMath Windows code subtracted idle
    // twice in unsigned arithmetic and reported 0/100 for loads like this.
    CpuTimes previous = metrics::CpuTimesFromSystemTimes(0, 0, 0);
    CpuTimes current = metrics::CpuTimesFromSystemTimes(900, 950, 50);
    EXPECT_EQ(current.total, 1000u);
    EXPECT_EQ(current.idle, 900u);
    EXPECT_EQ(metrics::CpuBusyPercent(previous, current), 10);
}

TEST(CpuTimesFromSystemTimes, TypicalLowLoadSample) {
    // 4 cores idle 95% of a 1 s window (100-ns units): previously garbage.
    CpuTimes previous = metrics::CpuTimesFromSystemTimes(10'000'000, 12'000'000, 3'000'000);
    CpuTimes current = metrics::CpuTimesFromSystemTimes(10'000'000 + 38'000'000,
                                                        12'000'000 + 39'000'000,
                                                        3'000'000 + 1'000'000);
    EXPECT_EQ(metrics::CpuBusyPercent(previous, current), 5);
}

TEST(ProcStat, ParsesTheAggregateCpuLine) {
    auto times = metrics::ParseProcStatCpuLine("cpu  4705 150 1120 16250 520 30 40 0 10 0");
    ASSERT_TRUE(times);
    EXPECT_EQ(times->total, 4705u + 150 + 1120 + 16250 + 520 + 30 + 40 + 0 + 10);
    EXPECT_EQ(times->idle, 16250u);  // iowait counts as busy (long-standing definition)
}

TEST(ProcStat, RejectsOtherLinesAndShortInput) {
    EXPECT_FALSE(metrics::ParseProcStatCpuLine("cpu0 1 2 3 4 5 6 7 8 9"));  // per-core line
    EXPECT_FALSE(metrics::ParseProcStatCpuLine("intr 12345"));
    EXPECT_FALSE(metrics::ParseProcStatCpuLine("cpu  1 2 3"));              // too few fields
    EXPECT_FALSE(metrics::ParseProcStatCpuLine(""));
}

TEST(ProcStat, TwoSamplesGiveUsage) {
    auto first = metrics::ParseProcStatCpuLine("cpu  100 0 100 800 0 0 0 0 0");
    auto second = metrics::ParseProcStatCpuLine("cpu  250 0 150 1400 0 0 0 0 0");
    ASSERT_TRUE(first && second);
    // delta total 800, delta idle 600 -> 25%
    EXPECT_EQ(metrics::CpuBusyPercent(*first, *second), 25);
}

// --- RAM ---------------------------------------------------------------------------

TEST(MemInfo, UsedIsTotalMinusAvailable) {
    std::istringstream meminfo(
        "MemTotal:       16000000 kB\n"
        "MemFree:         1000000 kB\n"
        "MemAvailable:   12000000 kB\n"
        "Buffers:          200000 kB\n");
    EXPECT_EQ(metrics::MemInfoUsedPercent(meminfo), 25);
}

TEST(MemInfo, OrderIndependentAndRounded) {
    std::istringstream meminfo("MemAvailable: 2 kB\nMemTotal: 3 kB\n");
    EXPECT_EQ(metrics::MemInfoUsedPercent(meminfo), 33);
}

TEST(MemInfo, MissingTotalIsNoValue) {
    std::istringstream empty("");
    EXPECT_FALSE(metrics::MemInfoUsedPercent(empty));
    std::istringstream noTotal("MemAvailable: 100 kB\n");
    EXPECT_FALSE(metrics::MemInfoUsedPercent(noTotal));
}

TEST(MemInfo, MissingAvailableMeansFullyUsedAndOverflowClamps) {
    std::istringstream noAvailable("MemTotal: 100 kB\n");
    EXPECT_EQ(metrics::MemInfoUsedPercent(noAvailable), 100);
    std::istringstream bogus("MemTotal: 100 kB\nMemAvailable: 500 kB\n");
    EXPECT_EQ(metrics::MemInfoUsedPercent(bogus), 0);
}

// --- formatting --------------------------------------------------------------------

TEST(FormatUptime, DaysHoursMinutesSeconds) {
    EXPECT_EQ(metrics::FormatUptime(0), "0d 00h 00m 00s");
    EXPECT_EQ(metrics::FormatUptime(59), "0d 00h 00m 59s");
    EXPECT_EQ(metrics::FormatUptime(3661), "0d 01h 01m 01s");
    EXPECT_EQ(metrics::FormatUptime(2 * 86400 + 4 * 3600 + 13 * 60 + 9), "2d 04h 13m 09s");
    EXPECT_EQ(metrics::FormatUptime(400 * 86400ull), "400d 00h 00m 00s");
}

TEST(FormatGigabytes, OneDecimalGiB) {
    EXPECT_EQ(metrics::FormatGigabytes(0), "0.0");
    EXPECT_EQ(metrics::FormatGigabytes(1024ull * 1024 * 1024), "1.0");
    EXPECT_EQ(metrics::FormatGigabytes(1536ull * 1024 * 1024), "1.5");
    EXPECT_EQ(metrics::FormatGigabytes(500ull * 1024 * 1024 * 1024), "500.0");
}

// --- MetricCache with a controllable clock -------------------------------------------

class MetricCacheClockTest : public ::testing::Test {
protected:
    void SetUp() override { test::MockClock::reset(); }
};

TEST_F(MetricCacheClockTest, RecomputesExactlyWhenTtlElapses) {
    MetricCache<int, test::MockClock> cache(60);
    int computes = 0;
    auto compute = [&] { return ++computes; };

    EXPECT_EQ(cache.get(compute), 1);
    test::MockClock::advance(std::chrono::seconds(59));
    EXPECT_EQ(cache.get(compute), 1);
    EXPECT_TRUE(cache.isValid());

    test::MockClock::advance(std::chrono::seconds(1));  // exactly the TTL
    EXPECT_FALSE(cache.isValid());
    EXPECT_EQ(cache.get(compute), 2);
    EXPECT_EQ(computes, 2);
}

TEST_F(MetricCacheClockTest, ZeroTtlAlwaysRecomputes) {
    MetricCache<int, test::MockClock> cache(0);
    int computes = 0;
    cache.get([&] { return ++computes; });
    cache.get([&] { return ++computes; });
    EXPECT_EQ(computes, 2);
}

TEST_F(MetricCacheClockTest, SetTtlAppliesToTheExistingValue) {
    MetricCache<std::string, test::MockClock> cache(3600);
    cache.get([] { return std::string("first"); });
    test::MockClock::advance(std::chrono::seconds(30));
    cache.setTtl(10);
    EXPECT_EQ(cache.getTtlSeconds(), 10);
    EXPECT_EQ(cache.get([] { return std::string("second"); }), "second");
}

TEST_F(MetricCacheClockTest, ProductionTtlsMatchTheirIntent) {
    // Frequently-changing metrics are never cached; expensive ones are.
    EXPECT_EQ(CacheDurations::CPU_USAGE, 0);
    EXPECT_EQ(CacheDurations::RAM_USAGE, 0);
    EXPECT_GT(CacheDurations::GPU_DRIVER_INFO, CacheDurations::WINDOWS_UPDATE);
    EXPECT_GT(CacheDurations::WINDOWS_UPDATE, CacheDurations::FREE_DISK_SPACE);
}

// --- MetricsCollector against a mock Platform ----------------------------------------

#ifdef ENABLE_METRICS
using ::testing::NiceMock;
using ::testing::Return;

class MetricsCollectorTest : public ::testing::Test {
protected:
    NiceMock<test::MockPlatform> platform;

    void SetUp() override {
        ON_CALL(platform, getCpuUsagePercent()).WillByDefault(Return(37));
        ON_CALL(platform, getRamUsagePercent()).WillByDefault(Return(64));
        ON_CALL(platform, getDiskQueueLength()).WillByDefault(Return(0.5f));
        ON_CALL(platform, getNetworkRetransRate()).WillByDefault(Return(1.25f));
        ON_CALL(platform, getSystemUptime()).WillByDefault(Return("1d 02h 03m 04s"));
        ON_CALL(platform, getFreeDiskSpaceGB(::testing::_)).WillByDefault(Return("123.4"));
        ON_CALL(platform, getGpuDriverInfo()).WillByDefault(Return("GPU: Intel UHD | Driver: 31.0"));
        ON_CALL(platform, getGpuUsagePercent()).WillByDefault(Return(12.5f));
        ON_CALL(platform, getHighRamProcesses()).WillByDefault(Return("None"));
        ON_CALL(platform, getWindowsUpdateState()).WillByDefault(Return("Up to Date or Unknown"));
    }
};

TEST_F(MetricsCollectorTest, CollectAllMapsEveryPlatformValue) {
    MetricsCollector collector(&platform);
    auto m = collector.CollectAll();
    EXPECT_EQ(m.performance.cpuUsage, 37);
    EXPECT_EQ(m.performance.ramUsage, 64);
    EXPECT_FLOAT_EQ(m.performance.diskQueue, 0.5f);
    EXPECT_FLOAT_EQ(m.performance.netRetrans, 1.25f);
    EXPECT_EQ(m.performance.uptime, "1d 02h 03m 04s");
    EXPECT_EQ(m.performance.freeDiskSpace, "123.4");
    EXPECT_EQ(m.gpu.driverInfo, "GPU: Intel UHD | Driver: 31.0");
    EXPECT_FLOAT_EQ(m.gpu.usage, 12.5f);
    EXPECT_EQ(m.processes.highRamProcesses, "None");
    EXPECT_EQ(m.updates.state, "Up to Date or Unknown");
}

TEST_F(MetricsCollectorTest, AsksForTheSystemDrive) {
#ifdef _WIN32
    EXPECT_CALL(platform, getFreeDiskSpaceGB("C:")).WillOnce(Return("1.0"));
#else
    EXPECT_CALL(platform, getFreeDiskSpaceGB("/")).WillOnce(Return("1.0"));
#endif
    MetricsCollector collector(&platform);
    collector.CollectPerformance();
}

TEST_F(MetricsCollectorTest, UpdateCountersSamplesThePlatform) {
    EXPECT_CALL(platform, updatePdhMetrics()).Times(1);
    MetricsCollector collector(&platform);
    collector.UpdateCounters();
}

TEST_F(MetricsCollectorTest, CachingDisabledInvalidatesBeforeEachCollection) {
    MetricsCollector collector(&platform);
    EXPECT_CALL(platform, invalidateMetricCaches()).Times(0);
    collector.CollectPerformance();
    ::testing::Mock::VerifyAndClearExpectations(&platform);

    collector.SetCachingEnabled(false);
    EXPECT_CALL(platform, invalidateMetricCaches()).Times(4);  // perf, gpu, processes, updates
    collector.CollectAll();
}

TEST_F(MetricsCollectorTest, FormattedReportContainsTheValues) {
    MetricsCollector collector(&platform);
    std::string report = collector.GetFormattedMetrics();
    EXPECT_NE(report.find("CPU Usage:       37%"), std::string::npos) << report;
    EXPECT_NE(report.find("Disk Queue:      0.50"), std::string::npos) << report;
    EXPECT_NE(report.find("GPU Usage:       12.5%"), std::string::npos) << report;
}

TEST(MetricsCollectorNoPlatform, ReturnsDefaultsInsteadOfCrashing) {
    MetricsCollector collector(nullptr);
    auto m = collector.CollectAll();
    EXPECT_EQ(m.performance.cpuUsage, 0);
    EXPECT_TRUE(m.gpu.driverInfo.empty());
    EXPECT_EQ(collector.GetFormattedMetrics(), "Error: No platform available");
    collector.UpdateCounters();   // no-op
    collector.InvalidateCache();  // no-op
}
#endif
