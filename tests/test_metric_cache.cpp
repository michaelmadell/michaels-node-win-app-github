#include <gtest/gtest.h>
#include "modules/metrics/MetricCache.h"

TEST(MetricCacheTest, FirstGetAlwaysComputes) {
    MetricCache<int> cache(60);
    int callCount = 0;
    int value = cache.get([&]() { ++callCount; return 42; });
    EXPECT_EQ(value, 42);
    EXPECT_EQ(callCount, 1);
}

TEST(MetricCacheTest, SecondGetWithinTtlReusesCachedValue) {
    MetricCache<int> cache(60);
    cache.get([]() { return 1; });

    int callCount = 0;
    int value = cache.get([&]() { ++callCount; return 2; });

    EXPECT_EQ(value, 1);      // still the first cached value
    EXPECT_EQ(callCount, 0);  // second compute function never invoked
}

TEST(MetricCacheTest, InvalidateForcesRecompute) {
    MetricCache<int> cache(60);
    cache.get([]() { return 1; });
    cache.invalidate();

    int callCount = 0;
    int value = cache.get([&]() { ++callCount; return 2; });

    EXPECT_EQ(value, 2);
    EXPECT_EQ(callCount, 1);
}

TEST(MetricCacheTest, ZeroTtlAlwaysRecomputes) {
    MetricCache<int> cache(0);
    int callCount = 0;
    cache.get([&]() { ++callCount; return 1; });
    cache.get([&]() { ++callCount; return 2; });
    EXPECT_EQ(callCount, 2);
}

TEST(MetricCacheTest, IsValidReflectsCacheState) {
    MetricCache<int> cache(60);
    EXPECT_FALSE(cache.isValid());

    cache.get([]() { return 1; });
    EXPECT_TRUE(cache.isValid());

    cache.invalidate();
    EXPECT_FALSE(cache.isValid());
}

TEST(MetricCacheTest, SetTtlUpdatesReportedTtl) {
    MetricCache<int> cache(60);
    EXPECT_EQ(cache.getTtlSeconds(), 60);

    cache.setTtl(120);
    EXPECT_EQ(cache.getTtlSeconds(), 120);
}

TEST(MetricCacheTest, WorksWithStringValues) {
    MetricCache<std::string> cache(60);
    std::string value = cache.get([]() { return std::string("hello"); });
    EXPECT_EQ(value, "hello");
}
