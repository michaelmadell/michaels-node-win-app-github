#pragma once

#include "../../core/SystemState.h"
#include "MetricCache.h"
#include <memory>
#include <string>
#include <functional>

// Forward declarations
class Platform;

/**
 * @brief Centralized system metrics collection
 *
 * This class encapsulates all system metric gathering logic,
 * providing a clean interface for collecting performance data,
 * system information, and resource usage statistics.
 */
class MetricsCollector {
public:
    /**
     * @brief System performance metrics
     */
    struct PerformanceMetrics {
        int cpuUsage = 0;           // CPU usage percentage (0-100)
        int ramUsage = 0;           // RAM usage percentage (0-100)
        float diskQueue = 0.0f;     // Average disk queue length
        float netRetrans = 0.0f;    // Network retransmissions per second
        std::string uptime;         // System uptime (formatted)
        std::string freeDiskSpace;  // Free disk space in GB
    };

    /**
     * @brief GPU-related metrics
     */
    struct GpuMetrics {
        std::string driverInfo;     // GPU driver information
        float usage = 0.0f;         // GPU usage percentage (0-100)
    };

    /**
     * @brief Process information metrics
     */
    struct ProcessMetrics {
        std::string highRamProcesses;  // List of high RAM usage processes
    };

    /**
     * @brief System update status
     */
    struct UpdateStatus {
        std::string state;          // Windows/system update state
    };

    /**
     * @brief Complete system metrics snapshot
     */
    struct SystemMetrics {
        PerformanceMetrics performance;
        GpuMetrics gpu;
        ProcessMetrics processes;
        UpdateStatus updates;
    };

    /**
     * @brief Construct a MetricsCollector
     * @param platform Pointer to platform implementation for metric gathering
     */
    explicit MetricsCollector(Platform* platform);
    ~MetricsCollector();

    /**
     * @brief Update performance counters (PDH/system counters)
     *
     * This should be called before collecting metrics to ensure
     * counters have fresh data. Some metrics require two samples.
     */
    void UpdateCounters();

    /**
     * @brief Collect all system metrics
     * @return Complete SystemMetrics structure
     */
    SystemMetrics CollectAll();

    /**
     * @brief Collect only performance metrics
     * @return PerformanceMetrics structure
     */
    PerformanceMetrics CollectPerformance();

    /**
     * @brief Collect only GPU metrics
     * @return GpuMetrics structure
     */
    GpuMetrics CollectGpu();

    /**
     * @brief Collect process-related metrics
     * @return ProcessMetrics structure
     */
    ProcessMetrics CollectProcesses();

    /**
     * @brief Check system update status
     * @return UpdateStatus structure
     */
    UpdateStatus CheckUpdates();

    /**
     * @brief Invalidate all metric caches
     *
     * Forces fresh collection on next request
     */
    void InvalidateCache();

    /**
     * @brief Set whether to use caching
     * @param enabled true to enable caching, false to always collect fresh
     */
    void SetCachingEnabled(bool enabled);

    /**
     * @brief Get a formatted string of all metrics
     * @return Multi-line string with all metric values
     */
    std::string GetFormattedMetrics();

    // Delete copy constructor and assignment operator
    MetricsCollector(const MetricsCollector&) = delete;
    MetricsCollector& operator=(const MetricsCollector&) = delete;

private:
    Platform* platform_;
    bool cachingEnabled_ = true;
};