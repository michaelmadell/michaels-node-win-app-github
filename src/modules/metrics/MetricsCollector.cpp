#include "MetricsCollector.h"
#include "../../core/Platform.h"
#include <sstream>
#include <iomanip>

MetricsCollector::MetricsCollector(Platform* platform)
    : platform_(platform) {
}

MetricsCollector::~MetricsCollector() {
}

void MetricsCollector::UpdateCounters() {
    if (platform_) {
        platform_->updatePdhMetrics();
    }
}

MetricsCollector::SystemMetrics MetricsCollector::CollectAll() {
    SystemMetrics metrics;

    metrics.performance = CollectPerformance();
    metrics.gpu = CollectGpu();
    metrics.processes = CollectProcesses();
    metrics.updates = CheckUpdates();

    return metrics;
}

MetricsCollector::PerformanceMetrics MetricsCollector::CollectPerformance() {
    PerformanceMetrics metrics;

    if (!platform_) {
        return metrics;
    }

    if (!cachingEnabled_) {
        platform_->invalidateMetricCaches();
    }

    metrics.cpuUsage = platform_->getCpuUsagePercent();
    metrics.ramUsage = platform_->getRamUsagePercent();
    metrics.diskQueue = platform_->getDiskQueueLength();
    metrics.netRetrans = platform_->getNetworkRetransRate();
    metrics.uptime = platform_->getSystemUptime();

    // Default to C: drive on Windows, root on Linux
#ifdef _WIN32
    metrics.freeDiskSpace = platform_->getFreeDiskSpaceGB("C:");
#else
    metrics.freeDiskSpace = platform_->getFreeDiskSpaceGB("/");
#endif

    return metrics;
}

MetricsCollector::GpuMetrics MetricsCollector::CollectGpu() {
    GpuMetrics metrics;

    if (!platform_) {
        return metrics;
    }

    if (!cachingEnabled_) {
        platform_->invalidateMetricCaches();
    }

    metrics.driverInfo = platform_->getGpuDriverInfo();
    metrics.usage = platform_->getGpuUsagePercent();

    return metrics;
}

MetricsCollector::ProcessMetrics MetricsCollector::CollectProcesses() {
    ProcessMetrics metrics;

    if (!platform_) {
        return metrics;
    }

    if (!cachingEnabled_) {
        platform_->invalidateMetricCaches();
    }

    metrics.highRamProcesses = platform_->getHighRamProcesses();

    return metrics;
}

MetricsCollector::UpdateStatus MetricsCollector::CheckUpdates() {
    UpdateStatus status;

    if (!platform_) {
        return status;
    }

    if (!cachingEnabled_) {
        platform_->invalidateMetricCaches();
    }

    status.state = platform_->getWindowsUpdateState();

    return status;
}

void MetricsCollector::InvalidateCache() {
    if (platform_) {
        platform_->invalidateMetricCaches();
    }
}

void MetricsCollector::SetCachingEnabled(bool enabled) {
    cachingEnabled_ = enabled;
}

std::string MetricsCollector::GetFormattedMetrics() {
    if (!platform_) {
        return "Error: No platform available";
    }

    SystemMetrics metrics = CollectAll();

    std::stringstream ss;
    ss << "=== System Metrics ===" << std::endl;
    ss << "CPU Usage:       " << metrics.performance.cpuUsage << "%" << std::endl;
    ss << "RAM Usage:       " << metrics.performance.ramUsage << "%" << std::endl;
    ss << "Disk Queue:      " << std::fixed << std::setprecision(2)
        << metrics.performance.diskQueue << std::endl;
    ss << "Net Retrans:     " << std::fixed << std::setprecision(2)
        << metrics.performance.netRetrans << " /s" << std::endl;
    ss << "Free Disk:       " << metrics.performance.freeDiskSpace << " GB" << std::endl;
    ss << "Uptime:          " << metrics.performance.uptime << std::endl;
    ss << std::endl;
    ss << "=== GPU Metrics ===" << std::endl;
    ss << "GPU Info:        " << metrics.gpu.driverInfo << std::endl;
    ss << "GPU Usage:       " << std::fixed << std::setprecision(1)
        << metrics.gpu.usage << "%" << std::endl;
    ss << std::endl;
    ss << "=== System Status ===" << std::endl;
    ss << "Update State:    " << metrics.updates.state << std::endl;
    ss << "High RAM Procs:  " << metrics.processes.highRamProcesses << std::endl;

    return ss.str();
}