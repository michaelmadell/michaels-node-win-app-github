#pragma once

// Pure metric calculations shared by the Windows and Linux platform code,
// split out of it so they're unit-testable without the OS (see
// tests/test_metrics.cpp). Header-only, no platform includes.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <format>
#include <istream>
#include <optional>
#include <sstream>
#include <string>

namespace metrics {

// Cumulative CPU time counters (any unit, as long as both use the same one).
// `total` includes `idle`.
struct CpuTimes {
    std::uint64_t total = 0;
    std::uint64_t idle = 0;
};

// Busy percentage (0-100, rounded) between two CpuTimes samples. Returns 0
// when no time elapsed, and clamps if the counters went backwards or idle
// grew faster than total (counter wrap/reset).
inline int CpuBusyPercent(const CpuTimes& previous, const CpuTimes& current) {
    if (current.total <= previous.total) {
        return 0;
    }
    const std::uint64_t totalDelta = current.total - previous.total;
    const std::uint64_t idleDelta = current.idle >= previous.idle ? current.idle - previous.idle : 0;
    if (idleDelta >= totalDelta) {
        return 0;
    }
    const double busy = 100.0 * static_cast<double>(totalDelta - idleDelta) / static_cast<double>(totalDelta);
    return std::clamp(static_cast<int>(std::lround(busy)), 0, 100);
}

// Windows GetSystemTimes(): the kernel time it reports INCLUDES idle time, so
// total = kernel + user (not kernel - idle + user).
constexpr CpuTimes CpuTimesFromSystemTimes(std::uint64_t idle, std::uint64_t kernel, std::uint64_t user) noexcept {
    return CpuTimes{ kernel + user, idle };
}

// Linux: parses the aggregate "cpu  user nice system idle iowait irq softirq
// steal guest ..." line of /proc/stat, keeping the agent's long-standing
// definition: total = sum of the first nine fields, idle = the idle field
// alone (iowait counts as busy).
inline std::optional<CpuTimes> ParseProcStatCpuLine(const std::string& line) {
    if (line.rfind("cpu ", 0) != 0) {
        return std::nullopt;
    }
    std::istringstream fields(line.substr(4));
    std::uint64_t user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0, guest = 0;
    if (!(fields >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest)) {
        return std::nullopt;
    }
    return CpuTimes{ user + nice + system + idle + iowait + irq + softirq + steal + guest, idle };
}

// Linux: RAM in use (0-100, rounded) from /proc/meminfo content, as
// (MemTotal - MemAvailable) / MemTotal. Returns nullopt if MemTotal is
// missing or zero.
inline std::optional<int> MemInfoUsedPercent(std::istream& meminfo) {
    std::uint64_t total = 0;
    std::uint64_t available = 0;
    std::string line;
    while (std::getline(meminfo, line)) {
        std::istringstream fields(line);
        std::string key;
        std::uint64_t value = 0;
        if (!(fields >> key >> value)) {
            continue;
        }
        if (key == "MemTotal:") {
            total = value;
        } else if (key == "MemAvailable:") {
            available = value;
        }
    }
    if (total == 0) {
        return std::nullopt;
    }
    const std::uint64_t used = available >= total ? 0 : total - available;
    const double percent = 100.0 * static_cast<double>(used) / static_cast<double>(total);
    return std::clamp(static_cast<int>(std::lround(percent)), 0, 100);
}

// "<d>d <hh>h <mm>m <ss>s" - the uptime format both platforms send.
inline std::string FormatUptime(std::uint64_t totalSeconds) {
    const std::uint64_t days = totalSeconds / 86400;
    const std::uint64_t hours = (totalSeconds / 3600) % 24;
    const std::uint64_t minutes = (totalSeconds / 60) % 60;
    const std::uint64_t seconds = totalSeconds % 60;
    return std::format("{}d {:02}h {:02}m {:02}s", days, hours, minutes, seconds);
}

// Bytes -> "<GiB with one decimal>", the free-disk-space wire format.
inline std::string FormatGigabytes(std::uint64_t bytes) {
    return std::format("{:.1f}", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
}

} // namespace metrics
