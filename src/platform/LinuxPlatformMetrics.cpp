// Performance metrics. Split in two tiers:
//   - Cheap, dependency-free trio (CPU/RAM/uptime, /proc-backed) - always
//     compiled, so C2A's "status" command works without BUILD_METRICS.
//   - Everything else (disk/network/GPU/high-RAM-procs/Windows Update state)
//     - gated behind ENABLE_METRICS.
#ifdef __linux__
#include "LinuxPlatform.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>

void getCpuTimes(unsigned long long& total_time, unsigned long long& idle_time) {
    total_time = 0;
    idle_time = 0;
    std::ifstream file("/proc/stat");
    std::string line;
    if (std::getline(file, line)) {
        if (line.substr(0, 3) == "cpu") {
            unsigned long long user, nice, system, iowait, irq, softirq, steal, guest;
            std::stringstream ss(line.substr(4));
            if (ss >> user >> nice >> system >> idle_time >> iowait >> irq >> softirq >> steal >> guest) {
                total_time = user + nice + system + idle_time + iowait + irq + softirq + steal + guest;
            }
        }
    }
}

std::string LinuxPlatform::getSystemUptime() {
    std::ifstream file("/proc/uptime");
    double uptime_seconds;
    if (file >> uptime_seconds) {
        long long seconds = (long long)uptime_seconds;
        long long minutes = seconds / 60;
        long long hours = minutes / 60;
        long long days = hours / 24;

        seconds %= 60;
        minutes %= 60;
        hours %= 24;

        std::stringstream ss;
        ss << days << "d "
           << std::setw(2) << std::setfill('0') << hours << "h "
           << std::setw(2) << std::setfill('0') << minutes << "m "
           << std::setw(2) << std::setfill('0') << seconds << "s";
        return ss.str();
    }
    return "Unknown";
}

int LinuxPlatform::getCpuUsagePercent() {
    unsigned long long total_time, idle_time;
    getCpuTimes(total_time, idle_time);

    unsigned long long total_diff = total_time - m_prev_total_time;
    unsigned long long idle_diff = idle_time - m_prev_idle_time;

    m_prev_total_time = total_time;
    m_prev_idle_time = idle_time;

    if (total_diff == 0) return 0;

    int usage = static_cast<int>(std::round((1.0 - (double)idle_diff / total_diff) * 100.0));
    return std::max(0, std::min(100, usage));
}

int LinuxPlatform::getRamUsagePercent() {
    long long total_mem = 0;
    long long free_mem = 0;

    std::ifstream file("/proc/meminfo");
    std::string line;

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string key;
        long long value;
        std::string unit;

        if (ss >> key >> value >> unit) {
            if (key == "MemTotal:") {
                total_mem = value;
            } else if (key == "MemAvailable:") {
                free_mem = value;
            }
        }
    }
    if (total_mem > 0) {
        long long used_mem = total_mem - free_mem;
        int usage_percent = static_cast<int>(std::round((double)used_mem / total_mem * 100.0));
        return std::max(0, std::min(100, usage_percent));
    }
    return 0;
}

#ifdef ENABLE_METRICS
#include <cctype>
#include <cstdio>
#include <syslog.h>
#include <sys/statvfs.h>

static unsigned long long getTcpValue(int index) {
    std::string cmd = "cat /proc/net/snmp | grep -A 1 'Tcp:' | tail -n 1 | awk '{print $" + std::to_string(index) + "}' 2>/dev/null";
    std::string result = executeCommand(cmd);

    unsigned long long value = 0;
    try {
        if (!result.empty()) {
            value = std::stoull(result);
        }
    } catch (const std::exception& e) {
        // Handle any conversion errors if necessary
        syslog(LOG_ERR, "Error converting TCP value: %s", e.what());
    }
    return value;
}

std::string LinuxPlatform::getFreeDiskSpaceGB(const std::string& drivePath) {
    struct statvfs vfs;
    // Use the root directory if drivePath is empty or irrelevant (like a Windows drive letter)
    std::string path = (drivePath.empty() || (drivePath.size() == 2 && drivePath[1] == ':')) ? "/" : drivePath;

    if (statvfs(path.c_str(), &vfs) != 0) {
        return "Error";
    }

    // Calculation: (Free blocks available to non-super user) * (Fundamental block size)
    unsigned long long free_bytes = (unsigned long long)vfs.f_bavail * vfs.f_frsize;

    // Convert bytes to GB and format to 1 decimal place
    double freeGB = (double)free_bytes / (1024.0 * 1024.0 * 1024.0);
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << freeGB;
    return ss.str();
}

float LinuxPlatform::getDiskQueueLength() {
    // Sum the "in_flight" (field 12) column of /proc/diskstats across whole-disk
    // block devices only (skip partitions and loop/ram devices) as an analog to
    // Windows' "Avg. Disk Queue Length" counter.
    std::ifstream file("/proc/diskstats");
    std::string line;
    float total_in_flight = 0.0f;

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string major, minor, devName;
        unsigned long long fields[10] = {0};

        ss >> major >> minor >> devName;
        for (int i = 0; i < 10; i++) {
            if (!(ss >> fields[i])) break;
        }

        if (devName.rfind("loop", 0) == 0 || devName.rfind("ram", 0) == 0) {
            continue;
        }

        // Skip partitions: sdXN, vdXN, hdXN have a trailing digit after the
        // letters; nvme/mmcblk whole-disks already end in a digit, so only
        // skip those with a partition suffix ("p<N>" or "n<N>p<N>").
        bool isPartition = false;
        if (devName.rfind("nvme", 0) == 0 || devName.rfind("mmcblk", 0) == 0) {
            isPartition = (devName.find('p', devName.find_first_of("0123456789")) != std::string::npos);
        } else {
            isPartition = !devName.empty() && std::isdigit(static_cast<unsigned char>(devName.back()));
        }
        if (isPartition) {
            continue;
        }

        // fields[8] is in_flight (the 12th whitespace-separated field overall:
        // major, minor, name, then 9 read/write stat fields before in_flight).
        total_in_flight += (float)fields[8];
    }

    return total_in_flight;
}

void LinuxPlatform::updatePdhMetrics() {
    m_prev_tcp_out = getTcpValue(11);
    m_prev_tcp_retrans = getTcpValue(12);
}

float LinuxPlatform::getNetworkRetransRate() {
    unsigned long long current_tcp_out = getTcpValue(11);
    unsigned long long current_tcp_retrans = getTcpValue(12);

    unsigned long long out_diff = current_tcp_out - m_prev_tcp_out;
    unsigned long long retrans_diff = current_tcp_retrans - m_prev_tcp_retrans;

    if (out_diff == 0 || out_diff < retrans_diff) {
        return 0.0f;
    }

    float retrans_rate = (float)retrans_diff / (float)out_diff * 100.0f;
    return retrans_rate;
}

std::string LinuxPlatform::getGpuDriverInfo() {
    // 1. Try to get NVIDIA dedicated GPU driver info (relies on nvidia-smi being installed)
    std::string driver_info = executeCommand("nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null");
    if (!driver_info.empty()) {
        return "NVIDIA Driver: " + driver_info;
    }

    // 2. Check for Intel Integrated Graphics using lsmod (more fundamental than lspci)
    std::string i915_module = executeCommand("lsmod | grep i915");
    if (!i915_module.empty()) {
        // Module is loaded, try to get the driver version
        std::string i915_version = executeCommand("modinfo i915 | grep -E '^version:' | awk '{print $2}'");
        if (!i915_version.empty()) {
            return "Intel Integrated Graphics (i915 Kernel Driver v" + i915_version + ")";
        }
        return "Intel Integrated Graphics Detected (Driver info N/A)";
    }

    // 3. Check for AMD
    std::string amdgpu_module = executeCommand("lsmod | grep amdgpu");
    if (!amdgpu_module.empty()) {
         return "AMD/Radeon GPU Detected (amdgpu Kernel Driver)";
    }


    return "Unknown/Unsupported GPU Driver";
}

float LinuxPlatform::getGpuUsagePercent() {
    // 1. Query NVIDIA GPU usage
    std::string usage_str = executeCommand(
        "nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>/dev/null | awk '{sum+=$1} END {print sum/NR}'"
    );

    if (!usage_str.empty()) {
        try {
            return std::stof(usage_str);
        } catch (...) {
            return 0.0f;
        }
    }

    // 2. AMD: amdgpu exposes a direct busy-percent sysfs attribute.
    std::string amdgpu_module = executeCommand("lsmod | grep amdgpu");
    if (!amdgpu_module.empty()) {
        std::string busy = executeCommand(
            "cat /sys/class/drm/card*/device/gpu_busy_percent 2>/dev/null | head -n 1");
        if (!busy.empty()) {
            try {
                return std::stof(busy);
            } catch (...) {
                return 0.0f;
            }
        }
    }

    // 3. Intel integrated graphics: query via intel_gpu_top (igt-gpu-tools, a required
    // package for the .deb build). Capture one JSON sample and read the Render/3D engine
    // busy percentage.
    std::string intel_busy = executeCommand(
        "timeout 2 intel_gpu_top -J -s 1000 -o - 2>/dev/null "
        "| grep -A3 '\"Render/3D' | grep -m1 '\"busy\"' | grep -oE '[0-9]+\\.?[0-9]*'");
    if (!intel_busy.empty()) {
        try {
            return std::stof(intel_busy);
        } catch (...) {
            return 0.0f;
        }
    }

    logMessage("GPU usage (percent) requested. Returning 0.0f: no NVIDIA/AMD/Intel usage source available.");
    return 0.0f;
}
std::string LinuxPlatform::getHighRamProcesses() {
    std::string cmd = "ps ax --sort=-rss -o pid,user,rss,comm --no-headers | head -n 5";
    std::string result = executeCommand(cmd);

    if (result.empty()) {
        return "None or Command Failed";
    }

    // Replace newlines with a separator for better JSON/String transport
    std::replace(result.begin(), result.end(), '\n', '|');
    return result;
}

std::string LinuxPlatform::getWindowsUpdateState() {
    const char* cmd = "apt list --upgradable 2>/dev/null | grep -c 'upgradable'";
    char buffer[128] = {0};
    int package_count = 0;

    FILE* pipe = popen(cmd, "r");
    if (pipe) {
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            try {
            package_count = std::stoi(buffer);
            } catch (const std::invalid_argument& e) {
                logMessage("Invalid argument when parsing package count: " + std::string(e.what()));
            } catch (const std::out_of_range& e) {
                logMessage("Out of range error when parsing package count: " + std::string(e.what()));
            }
        }
        pclose(pipe);
    }

    if (package_count > 0) {
        return "Pending Upgrades (" + std::to_string(package_count) + ")";
    }

    std::ifstream reboot_file("/var/run/reboot-required");
    if (reboot_file.good()) {
        return "Reboot Required";
    }

    return "Up to Date";
}

#endif // ENABLE_METRICS
#endif // __linux__
