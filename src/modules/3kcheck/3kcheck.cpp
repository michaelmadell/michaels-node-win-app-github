#ifdef _WIN32

#include "3kcheck.h"
#include <intrin.h>
#include <string>
#include <array>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace {

std::string trim(const std::string& value) {
    const auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    });

    const auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) {
        return std::isspace(c) != 0;
    }).base();

    if (begin >= end) {
        return "";
    }

    return std::string(begin, end);
}

}

const std::vector<std::string> hx2kCpus = {
    "Intel(R) Core(TM) Ultra 7 165H",
    "Intel(R) Core(TM) Ultra 7 165U",
    "Intel(R) Core(TM) Ultra 9 285H"
};

CPUInfo GetCpuInfo() {
    CPUInfo info;

    std::array<int, 4> regs = {};

    // Vendor string comes from CPUID leaf 0: EBX, EDX, ECX.
    __cpuid(regs.data(), 0);
    std::array<char, 13> vendor = {};
    std::memcpy(vendor.data(), &regs[1], sizeof(int));
    std::memcpy(vendor.data() + 4, &regs[3], sizeof(int));
    std::memcpy(vendor.data() + 8, &regs[2], sizeof(int));
    info.manufacturer = trim(std::string(vendor.data()));

    // Brand string is spread across leaves 0x80000002..0x80000004.
    __cpuid(regs.data(), 0x80000000);
    const unsigned int maxExtendedLeaf = static_cast<unsigned int>(regs[0]);
    if (maxExtendedLeaf >= 0x80000004) {
        std::array<char, 49> brand = {};
        char* writePtr = brand.data();

        for (int leaf = 0x80000002; leaf <= 0x80000004; ++leaf) {
            __cpuid(regs.data(), leaf);
            std::memcpy(writePtr, regs.data(), sizeof(regs));
            writePtr += sizeof(regs);
        }

        info.model = trim(std::string(brand.data()));
    }

    const std::size_t atPos = info.model.find('@');
    if (atPos != std::string::npos) {
        info.clockspeed = trim(info.model.substr(atPos + 1));
        info.model = trim(info.model.substr(0, atPos));
    }

    return info;
}

bool IsHX2KCPU(CPUInfo* info) {
    CPUInfo cpuInfo;
    if (info != nullptr && (!info->manufacturer.empty() || !info->model.empty() || !info->clockspeed.empty())) {
        cpuInfo = *info;
    } else {
        cpuInfo = GetCpuInfo();
    }

    bool isHx2k = true;

    for (const std::string& hx2kCpu : hx2kCpus) {
        if (cpuInfo.model.find(hx2kCpu) != std::string::npos) {
            isHx2k = true;
            break;
        } else { 
            isHx2k = false;
        }
    }

    if (info) {
        *info = cpuInfo;
    }

    return isHx2k;
}


#endif