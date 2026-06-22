#ifdef _WIN32

#include <string>

struct CPUInfo {
    std::string manufacturer;
    std::string model;
    std::string clockspeed;
};

CPUInfo GetCpuInfo();
bool IsHX2KCPU(CPUInfo* info);

#endif