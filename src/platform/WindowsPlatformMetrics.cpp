// Performance metrics. Split in two tiers:
//   - Cheap, dependency-free trio (CPU/RAM/uptime) - always compiled, no
//     PDH/WMI needed, so C2A's "status" command works without BUILD_METRICS.
//   - Everything else (disk/network/GPU/high-RAM-procs, PDH-backed) - gated
//     behind ENABLE_METRICS since it needs PDH counters + WMI.
#ifdef _WIN32
#include <windows.h>
#include "WindowsPlatform.h"
#include <iomanip>
#include <sstream>

static ULONGLONG FileTimeToInt64(const FILETIME& ft) {
    return ((ULONGLONG)ft.dwHighDateTime) << 32 | ((ULONGLONG)ft.dwLowDateTime);
}

void WindowsPlatform::updateCpuTimes() {
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        m_previousIdleTime = FileTimeToInt64(idleTime);
        m_previousKernelTime = FileTimeToInt64(kernelTime) - m_previousIdleTime;
        m_previousUserTime = FileTimeToInt64(userTime);
    }
}

int WindowsPlatform::getCpuUsagePercent() {
    return cpuCache_.get([this]() {return getCpuUsagePercentImpl();  });
}

int WindowsPlatform::getCpuUsagePercentImpl()
{
    // NOTE: When ENABLE_METRICS is on, this relies on updatePdhMetrics having
    // been called right before it - the previous times were updated there.
    // When ENABLE_METRICS is off, nothing else refreshes the baseline, so
    // this degrades to comparing against the value from construction time.

    FILETIME idleTime, kernelTime, userTime;
    if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        return 0;
    }

    ULONGLONG currentIdleTime = FileTimeToInt64(idleTime);
    ULONGLONG currentKernelTime = FileTimeToInt64(kernelTime) - currentIdleTime;
    ULONGLONG currentUserTime = FileTimeToInt64(userTime);

    ULONGLONG idleTimeDelta = currentIdleTime - m_previousIdleTime;
    ULONGLONG kernelTimeDelta = currentKernelTime - m_previousKernelTime;
    ULONGLONG userTimeDelta = currentUserTime - m_previousUserTime;

    ULONGLONG totalTimeDelta = kernelTimeDelta + userTimeDelta;

    if (totalTimeDelta == 0) {
        return 0;
    }

    // CPU Usage = (Total Time - Idle Time) / Total Time * 100
    int cpuUsage = (int)((totalTimeDelta - idleTimeDelta) * 100 / totalTimeDelta);

    if (cpuUsage < 0) return 0;
    if (cpuUsage > 100) return 100;

    return cpuUsage;
}

int WindowsPlatform::getRamUsagePercent() {
    return ramCache_.get([this]() { return getRamUsagePercentImpl(); });
}

int WindowsPlatform::getRamUsagePercentImpl() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);

    if (GlobalMemoryStatusEx(&statex)) {
        return (int)statex.dwMemoryLoad;
    }

    return 0;
}

std::string WindowsPlatform::getSystemUptime() {
	return uptimeCache_.get([this]() { return getSystemUptimeImpl(); });
}

std::string WindowsPlatform::getSystemUptimeImpl()
{
    // Get the system tick count in milliseconds
    ULONGLONG ms = GetTickCount64();

    // Convert milliseconds to days, hours, minutes, seconds
    ULONGLONG seconds = ms / 1000;
    ULONGLONG minutes = seconds / 60;
    ULONGLONG hours = minutes / 60;
    ULONGLONG days = hours / 24;

    seconds %= 60;
    minutes %= 60;
    hours %= 24;

    std::stringstream ss;
    ss << days << "d ";
    ss << std::setw(2) << std::setfill('0') << hours << "h ";
    ss << std::setw(2) << std::setfill('0') << minutes << "m ";
    ss << std::setw(2) << std::setfill('0') << seconds << "s";

    return ss.str();
}

#ifdef ENABLE_METRICS
#include <psapi.h>
#include <pdh.h>
#include <wbemidl.h>
#include <comutil.h>
#include <vector>
#include <mutex>

#ifndef PDH_FMT_FLOAT
#define PDH_FMT_FLOAT 0x00000200
#endif

#ifndef PDH_MORE_DATA
#define PDH_MORE_DATA ((PDH_STATUS)0x800007D2)
#endif

std::string WindowsPlatform::getFreeDiskSpaceGB(const std::string& drivePath) {
	return diskSpaceCache_.get([this, drivePath]() { return getFreeDiskSpaceGBImpl(drivePath); });
}

std::string WindowsPlatform::getFreeDiskSpaceGBImpl(const std::string& drivePath) {
    ULARGE_INTEGER freeBytesAvailableToCaller;
    ULARGE_INTEGER totalNumberOfBytes;
    ULARGE_INTEGER totalNumberOfFreeBytes;

    std::wstring wDrivePath = L"C:\\";
    if (!drivePath.empty()) {
        std::string path = drivePath;
        if (path.size() == 2 && path[1] == ':') path += "\\";
        wDrivePath = std::wstring(path.begin(), path.end());
    }

    if (GetDiskFreeSpaceExW(
        wDrivePath.c_str(),
        &freeBytesAvailableToCaller,
        &totalNumberOfBytes,
        &totalNumberOfFreeBytes
    ))
    {
        double freeGB = (double)freeBytesAvailableToCaller.QuadPart / (1024.0 * 1024.0 * 1024.0);
        std::stringstream ss;
        ss << std::fixed << std::setprecision(1) << freeGB;
        return ss.str();
    }
    return "Unknown";
}

std::string WindowsPlatform::getWindowsUpdateState() {
    return windowsUpdateCache_.get([this]() { return getWindowsUpdateStateImpl(); });
}

std::string WindowsPlatform::getWindowsUpdateStateImpl() {
    HKEY hKey;

    const REGSAM samDesired = KEY_READ | KEY_WOW64_64KEY;

    LONG lResult = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired",
        0,
        samDesired,
        &hKey
    );

    if (lResult == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "Pending Reboot";
    }

    lResult = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending",
        0,
        samDesired,
        &hKey
    );

    if (lResult == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "Pending Reboot";
    }

    return "Up to Date or Unknown";
}

void WindowsPlatform::invalidateMetricCaches() {
    cpuCache_.invalidate();
    ramCache_.invalidate();
    diskSpaceCache_.invalidate();
    windowsUpdateCache_.invalidate();
    diskQueueCache_.invalidate();
    netRetransCache_.invalidate();
    uptimeCache_.invalidate();
    gpuDriverCache_.invalidate();
    gpuUsageCache_.invalidate();
    highRamProcsCache_.invalidate();
}

void WindowsPlatform::updatePdhMetrics() {
	std::lock_guard<std::mutex> lock(platformMutex_);

    if (m_hQuery.get()) {
        PdhCollectQueryData((PDH_HQUERY)m_hQuery.get());
    }
    updateCpuTimes();
}

float WindowsPlatform::getDiskQueueLength() {
	return diskQueueCache_.get([this]() { return getDiskQueueLengthImpl(); });
}

float WindowsPlatform::getDiskQueueLengthImpl()
{
    if (m_hQuery.get() == NULL || m_hDiskCounter == NULL) return 0.0f;

    PDH_FMT_COUNTERVALUE value;
    // PdhCollectQueryData is now called externally in updatePdhMetrics()
    if (PdhGetFormattedCounterValue(m_hDiskCounter, PDH_FMT_FLOAT, NULL, &value) == ERROR_SUCCESS) {
        return (float)value.doubleValue;
    }
    return 0.0f;
}

float WindowsPlatform::getNetworkRetransRate() {
    return netRetransCache_.get([this]() { return getNetworkRetransRateImpl(); });
}

float WindowsPlatform::getNetworkRetransRateImpl()
{
    if (m_hQuery.get() == NULL || m_hNetRetransCounter == NULL) return 0.0f;

    PDH_FMT_COUNTERVALUE value;
    // PdhCollectQueryData is now called externally in updatePdhMetrics()
    if (PdhGetFormattedCounterValue(m_hNetRetransCounter, PDH_FMT_FLOAT, NULL, &value) == ERROR_SUCCESS) {
        return (float)value.doubleValue;
    }
    return 0.0f;
}

std::string WindowsPlatform::getGpuDriverInfo() {
	return gpuDriverCache_.get([this]() { return getGpuDriverInfoImpl(); });
}

std::string WindowsPlatform::getGpuDriverInfoImpl() {
    std::string result = "GPU: Not Found.";
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc
    );

    if (FAILED(hr)) goto cleanup;

    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        0,
        0,
        0,
        &pSvc
    );

    if (FAILED(hr)) goto cleanup;

    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hr)) goto cleanup;

    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT Name, DriverVersion FROM Win32_VideoController"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) goto cleanup;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) break;

        VARIANT vtPropName, vtPropVersion;
        HRESULT hrGet1 = pclsObj->Get(L"Name", 0, &vtPropName, 0, 0);
        HRESULT hrGet2 = pclsObj->Get(L"DriverVersion", 0, &vtPropVersion, 0, 0);

        if (hrGet1 == S_OK && hrGet2 == S_OK) {
            std::string name = WideToUtf8(vtPropName.bstrVal ? vtPropName.bstrVal : L"Unknown GPU");
            std::string version = WideToUtf8(vtPropVersion.bstrVal ? vtPropVersion.bstrVal : L"Unknown Version");

            if (name.find("Intel") != std::string::npos ||
                name.find("HD Graphics") != std::string::npos ||
                name.find("UHD Graphics") != std::string::npos ||
                name.find("Xe Graphics") != std::string::npos) {
                result = "GPU: " + name + " | Driver: " + version;
                VariantClear(&vtPropName);
                VariantClear(&vtPropVersion);
                pclsObj->Release();
                pclsObj = NULL;
                goto cleanup;
            }
        }
        VariantClear(&vtPropName);
        VariantClear(&vtPropVersion);
        pclsObj->Release();
        pclsObj = NULL;
    }

cleanup:
    if (pclsObj) pclsObj->Release();
    if (pEnumerator) pEnumerator->Release();
    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();

    return result;
}

float WindowsPlatform::getGpuUsagePercent() {
    return gpuUsageCache_.get([this]() { return getGpuUsagePercentImpl(); });
}

float WindowsPlatform::getGpuUsagePercentImpl() {
    if (m_hQuery.get() == NULL || m_hGpuTotalCounter == NULL) return 0.0f;

    PDH_FMT_COUNTERVALUE_ITEM_W* items = nullptr;
    DWORD bufferSize = 0;
    DWORD item_count = 0;
    float totalUsage = 0.0f;
    PDH_STATUS status;

    status = PdhGetFormattedCounterArrayW(m_hGpuTotalCounter, PDH_FMT_FLOAT, &bufferSize, &item_count, nullptr);

    if (status != PDH_MORE_DATA && status != ERROR_SUCCESS) {
        return 0.0f;
    }

    std::vector<BYTE> buffer(bufferSize);
    items = (PDH_FMT_COUNTERVALUE_ITEM_W*)buffer.data();

    status = PdhGetFormattedCounterArrayW(m_hGpuTotalCounter, PDH_FMT_FLOAT, &bufferSize, &item_count, items);

    if (status == ERROR_SUCCESS) {
        for (DWORD i = 0; i < item_count; i++) {
            totalUsage += (float)items[i].FmtValue.doubleValue;
        }
    }

    return (totalUsage > 100.0f ? 100.0f : totalUsage);
}

std::string WindowsPlatform::getProcessName(HANDLE hProcess) {
    wchar_t szProcessPath[MAX_PATH];
    DWORD pathSize = MAX_PATH;

    if (QueryFullProcessImageNameW(hProcess, 0, szProcessPath, &pathSize)) {
        std::wstring wsPath = szProcessPath;
        size_t lastSlash = wsPath.find_last_of(L"\\");
        if (lastSlash != std::wstring::npos) {
            return WideToUtf8(wsPath.substr(lastSlash + 1));
        }

        return WideToUtf8(wsPath);
    }

    TCHAR szProcessName[MAX_PATH] = TEXT("unknown");
    DWORD bufferSize = sizeof(szProcessName) / sizeof(TCHAR);

    if (GetModuleBaseName(hProcess, NULL, szProcessName, bufferSize)) {
        return WideToUtf8(std::wstring(reinterpret_cast<const wchar_t*>(szProcessName)));
    }

    return "unknown";
}

std::string WindowsPlatform::getHighRamProcesses() {
    return highRamProcsCache_.get([this]() { return getHighRamProcessesImpl(); });
}

std::string WindowsPlatform::getHighRamProcessesImpl() {
    const ULONGLONG HIGH_RAM_THRESHOLD_MB = 500;
    const ULONGLONG HIGH_RAM_THRESHOLD_BYTES = HIGH_RAM_THRESHOLD_MB * 1024 * 1024;

    DWORD aProcesses[2048];
    DWORD cbNeeded;
    DWORD cProcesses;
    std::stringstream ss;
    bool first = true;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return "error: EnumProcesses failed";
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < cProcesses; i++) {
        if (aProcesses[i] == 0) continue;

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            aProcesses[i]
        );

        if (hProcess == NULL) continue;

        PROCESS_MEMORY_COUNTERS pmc;

        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            if (pmc.PagefileUsage >= HIGH_RAM_THRESHOLD_BYTES) {
                std::string name = getProcessName(hProcess);

                ULONGLONG ram_mb = pmc.PagefileUsage / (1024 * 1024);

                if (!first) {
                    ss << "|";
                }

                ss << name << "(" << aProcesses[i] << ")=" << ram_mb  << "MB";
                first = false;
            }
        }

        CloseHandle(hProcess);
    }

    std::string result = ss.str();
    return result.empty() ? "None" : result;
}

#endif // ENABLE_METRICS
#endif // _WIN32
