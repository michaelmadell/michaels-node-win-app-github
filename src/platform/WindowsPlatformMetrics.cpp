// Performance metrics. Split in two tiers:
//   - Cheap, dependency-free trio (CPU/RAM/uptime) - always compiled, no
//     PDH/WMI needed, so C2A's "status" command works without BUILD_METRICS.
//   - Everything else (disk/network/GPU/high-RAM-procs, PDH-backed) - gated
//     behind ENABLE_METRICS since it needs PDH counters + WMI.
//
// Each *Impl returns std::expected; the public cached getters unwrap it with
// valueOrReport(), which logs a failure (once per distinct error) and returns
// the same placeholder value ("Unknown", 0, ...) the wire format has always
// carried, so the BMC protocol is unchanged.
#ifdef _WIN32
#include <windows.h>
#include "WindowsPlatform.h"
#include "../core/Logging.h"
#include "../modules/metrics/MetricMath.h"
#include <format>

static ULONGLONG FileTimeToInt64(const FILETIME& ft) {
    return ((ULONGLONG)ft.dwHighDateTime) << 32 | ((ULONGLONG)ft.dwLowDateTime);
}

namespace {

core::PlatformError metricError(const char* what, std::uint32_t err,
                                core::PlatformError::SubCode subCode = core::PlatformError::SubCode::WmiQueryFailed) {
    return core::PlatformError{
        .code = core::CoreError::Code::Internal,
        .sub_code = subCode,
        .message = std::format("{} failed", what),
        .platform_error = err,
    };
}

} // namespace

void WindowsPlatform::updateCpuTimes() {
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        // Raw counters; kernel time includes idle (see metrics::CpuTimesFromSystemTimes).
        m_previousIdleTime = FileTimeToInt64(idleTime);
        m_previousKernelTime = FileTimeToInt64(kernelTime);
        m_previousUserTime = FileTimeToInt64(userTime);
    }
}

int WindowsPlatform::getCpuUsagePercent() {
    return cpuCache_.get([this]() {
        return valueOrReport(core::kMsgIDMetrics, getCpuUsagePercentImpl(), 0, "metric:cpu", "CPU usage");
    });
}

std::expected<int, core::PlatformError> WindowsPlatform::getCpuUsagePercentImpl()
{
    // NOTE: When ENABLE_METRICS is on, this relies on updatePdhMetrics having
    // been called right before it - the previous times were updated there.
    // When ENABLE_METRICS is off, nothing else refreshes the baseline, so
    // this degrades to comparing against the value from construction time.

    FILETIME idleTime, kernelTime, userTime;
    if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        return std::unexpected(metricError("GetSystemTimes", GetLastError()));
    }

    // GetSystemTimes' kernel time includes idle time. This used to subtract
    // idle from kernel and then subtract it again from the total, in unsigned
    // arithmetic, which wrapped whenever idle exceeded busy time (i.e. under
    // ~50% load) and reported 0/100. metrics::CpuBusyPercent is the tested
    // calculation (tests/test_metrics.cpp).
    const metrics::CpuTimes previous = metrics::CpuTimesFromSystemTimes(
        m_previousIdleTime, m_previousKernelTime, m_previousUserTime);
    const metrics::CpuTimes current = metrics::CpuTimesFromSystemTimes(
        FileTimeToInt64(idleTime), FileTimeToInt64(kernelTime), FileTimeToInt64(userTime));

    // No time elapsed since the baseline reads as 0% - not an error.
    return metrics::CpuBusyPercent(previous, current);
}

int WindowsPlatform::getRamUsagePercent() {
    return ramCache_.get([this]() {
        return valueOrReport(core::kMsgIDMetrics, getRamUsagePercentImpl(), 0, "metric:ram", "RAM usage");
    });
}

std::expected<int, core::PlatformError> WindowsPlatform::getRamUsagePercentImpl() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);

    if (!GlobalMemoryStatusEx(&statex)) {
        return std::unexpected(metricError("GlobalMemoryStatusEx", GetLastError()));
    }
    return (int)statex.dwMemoryLoad;
}

std::string WindowsPlatform::getSystemUptime() {
	return uptimeCache_.get([this]() { return getSystemUptimeImpl(); });
}

// GetTickCount64 can't fail, so this stays a plain value.
std::string WindowsPlatform::getSystemUptimeImpl()
{
    // System tick count in milliseconds -> "<d>d <hh>h <mm>m <ss>s"
    return metrics::FormatUptime(GetTickCount64() / 1000);
}

#ifdef ENABLE_METRICS
#include <psapi.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <wbemidl.h>
#include <comutil.h>
#include <memory>
#include <vector>
#include <mutex>

#ifndef PDH_FMT_FLOAT
#define PDH_FMT_FLOAT 0x00000200
#endif

namespace {

// Releases a COM interface on scope exit.
struct ComReleaser {
    void operator()(IUnknown* p) const { if (p) p->Release(); }
};
template <typename T>
using ComPtr = std::unique_ptr<T, ComReleaser>;

// Clears a VARIANT on scope exit. VariantInit up front so clearing is safe
// even if IWbemClassObject::Get fails without touching it.
struct ScopedVariant {
    VARIANT v;
    ScopedVariant() { VariantInit(&v); }
    ~ScopedVariant() { VariantClear(&v); }
    ScopedVariant(const ScopedVariant&) = delete;
    ScopedVariant& operator=(const ScopedVariant&) = delete;
};

// "No data yet" statuses: the counter exists but hasn't got two samples yet,
// or has no instances right now. The metric is genuinely 0, not failing.
bool isPdhNoData(PDH_STATUS status) {
    const DWORD code = static_cast<DWORD>(status);
    return code == PDH_INVALID_DATA || code == PDH_CSTATUS_INVALID_DATA || code == PDH_NO_DATA;
}

} // namespace

std::string WindowsPlatform::getFreeDiskSpaceGB(const std::string& drivePath) {
	return diskSpaceCache_.get([this, drivePath]() {
        return valueOrReport(core::kMsgIDMetrics, getFreeDiskSpaceGBImpl(drivePath), std::string("Unknown"),
                             "metric:disk:" + drivePath, "Free disk space");
    });
}

std::expected<std::string, core::PlatformError> WindowsPlatform::getFreeDiskSpaceGBImpl(const std::string& drivePath) {
    ULARGE_INTEGER freeBytesAvailableToCaller;
    ULARGE_INTEGER totalNumberOfBytes;
    ULARGE_INTEGER totalNumberOfFreeBytes;

    std::wstring wDrivePath = L"C:\\";
    if (!drivePath.empty()) {
        std::string path = drivePath;
        if (path.size() == 2 && path[1] == ':') path += "\\";
        wDrivePath = std::wstring(path.begin(), path.end());
    }

    if (!GetDiskFreeSpaceExW(
        wDrivePath.c_str(),
        &freeBytesAvailableToCaller,
        &totalNumberOfBytes,
        &totalNumberOfFreeBytes
    ))
    {
        DWORD err = GetLastError();
        return std::unexpected(core::PlatformError{
            .code = err == ERROR_PATH_NOT_FOUND || err == ERROR_INVALID_DRIVE ? core::CoreError::Code::NotFound
                                                                              : core::CoreError::Code::Internal,
            .sub_code = core::PlatformError::SubCode::WmiQueryFailed,
            .message = std::format("GetDiskFreeSpaceEx failed for '{}'", drivePath.empty() ? "C:" : drivePath),
            .platform_error = err,
        });
    }

    return metrics::FormatGigabytes(freeBytesAvailableToCaller.QuadPart);
}

std::string WindowsPlatform::getWindowsUpdateState() {
    return windowsUpdateCache_.get([this]() {
        return valueOrReport(core::kMsgIDMetrics, getWindowsUpdateStateImpl(), std::string("Up to Date or Unknown"),
                             "metric:windowsUpdate", "Windows Update state");
    });
}

std::expected<std::string, core::PlatformError> WindowsPlatform::getWindowsUpdateStateImpl() {
    // Either key existing means a reboot is pending. A missing key is the
    // normal "nothing pending" answer; any other failure (access denied, ...)
    // means we genuinely don't know.
    static const char* const kRebootKeys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending",
    };

    for (const char* keyPath : kRebootKeys) {
        HKEY hKey;
        LONG lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ | KEY_WOW64_64KEY, &hKey);

        if (lResult == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return "Pending Reboot";
        }
        if (lResult != ERROR_FILE_NOT_FOUND) {
            return std::unexpected(core::PlatformError{
                .code = lResult == ERROR_ACCESS_DENIED ? core::CoreError::Code::PermissionDenied
                                                       : core::CoreError::Code::Internal,
                .sub_code = lResult == ERROR_ACCESS_DENIED ? core::PlatformError::SubCode::RegistryAccessDenied
                                                           : core::PlatformError::SubCode::RegistryReadFailed,
                .message = std::format("Failed to open HKLM\\{}", keyPath),
                .platform_error = static_cast<std::uint32_t>(lResult),
            });
        }
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
        if (PDH_STATUS status = PdhCollectQueryData((PDH_HQUERY)m_hQuery.get()); status != ERROR_SUCCESS) {
            reportErrorOnChange(core::kMsgIDMetrics, "metric:pdhCollect", "PDH sample collection",
                                metricError("PdhCollectQueryData", static_cast<std::uint32_t>(status)));
        } else {
            clearReportedError("metric:pdhCollect");
        }
    }
    updateCpuTimes();
}

// A NULL counter means PdhAddCounter failed at start-up, which
// initPdhCounters() has already reported - the metric reads as 0 from then on
// rather than re-reporting the same set-up failure on every poll.
std::expected<float, core::PlatformError> WindowsPlatform::readPdhCounter(PDH_HCOUNTER counter, const char* name)
{
    if (m_hQuery.get() == NULL || counter == NULL) return 0.0f;

    PDH_FMT_COUNTERVALUE value;
    // PdhCollectQueryData is called externally in updatePdhMetrics()
    PDH_STATUS status = PdhGetFormattedCounterValue(counter, PDH_FMT_FLOAT, NULL, &value);
    if (status == ERROR_SUCCESS) {
        return (float)value.doubleValue;
    }
    if (isPdhNoData(status)) {
        return 0.0f;
    }
    return std::unexpected(metricError(name, static_cast<std::uint32_t>(status)));
}

float WindowsPlatform::getDiskQueueLength() {
	return diskQueueCache_.get([this]() {
        return valueOrReport(core::kMsgIDMetrics, getDiskQueueLengthImpl(), 0.0f, "metric:diskQueue", "Disk queue length");
    });
}

std::expected<float, core::PlatformError> WindowsPlatform::getDiskQueueLengthImpl()
{
    return readPdhCounter(m_hDiskCounter, "PdhGetFormattedCounterValue (disk queue)");
}

float WindowsPlatform::getNetworkRetransRate() {
    return netRetransCache_.get([this]() {
        return valueOrReport(core::kMsgIDMetrics, getNetworkRetransRateImpl(), 0.0f, "metric:netRetrans", "TCP retransmit rate");
    });
}

std::expected<float, core::PlatformError> WindowsPlatform::getNetworkRetransRateImpl()
{
    return readPdhCounter(m_hNetRetransCounter, "PdhGetFormattedCounterValue (TCP retransmit)");
}

std::string WindowsPlatform::getGpuDriverInfo() {
	return gpuDriverCache_.get([this]() {
        return valueOrReport(core::kMsgIDMetrics, getGpuDriverInfoImpl(), std::string("GPU: Not Found."),
                             "metric:gpuDriver", "GPU driver query");
    });
}

std::expected<std::string, core::PlatformError> WindowsPlatform::getGpuDriverInfoImpl() {
    auto wmiFailed = [](const char* what, HRESULT hr) {
        return std::unexpected(metricError(what, static_cast<std::uint32_t>(hr)));
    };

    IWbemLocator* rawLoc = NULL;
    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&rawLoc
    );
    if (FAILED(hr)) return wmiFailed("CoCreateInstance(WbemLocator)", hr);
    ComPtr<IWbemLocator> pLoc(rawLoc);

    IWbemServices* rawSvc = NULL;
    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        0,
        0,
        0,
        &rawSvc
    );
    if (FAILED(hr)) return wmiFailed("IWbemLocator::ConnectServer", hr);
    ComPtr<IWbemServices> pSvc(rawSvc);

    hr = CoSetProxyBlanket(
        pSvc.get(),
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );
    if (FAILED(hr)) return wmiFailed("CoSetProxyBlanket", hr);

    IEnumWbemClassObject* rawEnumerator = NULL;
    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT Name, DriverVersion FROM Win32_VideoController"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &rawEnumerator
    );
    if (FAILED(hr)) return wmiFailed("IWbemServices::ExecQuery", hr);
    ComPtr<IEnumWbemClassObject> pEnumerator(rawEnumerator);

    for (;;) {
        IWbemClassObject* rawObj = NULL;
        ULONG uReturn = 0;
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &rawObj, &uReturn);
        if (FAILED(hr)) return wmiFailed("IEnumWbemClassObject::Next", hr);
        if (0 == uReturn) break;
        ComPtr<IWbemClassObject> pclsObj(rawObj);

        ScopedVariant vtPropName, vtPropVersion;
        HRESULT hrGet1 = pclsObj->Get(L"Name", 0, &vtPropName.v, 0, 0);
        HRESULT hrGet2 = pclsObj->Get(L"DriverVersion", 0, &vtPropVersion.v, 0, 0);

        if (hrGet1 == S_OK && hrGet2 == S_OK) {
            std::string name = WideToUtf8(vtPropName.v.bstrVal ? vtPropName.v.bstrVal : L"Unknown GPU");
            std::string version = WideToUtf8(vtPropVersion.v.bstrVal ? vtPropVersion.v.bstrVal : L"Unknown Version");

            if (name.find("Intel") != std::string::npos ||
                name.find("HD Graphics") != std::string::npos ||
                name.find("UHD Graphics") != std::string::npos ||
                name.find("Xe Graphics") != std::string::npos) {
                return std::format("GPU: {} | Driver: {}", name, version);
            }
        }
    }

    // Query worked but no Intel GPU present - a real answer, not an error.
    return "GPU: Not Found.";
}

float WindowsPlatform::getGpuUsagePercent() {
    return gpuUsageCache_.get([this]() {
        return valueOrReport(core::kMsgIDMetrics, getGpuUsagePercentImpl(), 0.0f, "metric:gpuUsage", "GPU usage");
    });
}

std::expected<float, core::PlatformError> WindowsPlatform::getGpuUsagePercentImpl() {
    // See readPdhCounter() for why a NULL counter reads as 0.
    if (m_hQuery.get() == NULL || m_hGpuTotalCounter == NULL) return 0.0f;

    DWORD bufferSize = 0;
    DWORD item_count = 0;
    float totalUsage = 0.0f;

    PDH_STATUS status = PdhGetFormattedCounterArrayW(m_hGpuTotalCounter, PDH_FMT_FLOAT, &bufferSize, &item_count, nullptr);
    if (isPdhNoData(status)) {
        return 0.0f;
    }
    if (static_cast<DWORD>(status) != PDH_MORE_DATA && status != ERROR_SUCCESS) {
        return std::unexpected(metricError("PdhGetFormattedCounterArray (GPU)", static_cast<std::uint32_t>(status)));
    }

    std::vector<BYTE> buffer(bufferSize);
    auto* items = (PDH_FMT_COUNTERVALUE_ITEM_W*)buffer.data();

    status = PdhGetFormattedCounterArrayW(m_hGpuTotalCounter, PDH_FMT_FLOAT, &bufferSize, &item_count, items);
    if (isPdhNoData(status)) {
        return 0.0f;
    }
    if (status != ERROR_SUCCESS) {
        return std::unexpected(metricError("PdhGetFormattedCounterArray (GPU)", static_cast<std::uint32_t>(status)));
    }

    for (DWORD i = 0; i < item_count; i++) {
        totalUsage += (float)items[i].FmtValue.doubleValue;
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
    return highRamProcsCache_.get([this]() {
        return valueOrReport(core::kMsgIDMetrics, getHighRamProcessesImpl(), std::string("error: EnumProcesses failed"),
                             "metric:highRamProcs", "High-RAM process scan");
    });
}

std::expected<std::string, core::PlatformError> WindowsPlatform::getHighRamProcessesImpl() {
    const ULONGLONG HIGH_RAM_THRESHOLD_MB = 500;
    const ULONGLONG HIGH_RAM_THRESHOLD_BYTES = HIGH_RAM_THRESHOLD_MB * 1024 * 1024;

    DWORD aProcesses[2048];
    DWORD cbNeeded;
    DWORD cProcesses;
    std::string result;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return std::unexpected(metricError("EnumProcesses", GetLastError()));
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < cProcesses; i++) {
        if (aProcesses[i] == 0) continue;

        // Protected/system processes refuse this - expected, just skip them.
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

                result += std::format("{}{}({})={}MB", result.empty() ? "" : "|", name, aProcesses[i], ram_mb);
            }
        }

        CloseHandle(hProcess);
    }

    return result.empty() ? "None" : result;
}

#endif // ENABLE_METRICS
#endif // _WIN32
