// System information getters: hostname, logged-in user, OS version/build,
// network interfaces, message dialogs, and file logging. Split out of
// WindowsPlatform.cpp to keep that file to just the service lifecycle.
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "WindowsPlatform.h"
#include <iphlpapi.h>
#include <wtsapi32.h>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <print>
#include <format>
#include <memory>
#include <type_traits>
#include "../core/Logging.h"
#include "../version.h"

std::string WideToUtf8(const std::wstring &wstr)
{
    if (wstr.empty())
        return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

typedef LONG(WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

static const wchar_t* const LOG_DIR_PATH = L"C:\\ProgramData\\ahk";
static const wchar_t* const LOG_FILE_PATH = L"C:\\ProgramData\\ahk\\node-win-app.log";

static bool IsErrorOrWarning(const std::string& message) {
    std::string upper = message;
    std::transform(upper.begin(), upper.end(), upper.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return upper.find("ERROR") != std::string::npos ||
           upper.find("WARNING") != std::string::npos ||
           upper.find("FATAL") != std::string::npos;
}

// Implementations for the core virtual methods
std::vector<NetworkInterface> WindowsPlatform::getNetworkInterfaces()
{
    std::vector<NetworkInterface> interfaces;
    ULONG bufferSize = 0;

    // First call to get the required buffer size
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufferSize);

    if (bufferSize == 0)
    {
        return interfaces;
    }

    std::vector<BYTE> buffer(bufferSize);
    IP_ADAPTER_ADDRESSES *pAdapterAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());

    // Second call to get the actual data
    DWORD result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAdapterAddresses, &bufferSize);

    if (result == NO_ERROR)
    {
        for (IP_ADAPTER_ADDRESSES* pAdapter = pAdapterAddresses; pAdapter; pAdapter = pAdapter->Next)
        {
            // We only care about Ethernet interfaces
            if (pAdapter->IfType != IF_TYPE_ETHERNET_CSMACD)
            {
                continue;
            }

            NetworkInterface iface;

            // Format MAC address
            for (ULONG i = 0; i < pAdapter->PhysicalAddressLength; i++)
            {
                iface.macAddress += std::format("{}{:02X}", i != 0 ? ":" : "", pAdapter->PhysicalAddress[i]);
            }

            if (iface.macAddress.compare(0, 8, "00:17:FD") == 0 || // Amulet Hotkey MAC
                iface.macAddress.compare(0, 8, "00:07:32") == 0 || // AAEON MAC
                iface.macAddress.compare(0, 8, "00:13:95") == 0)   // Congatec MAC
            {
                iface.name = pAdapter->FriendlyName ? WideToUtf8(pAdapter->FriendlyName) : "Unknown";
                iface.linkStatus = (pAdapter->OperStatus == IfOperStatusUp) ? "up" : "down";
                iface.dhcp = (pAdapter->Flags & IP_ADAPTER_DHCP_ENABLED) ? "dhcp" : "static";
                iface.ipv4 = "none";
                iface.ipv6 = "none";

                // Get IP addresses
                for (IP_ADAPTER_UNICAST_ADDRESS* pUnicast = pAdapter->FirstUnicastAddress; pUnicast; pUnicast = pUnicast->Next)
                {
                    char ipBuffer[INET6_ADDRSTRLEN] = { 0 };
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                    {
                        sockaddr_in* pSockAddr = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                        inet_ntop(AF_INET, &(pSockAddr->sin_addr), ipBuffer, sizeof(ipBuffer));
                        iface.ipv4 = ipBuffer;
                    }
                    else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
                    {
                        sockaddr_in6* pSockAddr6 = reinterpret_cast<sockaddr_in6*>(pUnicast->Address.lpSockaddr);
                        inet_ntop(AF_INET6, &(pSockAddr6->sin6_addr), ipBuffer, sizeof(ipBuffer));
                        iface.ipv6 = ipBuffer;
                    }
                }
                interfaces.push_back(iface);
            }
        }
    }
    return interfaces;
}

std::string WindowsPlatform::getHostname()
{
    char hostnameChar[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD hostnameLen = sizeof(hostnameChar);
    if (GetComputerNameA(hostnameChar, &hostnameLen))
    {
        return std::string(hostnameChar);
    }
    return "Unknown Host";
}

std::string WindowsPlatform::getLoggedInUser()
{
    PWTS_SESSION_INFOW pSessionInfo = NULL;
    DWORD sessionCount = 0;
    std::string username = "none";

    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount))
    {
        for (DWORD i = 0; i < sessionCount; ++i)
        {
            if (pSessionInfo[i].State == WTSActive)
            {
                LPWSTR pBuffer = NULL;
                DWORD bytesReturned = 0;
                if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, pSessionInfo[i].SessionId, WTSUserName, &pBuffer, &bytesReturned) && pBuffer)
                {
                    username = WideToUtf8(std::wstring(pBuffer));
                    WTSFreeMemory(pBuffer);
                    break; // Found the first active user
                }
            }
        }
        WTSFreeMemory(pSessionInfo);
    }
    return username;
}

namespace {

const char* const kCurrentVersionKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

// RtlGetVersion reports the real OS version (GetVersionEx lies to
// unmanifested apps). The error's message is a short tag ("ntdll.dll",
// "RtlGetVersion", "RtlGetVersion failed") that getOsBuild() reports on the
// wire as "Unknown Build (<tag>)", unchanged from before the migration.
std::expected<RTL_OSVERSIONINFOW, core::PlatformError> queryRtlVersion()
{
    auto versionError = [](const char* tag, std::uint32_t err) {
        return std::unexpected(core::PlatformError{
            .code = core::CoreError::Code::Internal,
            .sub_code = core::PlatformError::SubCode::VersionQueryFailed,
            .message = tag,
            .platform_error = err,
        });
    };

    HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
    if (!hMod) return versionError("ntdll.dll", GetLastError());

    // Via void(*)() - the generic function-pointer type - so -Wcast-function-type
    // accepts the FARPROC -> RtlGetVersionPtr conversion.
    auto fn = reinterpret_cast<RtlGetVersionPtr>(
        reinterpret_cast<void (*)()>(::GetProcAddress(hMod, "RtlGetVersion")));
    if (!fn) return versionError("RtlGetVersion", GetLastError());

    RTL_OSVERSIONINFOW rovi{};
    rovi.dwOSVersionInfoSize = sizeof(rovi);
    if (LONG status = fn(&rovi); status != 0) {
        return versionError("RtlGetVersion failed", static_cast<std::uint32_t>(status));
    }
    return rovi;
}

std::string formatVersion(const RTL_OSVERSIONINFOW& rovi)
{
    return std::format("{}.{}.{}", rovi.dwMajorVersion, rovi.dwMinorVersion, rovi.dwBuildNumber);
}

core::PlatformError registryError(LSTATUS status, std::string message)
{
    const bool denied = status == ERROR_ACCESS_DENIED;
    return core::PlatformError{
        .code = status == ERROR_FILE_NOT_FOUND ? core::CoreError::Code::NotFound
              : denied ? core::CoreError::Code::PermissionDenied
              : core::CoreError::Code::Internal,
        .sub_code = denied ? core::PlatformError::SubCode::RegistryAccessDenied
                           : core::PlatformError::SubCode::RegistryReadFailed,
        .message = std::move(message),
        .platform_error = static_cast<std::uint32_t>(status),
    };
}

// Closes the HKEY on scope exit.
struct RegKeyCloser {
    void operator()(HKEY key) const { RegCloseKey(key); }
};
using UniqueRegKey = std::unique_ptr<std::remove_pointer_t<HKEY>, RegKeyCloser>;

std::expected<UniqueRegKey, core::PlatformError> openHklmKey(const char* subKey)
{
    HKEY key = nullptr;
    LSTATUS status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &key);
    if (status != ERROR_SUCCESS) {
        return std::unexpected(registryError(status, std::format("Failed to open HKLM\\{}", subKey)));
    }
    return UniqueRegKey(key);
}

// Reads a REG_SZ value. RegGetValue guarantees the result is null-terminated,
// which a raw RegQueryValueEx into a char[] does not.
std::expected<std::string, core::PlatformError> readRegString(HKEY key, const char* valueName)
{
    char buffer[256] = {};
    DWORD size = sizeof(buffer);
    LSTATUS status = RegGetValueA(key, nullptr, valueName, RRF_RT_REG_SZ, nullptr, buffer, &size);
    if (status != ERROR_SUCCESS) {
        return std::unexpected(registryError(status, std::format("Failed to read registry value '{}'", valueName)));
    }
    return std::string(buffer);
}

} // namespace

std::string WindowsPlatform::getOsVersion()
{
    // First, get the raw version info to check the build number
    auto rovi = queryRtlVersion();
    if (!rovi) {
        reportErrorOnChange(core::kMsgIDPlatform, "getOsVersion", "OS version query", rovi.error());
        return "Unknown Windows Version";
    }

    // Now, query the registry for the friendly name
    auto key = openHklmKey(kCurrentVersionKey);
    if (!key) {
        reportErrorOnChange(core::kMsgIDPlatform, "getOsVersion", "OS version query", key.error());
        return formatVersion(*rovi);  // fall back to the build number
    }

    auto productName = readRegString(key->get(), "ProductName");
    if (!productName) {
        reportErrorOnChange(core::kMsgIDPlatform, "getOsVersion", "OS version query", productName.error());
        return "Unknown Windows Version";
    }
    clearReportedError("getOsVersion");

    std::string finalProductName = *productName;

    // Correct the product name if the build number indicates Windows 11
    if (rovi->dwBuildNumber >= 22000) {
        size_t pos = finalProductName.find("10");
        if (pos != std::string::npos) {
            finalProductName.replace(pos, 2, "11");
        }
    }

    // DisplayVersion (e.g. "23H2") doesn't exist on older builds - not an error.
    if (auto displayVersion = readRegString(key->get(), "DisplayVersion")) {
        return finalProductName + " " + *displayVersion;
    }
    return finalProductName;
}

std::string WindowsPlatform::getOsBuild()
{
    auto rovi = queryRtlVersion();
    if (!rovi) {
        reportErrorOnChange(core::kMsgIDPlatform, "getOsBuild", "OS build query", rovi.error());
        return std::format("Unknown Build ({})", rovi.error().message);
    }
    clearReportedError("getOsBuild");

    // Major.Minor.Build
    return formatVersion(*rovi);
}

#ifdef ENABLE_C2A
void WindowsPlatform::showMessageDialog(const std::string& title, const std::string& message) {
    std::wstring wTitle(title.begin(), title.end());
    std::wstring wMessage(message.begin(), message.end());

    DWORD mySession = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &mySession);

    if (mySession == 0) {
        // Running as a Session 0 service — route the dialog to the active
        // user session via WTSSendMessage so it appears on their desktop.
        DWORD sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId != 0xFFFFFFFF) {
            DWORD response = 0;
            WTSSendMessageW(
                WTS_CURRENT_SERVER_HANDLE,
                sessionId,
                const_cast<LPWSTR>(wTitle.c_str()),
                static_cast<DWORD>(wTitle.size() * sizeof(wchar_t)),
                const_cast<LPWSTR>(wMessage.c_str()),
                static_cast<DWORD>(wMessage.size() * sizeof(wchar_t)),
                MB_OK | MB_ICONINFORMATION,
                0,
                &response,
                FALSE   // non-blocking — don't hold up the serial thread
            );
            return;
        }
    }

    // Interactive / user-session fallback
    MessageBoxW(NULL, wMessage.c_str(), wTitle.c_str(), MB_OK | MB_ICONINFORMATION);
}
#endif

void WindowsPlatform::logMessage(const std::string &message)
{
    if (std::string(VERSION_EXTRAVERSION) != "rc" && !IsErrorOrWarning(message)) {
        return;
    }

    const size_t MAX_LOG_SIZE = 10 * 1024 * 1024;

    std::ifstream checkSize(LOG_FILE_PATH, std::ios::ate | std::ios::binary);
    if (checkSize.is_open()) {
        size_t fileSize = checkSize.tellg();
        checkSize.close();

        if (fileSize >= MAX_LOG_SIZE) {
            std::wstring backupPath = std::wstring(LOG_FILE_PATH) + L".old";
            DeleteFileW(backupPath.c_str());
            MoveFileW(LOG_FILE_PATH, backupPath.c_str());
        }
    }

    DWORD fileAttr = GetFileAttributesW(LOG_DIR_PATH);
    if (fileAttr == INVALID_FILE_ATTRIBUTES)
    {
        CreateDirectoryW(LOG_DIR_PATH, NULL);
    }

    std::ofstream logFile(LOG_FILE_PATH, std::ios::app);
    if (logFile.is_open())
    {
        SYSTEMTIME time;
        GetLocalTime(&time);

        logFile << "[" << time.wYear << "-"
            << std::setfill('0') << std::setw(2) << time.wMonth << "-"
            << std::setfill('0') << std::setw(2) << time.wDay << " "
            << std::setfill('0') << std::setw(2) << time.wHour << ":"
            << std::setfill('0') << std::setw(2) << time.wMinute << ":"
            << std::setfill('0') << std::setw(2) << time.wSecond << "."
            << std::setfill('0') << std::setw(3) << time.wMilliseconds << "] "
            << message << std::endl;
        logFile.close();
    }
}

#endif // _WIN32
