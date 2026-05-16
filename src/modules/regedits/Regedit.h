// src/modules/regedits/Regedit.h
#pragma once
#ifdef _WIN32
#include <windows.h>
#include <string>
#include <vector>
#include <functional>

// Windows registry read/write helpers. Used by AMT port management and
// any other Windows-only code that needs clean open/check/use/close semantics.
class Regedit {
public:
    using Logger = std::function<void(const std::string&)>;
    explicit Regedit(Logger logger);
    ~Regedit() = default;

    // Read a REG_SZ value. outValue receives the string on success.
    bool Read(const std::string& path, std::string& outValue, HKEY root = HKEY_CURRENT_USER);
    // ReadBinary exists for REG_BINARY entries like the COM Name Arbiter ComDB bitmask.
    bool ReadBinary(const std::string& path, std::vector<BYTE>& outData, HKEY root = HKEY_CURRENT_USER);
    bool Write(const std::string& path, const std::string& value, HKEY root = HKEY_CURRENT_USER);
    // WriteBinary exists for REG_BINARY entries like the COM Name Arbiter ComDB bitmask.
    bool WriteBinary(const std::string& path, const std::vector<BYTE>& data, HKEY root = HKEY_CURRENT_USER);
    bool Create(const std::string& path, const std::string& value, HKEY root = HKEY_CURRENT_USER);
    bool Delete(const std::string& path, HKEY root = HKEY_CURRENT_USER);

    Regedit(const Regedit&) = delete;
    Regedit& operator=(const Regedit&) = delete;

private:
    Logger log_;
    // Split "Key\\SubKey\\ValueName" at the last backslash into (subKey, valueName).
    bool splitPath(const std::string& path, std::string& subKey, std::string& valueName) const;
};

#endif // _WIN32
