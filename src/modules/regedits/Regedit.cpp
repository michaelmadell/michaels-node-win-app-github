// src/modules/regedits/Regedit.cpp
#ifdef _WIN32
#include "Regedit.h"
#include <windows.h>

Regedit::Regedit(Logger logger) : log_(std::move(logger)) {}

bool Regedit::splitPath(const std::string& path, std::string& subKey, std::string& valueName) const {
    size_t last = path.find_last_of('\\');
    if (last == std::string::npos) {
        log_("ERROR: Invalid registry path (no backslash): " + path);
        return false;
    }
    subKey    = path.substr(0, last);
    valueName = path.substr(last + 1);
    return true;
}

bool Regedit::Read(const std::string& path, std::string& outValue, HKEY root) {
    std::string subKey, valueName;
    if (!splitPath(path, subKey, valueName)) return false;

    HKEY hKey = nullptr;
    if (RegOpenKeyExA(root, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        log_("ERROR: Failed to open registry key: " + subKey);
        return false;
    }

    DWORD bufferSize = 0;
    DWORD type = 0;
    // First call: get required buffer size
    LONG result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, nullptr, &bufferSize);
    if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || bufferSize == 0) {
        RegCloseKey(hKey);
        log_("ERROR: Failed to query value size or not a string type: " + valueName);
        return false;
    }
    std::string buffer(bufferSize, '\0');
    result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type,
        reinterpret_cast<LPBYTE>(buffer.data()), &bufferSize);
    RegCloseKey(hKey);
    if (result != ERROR_SUCCESS) {
        log_("ERROR: Failed to read registry value: " + valueName);
        return false;
    }
    // bufferSize includes the null terminator; strip it for the std::string
    if (!buffer.empty() && buffer.back() == '\0') buffer.pop_back();
    outValue = buffer;
    log_("Registry Read OK: " + subKey + "\\" + valueName);
    return true;
}

// ReadBinary exists for REG_BINARY entries like the COM Name Arbiter ComDB bitmask.
bool Regedit::ReadBinary(const std::string& path, std::vector<BYTE>& outData, HKEY root) {
    std::string subKey, valueName;
    if (!splitPath(path, subKey, valueName)) return false;

    HKEY hKey = nullptr;
    if (RegOpenKeyExA(root, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        log_("ERROR: Failed to open registry key: " + subKey);
        return false;
    }

    DWORD dataSize = 0;
    DWORD type = 0;
    // First call: get required buffer size
    LONG result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, nullptr, &dataSize);
    if (result != ERROR_SUCCESS || type != REG_BINARY || dataSize == 0) {
        RegCloseKey(hKey);
        log_("ERROR: Failed to query binary value size: " + valueName);
        return false;
    }

    outData.resize(dataSize);
    result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, outData.data(), &dataSize);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        log_("ERROR: Failed to read binary registry value: " + valueName);
        return false;
    }
    log_("Registry ReadBinary OK: " + subKey + "\\" + valueName);
    return true;
}

bool Regedit::Write(const std::string& path, const std::string& value, HKEY root) {
    std::string subKey, valueName;
    if (!splitPath(path, subKey, valueName)) return false;

    HKEY hKey = nullptr;
    // REPLACED: each branch was re-calling RegCreateKeyExA instead of reusing the result
    /*
    if (RegCreateKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_INVALID_FUNCTION) {
        platform_->logMessage("ERROR: Invalid Function Call");
        return false;
    }
    else if (RegCreateKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_FILE_NOT_FOUND) {
        platform_->logMessage("ERROR: File Not Found");
        return false;
    }
    else if (RegCreateKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_PATH_NOT_FOUND) {
        platform_->logMessage("ERROR: Path Not Found");
        return false;
    }
    else if (RegCreateKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_ACCESS_DENIED) {
        platform_->logMessage("ERROR: Access Denied");
        return false;
    }
    else if (RegCreateKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_CANTWRITE) {
        platform_->logMessage("ERROR: Can't Write to Registry");
        return false;
    }
    else if (RegCreateKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_KEY_DELETED) {
        platform_->logMessage("ERROR: Illegal operation attempted on a registry key that has been marked for deletion.");
        return false;
    }
    else if (RegCreateKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_NO_MORE_ITEMS) {
        platform_->logMessage("ERROR: No more items can be added to the registry.");
        return false;
    }
    else if (RegCreateKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        platform_->logMessage("ERROR: Failed to create/open registry key");
        return false;
    }
    */
    LSTATUS status = RegCreateKeyExA(root, subKey.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    if (status != ERROR_SUCCESS) {
        switch (status) {
        case ERROR_INVALID_FUNCTION: log_("ERROR: Invalid function call opening: " + subKey); break;
        case ERROR_FILE_NOT_FOUND:   log_("ERROR: Key not found: "               + subKey); break;
        case ERROR_PATH_NOT_FOUND:   log_("ERROR: Path not found: "              + subKey); break;
        case ERROR_ACCESS_DENIED:    log_("ERROR: Access denied: "               + subKey); break;
        case ERROR_CANTWRITE:        log_("ERROR: Cannot write to: "             + subKey); break;
        case ERROR_KEY_DELETED:      log_("ERROR: Key marked for deletion: "     + subKey); break;
        case ERROR_NO_MORE_ITEMS:    log_("ERROR: Registry full, cannot add: "   + subKey); break;
        default:                     log_("ERROR: Failed to create/open: "       + subKey); break;
        }
        return false;
    }

    LONG result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ,
        (const BYTE*)value.c_str(), (DWORD)(value.size() + 1));
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        log_("ERROR: Failed to write registry value: " + valueName);
        return false;
    }
    log_("Registry Write OK: " + subKey + "\\" + valueName + " = " + value);
    return true;
}

// WriteBinary exists for REG_BINARY entries like the COM Name Arbiter ComDB bitmask.
bool Regedit::WriteBinary(const std::string& path, const std::vector<BYTE>& data, HKEY root) {
    std::string subKey, valueName;
    if (!splitPath(path, subKey, valueName)) return false;

    HKEY hKey = nullptr;
    LSTATUS status = RegCreateKeyExA(root, subKey.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    if (status != ERROR_SUCCESS) {
        log_("ERROR: Failed to open/create key for binary write: " + subKey);
        return false;
    }

    LONG result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_BINARY,
        data.data(), (DWORD)data.size());
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        log_("ERROR: Failed to write binary registry value: " + valueName);
        return false;
    }
    log_("Registry WriteBinary OK: " + subKey + "\\" + valueName);
    return true;
}

bool Regedit::Create(const std::string& path, const std::string& value, HKEY root) {
    return Write(path, value, root);
}

bool Regedit::Delete(const std::string& path, HKEY root) {
    std::string subKey, valueName;
    if (!splitPath(path, subKey, valueName)) return false;

    HKEY hKey = nullptr;
    if (RegOpenKeyExA(root, subKey.c_str(), 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        log_("ERROR: Failed to open registry key for delete: " + subKey);
        return false;
    }
    LONG result = RegDeleteValueA(hKey, valueName.c_str());
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        log_("ERROR: Failed to delete registry value: " + valueName);
        return false;
    }
    log_("Registry Delete OK: " + subKey + "\\" + valueName);
    return true;
}

#endif // _WIN32
