#ifdef _WIN32

#include "Regedit.h"
#include "../../platform/WindowsPlatform.h"
#include <windows.h>

Regedit::Regedit(WindowsPlatform* platform) : platform_(platform) {
}

Regedit::~Regedit() {
}

bool Regedit::Read(std::string path, std::string value) {
	HKEY hKey;

	std::string subKey, valueName;
	size_t lastBackslash = path.find_last_of('\\');
	if (lastBackslash == std::string::npos) {
		platform_->logMessage("ERROR: Invalid registry path format");
		return false;
	}
	subKey = path.substr(0, lastBackslash);
	valueName = path.substr(lastBackslash + 1);
	if (RegOpenKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
		platform_->logMessage("ERROR: Failed to open registry key");
		return false;
	}
	char buffer[512];
	DWORD bufferSize = sizeof(buffer);
	DWORD type;
	LONG result = RegQueryValueExA(hKey, valueName.c_str(), NULL, &type, (LPBYTE)buffer, &bufferSize);
	RegCloseKey(hKey);
	if (result != ERROR_SUCCESS || type != REG_SZ) {
		platform_->logMessage("ERROR: Failed to read registry value or value is not a string");
		return false;
	}
	platform_->logMessage("Registry Read Success: " + std::string(buffer));
	return true;
}

bool Regedit::Write(std::string path, std::string value, DWORD type) {
	HKEY hKey;
	std::string subKey, valueName;
	size_t lastBackslash = path.find_last_of('\\');
	if (lastBackslash == std::string::npos) {
		platform_->logMessage("ERROR: Invalid registry path format");
		return false;
	}
	subKey = path.substr(0, lastBackslash);
	valueName = path.substr(lastBackslash + 1);

	LPSTR type = std::to_string(type).c_str();

	if (!type) {
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
		LONG result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ, (const BYTE*)value.c_str(), (DWORD)(value.size() + 1));
		RegCloseKey(hKey);
		if (result != ERROR_SUCCESS) {
			platform_->logMessage("ERROR: Failed to write registry value");
			return false;
		}
		else if (RegCreateKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_CANTWRITE) {
			platform_->logMessage("ERROR: Can't Write to Registry");
			return false;
		}

		platform_->logMessage("Registry Write Success: " + value);
		return true;
	}
	else {
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
		LONG result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ, (const BYTE*)value.c_str(), (DWORD)(value.size() + 1));
		RegCloseKey(hKey);
		if (result != ERROR_SUCCESS) {
			platform_->logMessage("ERROR: Failed to write registry value");
			return false;
		}
		else if (RegCreateKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_CANTWRITE) {
			platform_->logMessage("ERROR: Can't Write to Registry");
			return false;
		}

		platform_->logMessage("Registry Write Success: " + value);
		return true
	}
}

bool Regedit::Create(std::string path, std::string value, DWORD type) {
	// For simplicity, this method will just call Write since RegCreateKeyEx is used in Write
	return Write(path, value, type);
}

bool Regedit::Delete(std::string path) {
	HKEY hKey;
	std::string subKey, valueName;
	size_t lastBackslash = path.find_last_of('\\');
	if (lastBackslash == std::string::npos) {
		platform_->logMessage("ERROR: Invalid registry path format");
		return false;
	}
	subKey = path.substr(0, lastBackslash);
	valueName = path.substr(lastBackslash + 1);
	if (RegOpenKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
		platform_->logMessage("ERROR: Failed to open registry key");
		return false;
	}
	LONG result = RegDeleteValueA(hKey, valueName.c_str());
	RegCloseKey(hKey);
	if (result != ERROR_SUCCESS) {
		platform_->logMessage("ERROR: Failed to delete registry value");
		return false;
	}
	platform_->logMessage("Registry Delete Success: " + valueName);
	return true;
}


#endif