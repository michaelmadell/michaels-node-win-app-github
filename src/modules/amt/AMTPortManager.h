#pragma once

#include <string>

struct AMTPortInfo {
	std::wstring comPort;
	std::wstring instanceId;
};

AMTPortInfo GetAMTComPort();
bool disableAMTComPort();
bool enableAMTComPort();
bool reassignComPort();
