#pragma once

#include <expected>
#include <string>

#include "../../core/Errors.h"

struct AMTPortInfo {
	std::wstring comPort;
	std::wstring instanceId;
};

// Current COM port of the AMT SOL serial device. Fails with
// PlatformError{NotFound, DeviceNotFound} when no AMT device (or no PortName)
// is present - the normal case on non-AMT hardware, and always on Linux.
std::expected<AMTPortInfo, core::PlatformError> GetAMTComPort();

std::expected<void, core::PlatformError> disableAMTComPort();
std::expected<void, core::PlatformError> enableAMTComPort();

// Moves the AMT SOL device to COM4 (see AMTPortManager.cpp for the steps).
std::expected<void, core::PlatformError> reassignComPort();
