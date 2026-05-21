#pragma once

#ifdef _WIN32
#ifdef ENABLE_VNC

#include <windows.h>
#include <string>

// Entry point for --vnc-only mode. Spawned by the service into the user
// session via CreateProcessAsUser. Runs a VNC server on port 5900,
// captures the desktop via GDI, and blocks until parentPid exits.
// password may be empty, in which case the server runs without authentication.
int runVncHelper(DWORD parentPid, const std::string& password);

#endif // ENABLE_VNC
#endif // _WIN32
