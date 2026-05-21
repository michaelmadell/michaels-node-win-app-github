#pragma once

#ifdef _WIN32
#ifdef ENABLE_VNC

#include <windows.h>

// Entry point for --vnc-only mode. Spawned by the service into the user
// session via CreateProcessAsUser. Runs a VNC server on port 5900,
// captures the desktop via GDI, and blocks until parentPid exits.
int runVncHelper(DWORD parentPid);

#endif // ENABLE_VNC
#endif // _WIN32
