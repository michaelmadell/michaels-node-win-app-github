// Compile-time check that the event IDs hard-coded in EventLogger.h match the
// ones mc.exe/windmc generates from EventMessages.mc. Only built by CMake,
// which is also what compiles the message table into the exe.
#include "EventLogger.h"
#include "EventMessages.h" // generated into the build tree

static_assert(core::kEventIdInfo == MSG_CORE_INFO, "EventLogger.h out of sync with EventMessages.mc");
static_assert(core::kEventIdWarning == MSG_CORE_WARNING, "EventLogger.h out of sync with EventMessages.mc");
static_assert(core::kEventIdError == MSG_CORE_ERROR, "EventLogger.h out of sync with EventMessages.mc");
