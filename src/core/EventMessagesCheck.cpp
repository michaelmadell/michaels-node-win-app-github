// Compile-time check that the message IDs in Logging.h (kMsgID*, shared by
// the Windows Event Log and Linux syslog backends) match the ones
// mc.exe/windmc generates from EventMessages.mc. Only built by CMake on
// Windows, which is also what compiles the message table into the exe. The
// platform-independent checks (unique, 16-bit) live in Logging.h itself.
#include "Logging.h"
#include "EventMessages.h" // generated into the build tree

#define CHECK_MSG_ID(constant, generated) \
    static_assert(core::constant == (generated), #constant " out of sync with EventMessages.mc (" #generated ")")

CHECK_MSG_ID(kMsgIDInfo, MSG_GENERAL_INFO);
CHECK_MSG_ID(kMsgIDWarning, MSG_GENERAL_WARNING);
CHECK_MSG_ID(kMsgIDError, MSG_GENERAL_ERROR);
CHECK_MSG_ID(kMsgIDSerial, MSG_SERIAL);
CHECK_MSG_ID(kMsgIDSerialBridge, MSG_SERIAL_BRIDGE);
CHECK_MSG_ID(kMsgIDPlatform, MSG_PLATFORM);
CHECK_MSG_ID(kMsgIDMetrics, MSG_METRICS);
CHECK_MSG_ID(kMsgIDAmt, MSG_AMT);
CHECK_MSG_ID(kMsgIDSession, MSG_SESSION);
CHECK_MSG_ID(kMsgIDUnhandledException, MSG_UNHANDLED_EXCEPTION);

// Every ID Logging.h knows about must have a message table entry above.
static_assert(std::size(core::detail::kAllMsgIDs) == 10,
              "a kMsgID* was added to Logging.h - add it to EventMessages.mc and check it here");
