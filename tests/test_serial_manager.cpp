// SerialManager (src/modules/serial/SerialManager.cpp) without hardware:
// opens are attempted on port names that cannot exist, so these exercise the
// real OS error paths, the closed-port guards, reconnect pacing and (on
// Windows) the error reporting. Line framing is covered separately in
// test_serialization.cpp. Read/write timeouts need a real port and are not
// unit-tested.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "modules/serial/SerialManager.h"
#include "test_helpers.h"

namespace {

#ifdef _WIN32
const char* const kMissingPort = "COM250";
#else
const char* const kMissingPort = "/dev/corestation-test-no-such-tty";
#endif

} // namespace

TEST(SerialManager, StartsClosed) {
    SerialManager serial([](const std::string&) {});
    EXPECT_FALSE(serial.IsOpen());
}

TEST(SerialManager, OpeningAMissingPortFails) {
    test::LogCapture log;
    test::OutputStreamCapture err(std::cerr);
    SerialManager serial([](const std::string&) {});
    EXPECT_FALSE(serial.Open(kMissingPort));
    EXPECT_FALSE(serial.IsOpen());
    // The failure is reported, naming the port.
    EXPECT_NE(err.str().find(kMissingPort), std::string::npos) << err.str();
}

TEST(SerialManager, ClosedPortRejectsIo) {
    SerialManager serial([](const std::string&) {});
    std::string data;
    EXPECT_FALSE(serial.Write("HB\r\n"));
    EXPECT_FALSE(serial.Read(data));
    EXPECT_TRUE(data.empty());
}

TEST(SerialManager, CloseIsIdempotent) {
    SerialManager serial([](const std::string&) {});
    serial.Close();
    serial.Close();
    EXPECT_FALSE(serial.IsOpen());
}

TEST(SerialManager, ProcessingWithNothingToReadDeliversNoMessages) {
    std::vector<std::string> received;
    SerialManager serial([&](const std::string& m) { received.push_back(m); });
    serial.ProcessIncomingData();
    EXPECT_TRUE(received.empty());
}

TEST(SerialManager, ReconnectIsPacedByTheRetryDelay) {
    test::LogCapture log;
    test::OutputStreamCapture out(std::cout);
    test::OutputStreamCapture err(std::cerr);
    SerialManager serial([](const std::string&) {});
    EXPECT_FALSE(serial.Open(kMissingPort));  // remembers the port for reconnects

    // The last-attempt time starts at the clock's epoch (boot time on Linux),
    // so make one attempt with no delay to set it, then check pacing.
    serial.SetRetryDelay(0);
    EXPECT_FALSE(serial.TryReconnect());      // attempt 1
    serial.SetRetryDelay(60 * 60 * 1000);     // 1 hour
    EXPECT_FALSE(serial.TryReconnect());      // within the delay: no attempt
    EXPECT_FALSE(serial.TryReconnect());

    const std::string output = out.str();
    size_t attempts = 0;
    for (size_t pos = 0; (pos = output.find("Attempting to reconnect", pos)) != std::string::npos; ++pos) {
        ++attempts;
    }
    EXPECT_EQ(attempts, 1u) << output;
}

#ifdef _WIN32
// Windows reports open failures through core::Log under the serial message
// ID, once per distinct error (TryReconnect retries every few seconds while
// the port is missing), and logs a recovery when the port opens again.
TEST(SerialManager, RepeatedOpenFailuresAreLoggedOnce) {
    test::LogCapture log;
    test::OutputStreamCapture err(std::cerr);
    SerialManager serial([](const std::string&) {});
    EXPECT_FALSE(serial.Open(kMissingPort));
    EXPECT_FALSE(serial.Open(kMissingPort));
    EXPECT_FALSE(serial.Open(kMissingPort));

    auto entries = log.entries();
    ASSERT_EQ(log.count(core::kMsgIDSerial), 1u);
    EXPECT_NE(entries[0].message.find(kMissingPort), std::string::npos) << entries[0].message;
    EXPECT_NE(entries[0].message.find("CreateFileA"), std::string::npos) << entries[0].message;
    // Every failure still goes to stderr.
    size_t stderrReports = 0;
    const std::string text = err.str();
    for (size_t pos = 0; (pos = text.find(kMissingPort, pos)) != std::string::npos; ++pos) {
        ++stderrReports;
    }
    EXPECT_EQ(stderrReports, 3u) << text;

    core::ClearReportedError(std::string("serial:") + kMissingPort);
}
#endif
