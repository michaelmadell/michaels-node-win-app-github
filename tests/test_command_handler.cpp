// C2A command dispatch (src/modules/cmc/CmcCommandHandler.cpp) against a
// mock Platform: every verb, the replies sent back to the BMC, argument
// validation, and the scheduled/cancelled shutdown flow. Only built with
// BUILD_C2A.

#ifdef ENABLE_C2A

#include <gtest/gtest.h>

#include <regex>
#include <string>

#include "modules/cmc/CmcCommandHandler.h"
#include "mock_platform.h"
#include "test_helpers.h"

using ::testing::_;
using ::testing::HasSubstr;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

class CommandHandlerTest : public ::testing::Test {
protected:
    // Declared before the handler so they outlive it: its destructor joins
    // the scheduled-action thread, which may still send a reply.
    NiceMock<test::MockPlatform> platform;
    test::MessageSink sent;
    CmcCommandHandler handler{ &platform, [this](const std::string& m) { sent(m); } };

    void SetUp() override {
        ON_CALL(platform, getCpuUsagePercent()).WillByDefault(Return(12));
        ON_CALL(platform, getRamUsagePercent()).WillByDefault(Return(34));
        ON_CALL(platform, getSystemUptime()).WillByDefault(Return("2d 04h 13m 09s"));
    }

    std::string onlyReply() {
        auto messages = sent.messages();
        EXPECT_EQ(messages.size(), 1u);
        return messages.empty() ? std::string() : messages.front();
    }
};

// --- simple queries ------------------------------------------------------------------

TEST_F(CommandHandlerTest, PingRepliesPong) {
    handler.handle("ping");
    EXPECT_EQ(onlyReply(), "pong");
}

TEST_F(CommandHandlerTest, VerbsAreCaseInsensitiveAndTrimmed) {
    handler.handle("  PiNg  ");
    EXPECT_EQ(onlyReply(), "pong");
}

TEST_F(CommandHandlerTest, StatusReportsCpuRamUptime) {
    handler.handle("status");
    EXPECT_EQ(onlyReply(), "status, cpu=12%, ram=34%, uptime=2d 04h 13m 09s");
}

TEST_F(CommandHandlerTest, CurrentTimeIsLocalTimestamp) {
    handler.handle("ct");
    EXPECT_TRUE(std::regex_match(onlyReply(), std::regex(R"(ct, \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")))
        << sent.messages().front();
}

// --- immediate actions -------------------------------------------------------------

TEST_F(CommandHandlerTest, ForcedShutdownExecutesImmediatelyWithReason) {
    EXPECT_CALL(platform, shutdownSystem("maintenance window"));
    handler.handle("shutdown, force, maintenance window");
    EXPECT_EQ(onlyReply(), "shutdownExecuting");
}

TEST_F(CommandHandlerTest, ForcedRestartJoinsMultiPartReason) {
    EXPECT_CALL(platform, restartSystem("firmware, step 2"));
    handler.handle("Restart, FORCE, firmware, step 2");
    EXPECT_EQ(onlyReply(), "RestartExecuting");  // reply echoes the verb as sent
}

TEST_F(CommandHandlerTest, LockAndLogoff) {
    EXPECT_CALL(platform, lockActiveSession());
    EXPECT_CALL(platform, logoffActiveSession());
    handler.handle("lock");
    handler.handle("logoff");
    EXPECT_EQ(sent.messages(), (std::vector<std::string>{ "locking", "loggingOff" }));
}

// --- argument validation -----------------------------------------------------------

TEST_F(CommandHandlerTest, MissingTimeoutValueIsRejected) {
    EXPECT_CALL(platform, shutdownSystem(_)).Times(0);
    handler.handle("shutdown, timeout");
    handler.handle("shutdown, timeout, ");
    EXPECT_EQ(sent.messages(), (std::vector<std::string>{ "shutdownRejected, missing-timeout-value",
                                                          "shutdownRejected, missing-timeout-value" }));
}

TEST_F(CommandHandlerTest, MalformedTimeoutsAreRejectedWithAReason) {
    EXPECT_CALL(platform, shutdownSystem(_)).Times(0);
    const struct { const char* value; const char* reason; } cases[] = {
        { "abc", "digits followed by one unit" },
        { "5", "too short" },
        { "0s", "must be positive" },
        { "5x", "unknown unit" },
        { "10ms", "digits followed by one unit" },
        { "-5s", "digits followed by one unit" },
        { "99999999999999999999s", "out of range" },
    };
    for (const auto& c : cases) {
        std::string logged;
        EXPECT_CALL(platform, logMessage(_)).WillOnce([&](const std::string& m) { logged = m; });
        handler.handle(std::string("shutdown, timeout, ") + c.value);
        EXPECT_THAT(logged, HasSubstr(c.reason)) << "timeout '" << c.value << "'";
        ::testing::Mock::VerifyAndClearExpectations(&platform);
    }
    for (const auto& reply : sent.messages()) {
        EXPECT_EQ(reply, "shutdownRejected, invalid-timeout");
    }
    EXPECT_EQ(sent.messages().size(), std::size(cases));
}

TEST_F(CommandHandlerTest, TimeModifierValidation) {
    handler.handle("restart, time");
    handler.handle("restart, time, not-a-date");
    handler.handle("restart, time, 2026-13-45 99:99:99");
    EXPECT_EQ(sent.messages(), (std::vector<std::string>{ "restartRejected, missing-time-value",
                                                          "restartRejected, invalid-time",
                                                          "restartRejected, invalid-time" }));
}

// --- scheduled actions -------------------------------------------------------------

TEST_F(CommandHandlerTest, ScheduledShutdownCanBeCancelled) {
    EXPECT_CALL(platform, shutdownSystem(_)).Times(0);
    EXPECT_CALL(platform, showMessageDialog("Command from Chassis Controller", HasSubstr("shutdown")));

    handler.handle("shutdown, timeout, 1h, patching");
    ASSERT_TRUE(sent.waitFor("shutdownPending, "));
    std::string pending = sent.messages().front();
    EXPECT_TRUE(std::regex_match(pending,
        std::regex(R"(shutdownPending, \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}, patching)"))) << pending;

    handler.handle("cancel");
    EXPECT_TRUE(sent.waitFor("shutdownCancelled"));
}

TEST_F(CommandHandlerTest, NoModifierUsesTheDefaultGracePeriod) {
    EXPECT_CALL(platform, restartSystem(_)).Times(0);
    handler.handle("restart, routine");
    ASSERT_TRUE(sent.waitFor("restartPending, "));
    EXPECT_THAT(sent.messages().front(), HasSubstr(", routine"));
    handler.handle("cancel");
    EXPECT_TRUE(sent.waitFor("restartCancelled"));
}

TEST_F(CommandHandlerTest, ScheduledShutdownExecutesAtTheDeadline) {
    EXPECT_CALL(platform, shutdownSystem("soon"));
    handler.handle("shutdown, timeout, 1s, soon");
    EXPECT_TRUE(sent.waitFor("shutdownPending"));
    EXPECT_TRUE(sent.waitFor("shutdownExecuting", std::chrono::seconds(10)));
}

TEST_F(CommandHandlerTest, AbsoluteTimeInThePastExecutesImmediately) {
    EXPECT_CALL(platform, restartSystem(""));
    handler.handle("restart, time, 2000-01-01 00:00:00");
    EXPECT_TRUE(sent.waitFor("restartExecuting"));
}

TEST_F(CommandHandlerTest, CancelWithNothingPending) {
    handler.handle("cancel");
    EXPECT_EQ(onlyReply(), "cancelled, none-pending");
}

// --- fallback ----------------------------------------------------------------------

TEST_F(CommandHandlerTest, UnknownCommandIsShownAsADialog) {
    EXPECT_CALL(platform, showMessageDialog("Command from BMC", "hello operator"));
    handler.handle("hello operator");
    EXPECT_TRUE(sent.messages().empty());
}

TEST_F(CommandHandlerTest, EmptyCommandIsShownAsADialog) {
    EXPECT_CALL(platform, showMessageDialog("Command from BMC", ""));
    handler.handle("");
}

TEST(CommandHandlerStrict, PingTouchesNothingButTheReply) {
    StrictMock<test::MockPlatform> platform;  // any platform call fails the test
    test::MessageSink sent;
    CmcCommandHandler handler(&platform, [&](const std::string& m) { sent(m); });
    handler.handle("ping");
    EXPECT_EQ(sent.messages(), std::vector<std::string>{ "pong" });
}

#endif // ENABLE_C2A
