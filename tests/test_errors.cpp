// Error types (src/core/Errors.h) and the error-reporting helpers built on
// them (src/core/Logging.h). Pure logic - no OS calls except the OS error
// text lookup in describe().

#include <gtest/gtest.h>

#include <expected>
#include <string>
#include <system_error>

#include "core/Errors.h"
#include "core/Logging.h"
#include "test_helpers.h"

using core::AuthError;
using core::CoreError;
using core::PipeError;
using core::PlatformError;
using core::SerialError;

// --- construction ------------------------------------------------------------

TEST(ErrorTypes, DesignatedInitializersSetEveryField) {
    SerialError serial{
        .code = CoreError::Code::NotFound,
        .sub_code = SerialError::SubCode::PortNotFound,
        .message = "Port COM1 not found",
        .platform_error = 2,
    };
    EXPECT_EQ(serial.code, CoreError::Code::NotFound);
    EXPECT_EQ(serial.sub_code, SerialError::SubCode::PortNotFound);
    EXPECT_EQ(serial.message, "Port COM1 not found");
    EXPECT_EQ(serial.platform_error, 2u);

    PlatformError platform{ .code = CoreError::Code::Internal,
                            .sub_code = PlatformError::SubCode::WmiQueryFailed,
                            .message = "PDH failed" };
    EXPECT_EQ(platform.platform_error, 0u);  // omitted fields default

    AuthError auth{ .code = CoreError::Code::PermissionDenied,
                    .sub_code = AuthError::SubCode::TrustedIdentityMismatch };
    EXPECT_TRUE(auth.message.empty());

    PipeError pipe{ .code = CoreError::Code::Busy, .sub_code = PipeError::SubCode::PipeBusy };
    EXPECT_EQ(pipe.sub_code, PipeError::SubCode::PipeBusy);

    CoreError core{ .code = CoreError::Code::InvalidArgument, .message = "bad" };
    EXPECT_EQ(core.code, CoreError::Code::InvalidArgument);
}

TEST(ErrorTypes, DefaultsAreUnknownWithNoOsError) {
    SerialError e;
    EXPECT_EQ(e.code, CoreError::Code::Unknown);
    EXPECT_EQ(e.platform_error, 0u);
    EXPECT_TRUE(e.message.empty());
}

// Every error type satisfies the concept the generic helpers are written
// against.
static_assert(core::Error<CoreError>);
static_assert(core::Error<SerialError>);
static_assert(core::Error<PlatformError>);
static_assert(core::Error<AuthError>);
static_assert(core::Error<PipeError>);
static_assert(!core::Error<std::string>);

// --- std::error_code ------------------------------------------------------------

TEST(ErrorCode, StructsConvertToTheirSubsystemCategory) {
    SerialError serial{ .code = CoreError::Code::Timeout, .sub_code = SerialError::SubCode::ReadTimeout };
    std::error_code ec = core::make_error_code(serial);
    EXPECT_EQ(ec.value(), 102);
    EXPECT_STREQ(ec.category().name(), "serial");
    EXPECT_EQ(ec.message(), "serial read timeout");

    EXPECT_STREQ(core::make_error_code(PlatformError{ .sub_code = PlatformError::SubCode::ServiceNotFound })
                     .category().name(), "platform");
    EXPECT_STREQ(core::make_error_code(AuthError{ .sub_code = AuthError::SubCode::CertificateExpired })
                     .category().name(), "auth");
    EXPECT_STREQ(core::make_error_code(PipeError{ .sub_code = PipeError::SubCode::AuthRequired })
                     .category().name(), "pipe");
    EXPECT_STREQ(core::make_error_code(CoreError{ .code = CoreError::Code::Internal }).category().name(), "core");
}

TEST(ErrorCode, EnumsAreErrorCodeEnums) {
    // is_error_code_enum lets enums compare directly against error_codes.
    std::error_code ec = SerialError::SubCode::PortBusy;
    EXPECT_EQ(ec, SerialError::SubCode::PortBusy);
    EXPECT_NE(ec, SerialError::SubCode::PortNotFound);
    // Same numeric value in a different category is a different error.
    EXPECT_NE(std::error_code(CoreError::Code::NotFound), std::error_code(2, core::serial_category()));
}

TEST(ErrorCode, EveryCodeHasAName) {
    for (int c = 0; c <= 8; ++c) {
        EXPECT_EQ(std::string(core::to_string(static_cast<CoreError::Code>(c))).find("unrecognised"),
                  std::string::npos) << "CoreError::Code " << c;
    }
    for (int c = 100; c <= 106; ++c) {
        EXPECT_EQ(std::string(core::to_string(static_cast<SerialError::SubCode>(c))).find("unrecognised"),
                  std::string::npos) << "SerialError::SubCode " << c;
    }
    for (int c = 200; c <= 213; ++c) {
        EXPECT_EQ(std::string(core::to_string(static_cast<PlatformError::SubCode>(c))).find("unrecognised"),
                  std::string::npos) << "PlatformError::SubCode " << c;
    }
    for (int c = 300; c <= 304; ++c) {
        EXPECT_EQ(std::string(core::to_string(static_cast<AuthError::SubCode>(c))).find("unrecognised"),
                  std::string::npos) << "AuthError::SubCode " << c;
    }
    for (int c = 400; c <= 405; ++c) {
        EXPECT_EQ(std::string(core::to_string(static_cast<PipeError::SubCode>(c))).find("unrecognised"),
                  std::string::npos) << "PipeError::SubCode " << c;
    }
    EXPECT_STREQ(core::to_string(static_cast<SerialError::SubCode>(999)), "unrecognised serial error");
}

// --- describe() ---------------------------------------------------------------

TEST(Describe, MessageOnlyWithoutOsError) {
    EXPECT_EQ(core::describe(CoreError{ .message = "plain" }), "plain");
}

TEST(Describe, AppendsOsErrorNumberAndText) {
    // 2 is "file not found" on Windows (ERROR_FILE_NOT_FOUND) and Linux (ENOENT).
    std::string text = core::describe(SerialError{ .message = "CreateFileA failed for COM9", .platform_error = 2 });
    EXPECT_EQ(text.rfind("CreateFileA failed for COM9 (error 2: ", 0), 0u) << text;
    EXPECT_EQ(text.back(), ')');
    // OS text is trimmed - no stray CR/LF before the closing parenthesis.
    EXPECT_EQ(text.find('\n'), std::string::npos);
    EXPECT_EQ(text.find('\r'), std::string::npos);
    EXPECT_GT(text.size(), std::string("CreateFileA failed for COM9 (error 2: )").size());
}

// --- std::expected paths ------------------------------------------------------

namespace {

std::expected<int, SerialError> parsePort(const std::string& name) {
    if (name.rfind("COM", 0) != 0) {
        return std::unexpected(SerialError{ .code = CoreError::Code::InvalidArgument,
                                            .sub_code = SerialError::SubCode::PortNotFound,
                                            .message = "not a COM port: " + name });
    }
    return std::stoi(name.substr(3));
}

} // namespace

TEST(Expected, SuccessPath) {
    auto port = parsePort("COM3");
    ASSERT_TRUE(port.has_value());
    EXPECT_EQ(*port, 3);
    EXPECT_EQ(port.value_or(-1), 3);
}

TEST(Expected, FailurePathCarriesTheError) {
    auto port = parsePort("ttyS0");
    ASSERT_FALSE(port);
    EXPECT_EQ(port.error().sub_code, SerialError::SubCode::PortNotFound);
    EXPECT_EQ(port.error().message, "not a COM port: ttyS0");
    EXPECT_EQ(port.value_or(-1), -1);
}

TEST(Expected, MonadicChainingShortCircuitsOnError) {
    int calls = 0;
    auto doubled = [&](int p) -> std::expected<int, SerialError> { ++calls; return p * 2; };

    EXPECT_EQ(parsePort("COM4").and_then(doubled).value(), 8);
    EXPECT_FALSE(parsePort("bad").and_then(doubled).has_value());
    EXPECT_EQ(calls, 1);  // and_then not invoked for the error

    auto recovered = parsePort("bad").or_else([](const SerialError&) -> std::expected<int, SerialError> { return 1; });
    EXPECT_EQ(recovered.value(), 1);

    auto asText = parsePort("COM7").transform([](int p) { return std::to_string(p); });
    EXPECT_EQ(asText.value(), "7");
}

TEST(Expected, VoidSuccessAndFailure) {
    std::expected<void, PipeError> ok;
    EXPECT_TRUE(ok.has_value());
    std::expected<void, PipeError> failed =
        std::unexpected(PipeError{ .code = CoreError::Code::Internal, .sub_code = PipeError::SubCode::CreateFailed });
    EXPECT_FALSE(failed.has_value());
    EXPECT_EQ(failed.error().sub_code, PipeError::SubCode::CreateFailed);
}

// --- Logging.h error helpers -----------------------------------------------------

TEST(LogLevelFor, TransientCodesAreWarnings) {
    EXPECT_EQ(core::LevelFor(CoreError::Code::NotFound), core::LogLevel::Warning);
    EXPECT_EQ(core::LevelFor(CoreError::Code::Timeout), core::LogLevel::Warning);
    EXPECT_EQ(core::LevelFor(CoreError::Code::Busy), core::LogLevel::Warning);
    EXPECT_EQ(core::LevelFor(CoreError::Code::Internal), core::LogLevel::Error);
    EXPECT_EQ(core::LevelFor(CoreError::Code::PermissionDenied), core::LogLevel::Error);
    EXPECT_EQ(core::LevelFor(CoreError::Code::Unknown), core::LogLevel::Error);
}

TEST(LogError, UsesTheCodesLevelAndFormatsContext) {
    test::LogCapture log;
    core::LogError(core::kMsgIDSerial, "Serial",
                   SerialError{ .code = CoreError::Code::NotFound, .message = "port gone" });
    core::LogError(core::kMsgIDPlatform, "",
                   PlatformError{ .code = CoreError::Code::Internal, .message = "boom" });

    auto entries = log.entries();
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].level, core::LogLevel::Warning);
    EXPECT_EQ(entries[0].messageId, core::kMsgIDSerial);
    EXPECT_EQ(entries[0].message, "Serial: port gone");
    EXPECT_EQ(entries[1].level, core::LogLevel::Error);
    EXPECT_EQ(entries[1].message, "boom");  // empty context -> no prefix
}

TEST(LogError, ExpectedHelperOnlyLogsErrors) {
    test::LogCapture log;
    core::LogExpectedError(core::kMsgIDInfo, "ctx", std::expected<int, CoreError>(5));
    EXPECT_TRUE(log.entries().empty());
    core::LogExpectedError(core::kMsgIDInfo, "ctx",
                           std::expected<int, CoreError>(std::unexpected(CoreError{ .message = "x" })));
    EXPECT_EQ(log.entries().size(), 1u);
}

TEST(LogErrorOnChange, RepeatsAreSuppressedUntilTheErrorChanges) {
    test::LogCapture log;
    const std::string key = "test:on-change";
    core::ClearReportedError(key);

    SerialError missing{ .code = CoreError::Code::NotFound,
                         .sub_code = SerialError::SubCode::PortNotFound, .platform_error = 2 };
    EXPECT_TRUE(core::LogErrorOnChange(key, core::kMsgIDSerial, "Serial", missing));
    EXPECT_FALSE(core::LogErrorOnChange(key, core::kMsgIDSerial, "Serial", missing));
    EXPECT_FALSE(core::LogErrorOnChange(key, core::kMsgIDSerial, "Serial", missing));

    // Different OS error -> logged again.
    SerialError busy = missing;
    busy.platform_error = 5;
    EXPECT_TRUE(core::LogErrorOnChange(key, core::kMsgIDSerial, "Serial", busy));

    // Different sub-code -> logged again.
    SerialError configure = busy;
    configure.sub_code = SerialError::SubCode::ConfigureFailed;
    EXPECT_TRUE(core::LogErrorOnChange(key, core::kMsgIDSerial, "Serial", configure));

    EXPECT_EQ(log.count(core::kMsgIDSerial), 3u);
    core::ClearReportedError(key);
}

TEST(LogErrorOnChange, KeysAreIndependent) {
    test::LogCapture log;
    core::ClearReportedError("test:a");
    core::ClearReportedError("test:b");
    CoreError e{ .code = CoreError::Code::Internal, .message = "e" };
    EXPECT_TRUE(core::LogErrorOnChange("test:a", core::kMsgIDInfo, "", e));
    EXPECT_TRUE(core::LogErrorOnChange("test:b", core::kMsgIDInfo, "", e));
    EXPECT_FALSE(core::LogErrorOnChange("test:a", core::kMsgIDInfo, "", e));
    core::ClearReportedError("test:a");
    core::ClearReportedError("test:b");
}

TEST(ClearReportedError, LogsRecoveryOnlyAfterAnError) {
    test::LogCapture log;
    const std::string key = "test:recovery";
    core::ClearReportedError(key);

    core::ClearReportedError(key, core::kMsgIDSerial, "recovered");  // nothing was reported
    EXPECT_TRUE(log.entries().empty());

    core::LogErrorOnChange(key, core::kMsgIDSerial, "Serial", CoreError{ .code = CoreError::Code::Internal });
    core::ClearReportedError(key, core::kMsgIDSerial, "recovered");
    auto entries = log.entries();
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[1].level, core::LogLevel::Info);
    EXPECT_EQ(entries[1].message, "recovered");

    // After clearing, the same error is reported afresh.
    EXPECT_TRUE(core::LogErrorOnChange(key, core::kMsgIDSerial, "Serial", CoreError{ .code = CoreError::Code::Internal }));
    core::ClearReportedError(key);
}

TEST(Log, BelowMinimumLevelIsDropped) {
    test::LogCapture log;
    core::Log(core::LogLevel::Debug, core::kMsgIDInfo, "debug line");  // default minimum is Info
    core::Log(core::LogLevel::Info, core::kMsgIDInfo, std::string("info line"));
    auto entries = log.entries();
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].message, "info line");
}
