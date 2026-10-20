#include "CmcCommandHandler.h"
#include "../../core/Errors.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <ctime>
#include <expected>
#include <format>
#include <iomanip>
#include <sstream>
#include <vector>

namespace {

core::CoreError invalidArgument(std::string message) {
    return core::CoreError{
        .code = core::CoreError::Code::InvalidArgument,
        .message = std::move(message),
    };
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin(), [](unsigned char x, unsigned char y) {
        return std::tolower(x) == std::tolower(y);
    });
}

std::vector<std::string> splitTokens(const std::string& message) {
    std::vector<std::string> tokens;
    std::istringstream ss(message);
    std::string token;
    while (std::getline(ss, token, ',')) {
        tokens.push_back(trim(token));
    }
    return tokens;
}

std::string joinFrom(const std::vector<std::string>& tokens, size_t idx) {
    std::string joined;
    for (size_t i = idx; i < tokens.size(); ++i) {
        if (i > idx) joined += ", ";
        joined += tokens[i];
    }
    return joined;
}

// Parses a duration string like "30s", "5m", "1h" (digits followed by
// exactly one unit character).
std::expected<std::chrono::seconds, core::CoreError> parseDurationString(const std::string& s) {
    if (s.size() < 2) {
        return std::unexpected(invalidArgument(std::format("timeout '{}' is too short", s)));
    }

    size_t digitsEnd = 0;
    while (digitsEnd < s.size() && std::isdigit(static_cast<unsigned char>(s[digitsEnd]))) {
        digitsEnd++;
    }
    if (digitsEnd == 0 || digitsEnd != s.size() - 1) {
        return std::unexpected(invalidArgument(std::format("timeout '{}' must be digits followed by one unit", s)));
    }

    // from_chars instead of stol: no exceptions, and overflow is reported
    // via ec rather than thrown.
    long value = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + digitsEnd, value);
    if (ec != std::errc{} || ptr != s.data() + digitsEnd) {
        return std::unexpected(invalidArgument(std::format("timeout '{}' is out of range", s)));
    }
    if (value <= 0) {
        return std::unexpected(invalidArgument(std::format("timeout '{}' must be positive", s)));
    }

    switch (std::tolower(static_cast<unsigned char>(s[digitsEnd]))) {
        case 's': return std::chrono::seconds(value);
        case 'm': return std::chrono::minutes(value);
        case 'h': return std::chrono::hours(value);
        default:
            return std::unexpected(invalidArgument(std::format("timeout '{}' has unknown unit (expected s/m/h)", s)));
    }
}

// Parses "YYYY-MM-DD HH:MM:SS" as a local time in the system's timezone.
std::expected<std::chrono::system_clock::time_point, core::CoreError> parseLocalDateTime(const std::string& s) {
    std::tm tmVal = {};
    std::istringstream iss(s);
    iss >> std::get_time(&tmVal, "%Y-%m-%d %H:%M:%S");
    if (iss.fail()) {
        return std::unexpected(invalidArgument(std::format("time '{}' is not YYYY-MM-DD HH:MM:SS", s)));
    }

    tmVal.tm_isdst = -1; // let mktime work out DST for this local time
    std::time_t t = std::mktime(&tmVal);
    if (t == static_cast<std::time_t>(-1)) {
        return std::unexpected(invalidArgument(std::format("time '{}' is not representable", s)));
    }

    return std::chrono::system_clock::from_time_t(t);
}

std::string formatLocalTime(std::chrono::system_clock::time_point tp) {
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tmVal{};
#ifdef _WIN32
    localtime_s(&tmVal, &t);
#else
    localtime_r(&t, &tmVal);
#endif
    // There's no std::formatter<std::tm>, and zoned_time needs a tzdb the
    // Linux CI toolchain doesn't ship - put_time is still the portable option.
    std::ostringstream oss;
    oss << std::put_time(&tmVal, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

} // namespace

CmcCommandHandler::CmcCommandHandler(Platform* platform, SendFn sendToMec)
    : platform_(platform), sendToMec_(std::move(sendToMec)) {
}

CmcCommandHandler::~CmcCommandHandler() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cancelRequested_ = true;
    }
    cv_.notify_all();
    if (pendingThread_.joinable()) {
        pendingThread_.join();
    }
}

void CmcCommandHandler::handle(const std::string& message) {
    std::vector<std::string> tokens = splitTokens(message);
    if (tokens.empty() || tokens[0].empty()) {
        platform_->showMessageDialog("Command from BMC", message);
        return;
    }

    const std::string& verb = tokens[0];

    if (iequals(verb, "ping")) {
        sendToMec_("pong");
        return;
    }

    if (iequals(verb, "status")) {
        sendToMec_("status, cpu=" + std::to_string(platform_->getCpuUsagePercent()) + "%, "
            + "ram=" + std::to_string(platform_->getRamUsagePercent()) + "%, "
            + "uptime=" + platform_->getSystemUptime());
        return;
    }

    if (iequals(verb, "ct")) {
        sendToMec_("ct, " + formatLocalTime(std::chrono::system_clock::now()));
        return;
    }

    if (iequals(verb, "shutdown") || iequals(verb, "restart")) {
        if (tokens.size() > 1 && iequals(tokens[1], "force")) {
            beginImmediateAction(verb, joinFrom(tokens, 2));
            return;
        }

        if (tokens.size() > 1 && iequals(tokens[1], "timeout")) {
            if (tokens.size() <= 2 || tokens[2].empty()) {
                sendToMec_(verb + "Rejected, missing-timeout-value");
                return;
            }
            auto duration = parseDurationString(tokens[2]);
            if (!duration) {
                platform_->logMessage(std::format("CMC {} rejected: {}.", verb, duration.error().message));
                sendToMec_(verb + "Rejected, invalid-timeout");
                return;
            }
            beginScheduledAction(verb, std::chrono::system_clock::now() + *duration, joinFrom(tokens, 3));
            return;
        }

        if (tokens.size() > 1 && iequals(tokens[1], "time")) {
            if (tokens.size() <= 2 || tokens[2].empty()) {
                sendToMec_(verb + "Rejected, missing-time-value");
                return;
            }
            auto deadline = parseLocalDateTime(tokens[2]);
            if (!deadline) {
                platform_->logMessage(std::format("CMC {} rejected: {}.", verb, deadline.error().message));
                sendToMec_(verb + "Rejected, invalid-time");
                return;
            }
            beginScheduledAction(verb, *deadline, joinFrom(tokens, 3));
            return;
        }

        // No modifier: default grace period, same as before.
        beginScheduledAction(verb, std::chrono::system_clock::now() + kDefaultGracePeriod, joinFrom(tokens, 1));
        return;
    }

    if (iequals(verb, "cancel")) {
        cancelPending();
        return;
    }

    if (iequals(verb, "lock")) {
        platform_->logMessage("CMC command: lock active session.");
        sendToMec_("locking");
        platform_->lockActiveSession();
        return;
    }

    if (iequals(verb, "logoff")) {
        platform_->logMessage("CMC command: log off active session.");
        sendToMec_("loggingOff");
        platform_->logoffActiveSession();
        return;
    }

    // Unrecognized command: preserve the original fallback behavior.
    platform_->showMessageDialog("Command from BMC", message);
}

void CmcCommandHandler::beginImmediateAction(const std::string& verb, const std::string& reason) {
    platform_->logMessage("CMC " + verb + " command received (forced)." +
        (reason.empty() ? "" : (" Reason: " + reason)));
    sendToMec_(verb + "Executing");
    invokeAction(verb, reason);
}

void CmcCommandHandler::beginScheduledAction(const std::string& verb,
    std::chrono::system_clock::time_point deadline, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pendingThread_.joinable()) {
        // A previous grace-period thread already finished (or is about to
        // execute) — reap it before starting a new one.
        pendingThread_.join();
    }
    actionPending_ = true;
    cancelRequested_ = false;
    pendingVerb_ = verb;
    pendingThread_ = std::thread(&CmcCommandHandler::runScheduledAction, this, verb, deadline, reason);
}

void CmcCommandHandler::runScheduledAction(std::string verb,
    std::chrono::system_clock::time_point deadline, std::string reason) {
    std::string targetStr = formatLocalTime(deadline);
    std::string reasonSuffix = reason.empty() ? "" : (", " + reason);

    platform_->logMessage("CMC " + verb + " scheduled for " + targetStr + "." +
        (reason.empty() ? "" : (" Reason: " + reason)));
    sendToMec_(verb + "Pending, " + targetStr + reasonSuffix);
    platform_->showMessageDialog(
        "Command from Chassis Controller",
        "The chassis controller has scheduled a " + verb + " for " + targetStr + "." +
        (reason.empty() ? "" : (" Reason: " + reason)));

    std::unique_lock<std::mutex> lock(mutex_);
    bool cancelled = cv_.wait_until(lock, deadline, [this] { return cancelRequested_; });

    actionPending_ = false;

    if (cancelled) {
        platform_->logMessage("CMC " + verb + " cancelled before execution.");
        sendToMec_(verb + "Cancelled");
        return;
    }

    lock.unlock();
    platform_->logMessage("CMC " + verb + " scheduled time reached; executing.");
    sendToMec_(verb + "Executing");
    invokeAction(verb, reason);
}

void CmcCommandHandler::cancelPending() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!actionPending_) {
        sendToMec_("cancelled, none-pending");
        return;
    }
    cancelRequested_ = true;
    cv_.notify_all();
}

void CmcCommandHandler::invokeAction(const std::string& verb, const std::string& reason) {
    if (iequals(verb, "shutdown")) {
        platform_->shutdownSystem(reason);
    } else if (iequals(verb, "restart")) {
        platform_->restartSystem(reason);
    }
}
