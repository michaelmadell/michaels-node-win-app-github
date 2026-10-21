#pragma once

// Shared unit-test utilities. Header-only; no OS mocking - everything here is
// either pure or works on the real filesystem/streams.

#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "core/Logging.h"

namespace test {

// Redirects a stream (std::cout by default) into a buffer for the lifetime
// of the object.
class OutputStreamCapture {
public:
    explicit OutputStreamCapture(std::ostream& stream = std::cout)
        : stream_(stream), original_(stream.rdbuf(buffer_.rdbuf())) {}
    ~OutputStreamCapture() { stream_.rdbuf(original_); }

    OutputStreamCapture(const OutputStreamCapture&) = delete;
    OutputStreamCapture& operator=(const OutputStreamCapture&) = delete;

    std::string str() const { return buffer_.str(); }

private:
    std::ostream& stream_;
    std::stringstream buffer_;
    std::streambuf* original_;
};

// A std::chrono clock that only moves when told to, for deterministic
// time-based tests (e.g. MetricCache<T, test::MockClock>). Static, because
// chrono clocks are used through Clock::now(); call reset() in each test.
struct MockClock {
    using duration = std::chrono::steady_clock::duration;
    using rep = duration::rep;
    using period = duration::period;
    using time_point = std::chrono::time_point<MockClock>;
    static constexpr bool is_steady = true;

    static time_point now() noexcept { return current(); }
    static void advance(duration d) noexcept { current() += d; }
    static void reset() noexcept { current() = time_point{}; }

private:
    static time_point& current() noexcept {
        static time_point t{};
        return t;
    }
};

// A uniquely named file in the system temp directory, deleted on
// destruction.
class TempFile {
public:
    explicit TempFile(const std::string& prefix = "test_") {
        std::random_device rd;
        std::mt19937_64 rng(rd());
        path_ = (std::filesystem::temp_directory_path() /
                 (prefix + std::to_string(rng()) + ".tmp")).string();
    }
    ~TempFile() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    const std::string& path() const { return path_; }

    void write(const std::string& content) const {
        std::ofstream out(path_, std::ios::binary | std::ios::trunc);
        out << content;
    }

    std::string read() const {
        std::ifstream in(path_, std::ios::binary);
        std::stringstream ss;
        ss << in.rdbuf();
        return ss.str();
    }

private:
    std::string path_;
};

// Captures core::Log output (test builds define CORESTATION_LOG_CAPTURE, so
// nothing reaches the real Event Log / syslog) for the object's lifetime.
// Thread-safe: production code may log from worker threads.
class LogCapture {
public:
    struct Entry {
        core::LogLevel level;
        std::uint32_t messageId;
        std::string message;
    };

    LogCapture() {
        core::LogCapture() = [this](core::LogLevel level, std::uint32_t id, const std::string& message) {
            std::lock_guard<std::mutex> lock(mutex_);
            entries_.push_back({ level, id, message });
        };
    }
    ~LogCapture() { core::LogCapture() = nullptr; }

    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;

    std::vector<Entry> entries() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_;
    }

    std::size_t count(std::uint32_t messageId) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::size_t n = 0;
        for (const auto& e : entries_) {
            if (e.messageId == messageId) ++n;
        }
        return n;
    }

private:
    mutable std::mutex mutex_;
    std::vector<Entry> entries_;
};

// Collects strings sent from other threads (e.g. CmcCommandHandler's
// sendToMec callback) and lets a test wait for one to arrive.
class MessageSink {
public:
    void operator()(const std::string& message) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            messages_.push_back(message);
        }
        cv_.notify_all();
    }

    std::vector<std::string> messages() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return messages_;
    }

    // True if a message starting with `prefix` arrives within `timeout`.
    bool waitFor(const std::string& prefix,
                 std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, timeout, [&] {
            for (const auto& m : messages_) {
                if (m.rfind(prefix, 0) == 0) return true;
            }
            return false;
        });
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<std::string> messages_;
};

} // namespace test
