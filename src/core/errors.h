#pragma once

#include <source_location>
#include <print>

struct SerialError {
    int code;
    const char* message;
    std::source_location location;

    static SerialError fail(int code, const char* msg, const std::source_location& loc = std::source_location::current()) {
        return {code, msg, loc};
    }
};

inline void logError(const SerialError& err) {
    std::print("[ERROR] {} ({}:{} in {})\n",
        err.message,
        err.location.file_name(),
        err.location.line(),
        err.location.function_name());
}
