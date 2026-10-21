#pragma once

// Serial line framing, split out of SerialManager::ProcessIncomingData so it
// is unit-testable without a port (see tests/test_serialization.cpp).
//
// The BMC link is newline-delimited text: a line ends at '\r', '\n' or a
// two-character "\r\n" / "\n\r" pair. Empty lines are dropped. Anything
// after the last terminator is an incomplete line and stays in the buffer
// until more bytes arrive. There is no maximum line length.

#include <string>
#include <vector>

namespace serial {

// Removes every complete line from the front of `buffer` and returns them in
// order.
inline std::vector<std::string> ExtractLines(std::string& buffer) {
    std::vector<std::string> lines;
    size_t pos = 0;
    while ((pos = buffer.find_first_of("\r\n")) != std::string::npos) {
        std::string line = buffer.substr(0, pos);
        if (!line.empty()) {
            lines.push_back(std::move(line));
        }
        buffer.erase(0, pos + 1);
        if (!buffer.empty() && (buffer[0] == '\r' || buffer[0] == '\n')) {
            buffer.erase(0, 1);
        }
    }
    return lines;
}

} // namespace serial
