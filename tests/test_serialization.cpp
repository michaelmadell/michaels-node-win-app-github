// Serial link framing (src/modules/serial/LineFramer.h). The BMC protocol is
// newline-delimited text ("cpuUsage, 12%\r\n"), not a binary frame format, so
// "serialization" here is line splitting: terminators, partial lines across
// reads, empty lines, and hostile input.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "modules/serial/LineFramer.h"

using serial::ExtractLines;
using Lines = std::vector<std::string>;

TEST(LineFramer, EmptyBufferYieldsNothing) {
    std::string buffer;
    EXPECT_TRUE(ExtractLines(buffer).empty());
    EXPECT_TRUE(buffer.empty());
}

TEST(LineFramer, AcceptsEveryTerminatorStyle) {
    for (const char* terminator : { "\r\n", "\n", "\r", "\n\r" }) {
        std::string buffer = std::string("ping") + terminator + "status" + terminator;
        EXPECT_EQ(ExtractLines(buffer), (Lines{ "ping", "status" })) << "terminator: " << (terminator[0] == '\r' ? "CR" : "LF") << (terminator[1] ? "+2" : "");
        EXPECT_TRUE(buffer.empty());
    }
}

TEST(LineFramer, PartialLineStaysBufferedUntilCompleted) {
    std::string buffer = "c2a, sta";
    EXPECT_TRUE(ExtractLines(buffer).empty());
    EXPECT_EQ(buffer, "c2a, sta");

    buffer += "tus\r";
    EXPECT_EQ(ExtractLines(buffer), Lines{ "c2a, status" });

    // The "\n" of a CRLF split across two reads is consumed as an empty line.
    buffer += "\nping\r\n";
    EXPECT_EQ(ExtractLines(buffer), Lines{ "ping" });
    EXPECT_TRUE(buffer.empty());
}

TEST(LineFramer, CompleteLinesBeforeAPartialOne) {
    std::string buffer = "a\r\nb\r\nhalf";
    EXPECT_EQ(ExtractLines(buffer), (Lines{ "a", "b" }));
    EXPECT_EQ(buffer, "half");
}

TEST(LineFramer, EmptyLinesAreDropped) {
    std::string buffer = "\r\n\r\n\n\rping\r\n\r\n\r\n";
    EXPECT_EQ(ExtractLines(buffer), Lines{ "ping" });
    EXPECT_TRUE(buffer.empty());
}

TEST(LineFramer, OnlyOneTerminatorPairIsCollapsed) {
    // "\r\n" is one terminator; a following "\r\n" is a second (empty) line,
    // not part of the first terminator.
    std::string buffer = "a\r\n\r\nb\n";
    EXPECT_EQ(ExtractLines(buffer), (Lines{ "a", "b" }));
}

TEST(LineFramer, PayloadIsPassedThroughVerbatim) {
    // Commas, spaces and non-ASCII bytes are the parser's business, not the
    // framer's.
    std::string buffer = "c2a, shutdown, timeout, 30s, Grüße \t \r\n";
    EXPECT_EQ(ExtractLines(buffer), Lines{ "c2a, shutdown, timeout, 30s, Grüße \t " });
}

TEST(LineFramer, EmbeddedNulAndBinaryBytesStayInTheLine) {
    std::string payload("a\0b\x01\xff", 5);
    std::string buffer = payload + "\n";
    Lines lines = ExtractLines(buffer);
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_EQ(lines[0], payload);
}

TEST(LineFramer, OversizedLineIsNotTruncated) {
    // Documents current behaviour: there is no maximum line length - a long
    // line is delivered whole, and an unterminated one keeps growing the
    // buffer until a terminator arrives.
    std::string big(64 * 1024, 'x');
    std::string buffer = big;
    EXPECT_TRUE(ExtractLines(buffer).empty());
    EXPECT_EQ(buffer.size(), big.size());

    buffer += "\r\n";
    Lines lines = ExtractLines(buffer);
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_EQ(lines[0].size(), big.size());
}

TEST(LineFramer, ManyLinesInOneRead) {
    std::string buffer;
    for (int i = 0; i < 1000; ++i) {
        buffer += "line" + std::to_string(i) + "\r\n";
    }
    Lines lines = ExtractLines(buffer);
    ASSERT_EQ(lines.size(), 1000u);
    EXPECT_EQ(lines.front(), "line0");
    EXPECT_EQ(lines.back(), "line999");
}
