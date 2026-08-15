using CoreStationAgent.Protocol;
using Xunit;

namespace CoreStationAgent.Tests;

public class DurationParserTests
{
    [Theory]
    [InlineData("30s", 30)]
    [InlineData("5m", 300)]
    [InlineData("1h", 3600)]
    [InlineData("2H", 7200)]
    public void ValidDurations_Parse(string input, int expectedSeconds)
    {
        Assert.True(DurationParser.TryParseDuration(input, out var duration));
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), duration);
    }

    [Theory]
    [InlineData("")]
    [InlineData("s")]
    [InlineData("30")]
    [InlineData("30x")]
    [InlineData("abc")]
    [InlineData("3 0s")]
    [InlineData("-5m")]
    [InlineData("0s")]
    [InlineData("1.5h")]
    public void MalformedDurations_AreRejected(string input)
    {
        // A rejected duration becomes a "Rejected" reply; silently coercing one
        // to zero would turn a typo into an immediate shutdown.
        Assert.False(DurationParser.TryParseDuration(input, out _));
    }

    [Fact]
    public void NullDuration_IsRejected()
    {
        Assert.False(DurationParser.TryParseDuration(null, out _));
    }

    [Fact]
    public void ValidLocalDateTime_Parses()
    {
        Assert.True(DurationParser.TryParseLocalDateTime("2026-08-15 17:30:00", out var deadline));

        Assert.Equal(2026, deadline.Year);
        Assert.Equal(8, deadline.Month);
        Assert.Equal(15, deadline.Day);
        Assert.Equal(17, deadline.Hour);
        Assert.Equal(30, deadline.Minute);
    }

    [Theory]
    [InlineData("2026-08-15")]
    [InlineData("15-08-2026 17:30:00")]
    [InlineData("2026-13-01 00:00:00")]
    [InlineData("not-a-time")]
    [InlineData("")]
    public void MalformedDateTimes_AreRejected(string input)
    {
        Assert.False(DurationParser.TryParseLocalDateTime(input, out _));
    }

    [Fact]
    public void Format_RoundTripsThroughTheParser()
    {
        var original = new DateTimeOffset(2026, 8, 15, 17, 30, 45, TimeSpan.Zero).ToLocalTime();

        var formatted = DurationParser.Format(original);

        Assert.True(DurationParser.TryParseLocalDateTime(formatted, out var reparsed));
        Assert.Equal(original.DateTime, reparsed.DateTime);
    }
}
