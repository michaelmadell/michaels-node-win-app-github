using CoreStationAgent.Serial;
using Xunit;

namespace CoreStationAgent.Tests;

public class LineFramerTests
{
    [Fact]
    public void CompleteLine_IsReturned()
    {
        var framer = new LineFramer();

        var lines = framer.Append("c2a, ping\r\n");

        Assert.Equal(["c2a, ping"], lines);
    }

    [Fact]
    public void CrLfPair_YieldsOneLineNotTwo()
    {
        var framer = new LineFramer();

        var lines = framer.Append("HB\r\nHB\r\n");

        Assert.Equal(["HB", "HB"], lines);
    }

    [Fact]
    public void PartialLine_IsBufferedUntilTerminatorArrives()
    {
        var framer = new LineFramer();

        Assert.Empty(framer.Append("c2a, sh"));
        Assert.Empty(framer.Append("utdown"));

        var lines = framer.Append(" force\r\n");

        Assert.Equal(["c2a, shutdown force"], lines);
    }

    [Fact]
    public void TrailingPartial_IsHeldBackAndCompletedLater()
    {
        var framer = new LineFramer();

        var first = framer.Append("first\r\nsecond-par");
        Assert.Equal(["first"], first);

        var second = framer.Append("tial\r\n");
        Assert.Equal(["second-partial"], second);
    }

    [Fact]
    public void LoneLf_TerminatesALine()
    {
        var framer = new LineFramer();

        Assert.Equal(["ping"], framer.Append("ping\n"));
    }

    [Fact]
    public void Reset_DiscardsBufferedPartial()
    {
        var framer = new LineFramer();

        framer.Append("stale-part");
        framer.Reset();

        Assert.Equal(["fresh"], framer.Append("fresh\r\n"));
    }

    [Fact]
    public void OversizedBufferWithoutTerminator_IsDiscarded()
    {
        var framer = new LineFramer();

        // A peer that never terminates a line must not grow the buffer forever.
        framer.Append(new string('x', 70_000));

        Assert.Equal(["recovered"], framer.Append("recovered\r\n"));
    }
}
