using CoreStationAgent.Configuration;
using CoreStationAgent.Protocol;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace CoreStationAgent.Tests;

public class C2ACommandHandlerTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    private readonly FakeBmcChannel _channel = new();
    private readonly FakeSystemInformation _systemInformation = new();
    private readonly FakePowerActions _powerActions = new();

    private C2ACommandHandler CreateHandler(int gracePeriodSeconds = 15)
    {
        var options = Options.Create(new AgentOptions { DefaultGracePeriodSeconds = gracePeriodSeconds });

        return new C2ACommandHandler(
            _channel,
            _systemInformation,
            _powerActions,
            options,
            NullLogger<C2ACommandHandler>.Instance);
    }

    [Theory]
    [InlineData("c2a, ping", "ping")]
    [InlineData("c2a,ping", "ping")]
    [InlineData("C2A, ping", "ping")]
    [InlineData("c2a,  shutdown, force  ", "shutdown, force")]
    public void TryExtractPayload_AcceptsC2ALines(string line, string expected)
    {
        Assert.True(C2ACommandHandler.TryExtractPayload(line, out var payload));
        Assert.Equal(expected, payload);
    }

    [Theory]
    [InlineData("HB")]
    [InlineData("hostname, NODE-1")]
    [InlineData("c2a,")]
    [InlineData("c2ax, ping")]
    public void TryExtractPayload_RejectsEverythingElse(string line)
    {
        Assert.False(C2ACommandHandler.TryExtractPayload(line, out _));
    }

    [Fact]
    public async Task Ping_RepliesPong()
    {
        await using var handler = CreateHandler();

        await handler.HandleAsync("ping", CancellationToken.None);

        Assert.Equal(["pong"], _channel.Lines);
    }

    [Fact]
    public async Task Status_ReportsCpuRamAndUptime()
    {
        _systemInformation.CpuUsage = 42;
        _systemInformation.RamUsage = 71;
        _systemInformation.Uptime = "1d 02h 03m 04s";

        await using var handler = CreateHandler();

        await handler.HandleAsync("status", CancellationToken.None);

        Assert.Equal(["status, cpu=42%, ram=71%, uptime=1d 02h 03m 04s"], _channel.Lines);
    }

    [Fact]
    public async Task Lock_AndLogoff_AcknowledgeThenAct()
    {
        await using var handler = CreateHandler();

        await handler.HandleAsync("lock", CancellationToken.None);
        await handler.HandleAsync("logoff", CancellationToken.None);

        Assert.Equal(["locking", "loggingOff"], _channel.Lines);
        Assert.True(_powerActions.Invoked("lock"));
        Assert.True(_powerActions.Invoked("logoff"));
    }

    [Fact]
    public async Task ForcedShutdown_ExecutesImmediately()
    {
        await using var handler = CreateHandler();

        await handler.HandleAsync("shutdown, force, maintenance window", CancellationToken.None);

        Assert.Contains("shutdownExecuting", _channel.Lines);
        Assert.True(_powerActions.Invoked("shutdown:maintenance window"));
    }

    [Fact]
    public async Task ForcedRestart_ExecutesImmediately()
    {
        await using var handler = CreateHandler();

        await handler.HandleAsync("restart, force", CancellationToken.None);

        Assert.Contains("restartExecuting", _channel.Lines);
        Assert.True(_powerActions.Invoked("restart:"));
    }

    [Fact]
    public async Task ScheduledShutdown_AnnouncesPendingThenExecutes()
    {
        await using var handler = CreateHandler();

        await handler.HandleAsync("shutdown, timeout, 1s, nightly patch", CancellationToken.None);

        Assert.Contains(_channel.Lines, line => line.StartsWith("shutdownPending, "));
        Assert.Contains(_channel.Lines, line => line.EndsWith(", nightly patch"));

        Assert.True(await _powerActions.WaitForAsync("shutdown:nightly patch", Timeout));
        Assert.Contains("shutdownExecuting", _channel.Lines);
    }

    [Fact]
    public async Task Cancel_StopsAPendingAction()
    {
        await using var handler = CreateHandler();

        await handler.HandleAsync("shutdown, timeout, 30s", CancellationToken.None);
        Assert.Contains(_channel.Lines, line => line.StartsWith("shutdownPending, "));

        await handler.HandleAsync("cancel", CancellationToken.None);

        Assert.True(await _channel.WaitForAsync("shutdownCancelled", Timeout));
        Assert.DoesNotContain("shutdownExecuting", _channel.Lines);
        Assert.DoesNotContain(_powerActions.Invocations, i => i.StartsWith("shutdown:"));
    }

    [Fact]
    public async Task Cancel_WithNothingPending_SaysSo()
    {
        await using var handler = CreateHandler();

        await handler.HandleAsync("cancel", CancellationToken.None);

        Assert.Equal(["cancelled, none-pending"], _channel.Lines);
    }

    [Theory]
    [InlineData("shutdown, timeout", "shutdownRejected, missing-timeout-value")]
    [InlineData("shutdown, timeout, banana", "shutdownRejected, invalid-timeout")]
    [InlineData("restart, time", "restartRejected, missing-time-value")]
    [InlineData("restart, time, yesterday", "restartRejected, invalid-time")]
    public async Task MalformedDeadlines_AreRejectedWithoutActing(string command, string expectedReply)
    {
        await using var handler = CreateHandler();

        await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal([expectedReply], _channel.Lines);
        Assert.Empty(_powerActions.Invocations);
    }

    [Fact]
    public async Task BareShutdown_UsesTheDefaultGracePeriod()
    {
        await using var handler = CreateHandler(gracePeriodSeconds: 1);

        await handler.HandleAsync("shutdown", CancellationToken.None);

        // The user gets a warning dialog before anything happens.
        Assert.Contains(_powerActions.Invocations,
            invocation => invocation.StartsWith("message:Command from Chassis Controller"));

        Assert.True(await _powerActions.WaitForAsync("shutdown:", Timeout));
    }

    [Fact]
    public async Task UnrecognizedCommand_IsSurfacedToTheUser()
    {
        await using var handler = CreateHandler();

        await handler.HandleAsync("frobnicate the widget", CancellationToken.None);

        Assert.Contains(_powerActions.Invocations,
            invocation => invocation.StartsWith("message:Command from BMC:"));
        Assert.Empty(_channel.Lines);
    }

    [Fact]
    public async Task SecondScheduledAction_SupersedesTheFirst()
    {
        await using var handler = CreateHandler();

        await handler.HandleAsync("shutdown, timeout, 30s", CancellationToken.None);
        await handler.HandleAsync("restart, timeout, 1s", CancellationToken.None);

        Assert.True(await _powerActions.WaitForAsync("restart:", Timeout));

        // The superseded shutdown must never fire.
        Assert.DoesNotContain(_powerActions.Invocations, i => i.StartsWith("shutdown:"));
    }

    [Fact]
    public async Task DisposingWithAPendingAction_CancelsIt()
    {
        var handler = CreateHandler();

        await handler.HandleAsync("shutdown, timeout, 30s", CancellationToken.None);
        await handler.DisposeAsync();

        Assert.DoesNotContain(_powerActions.Invocations, i => i.StartsWith("shutdown:"));
    }

    [Fact]
    public async Task CurrentTime_IsReportedInTheParseableFormat()
    {
        await using var handler = CreateHandler();

        await handler.HandleAsync("ct", CancellationToken.None);

        var reply = Assert.Single(_channel.Lines);
        Assert.StartsWith("ct, ", reply);
        Assert.True(DurationParser.TryParseLocalDateTime(reply["ct, ".Length..], out _));
    }
}
