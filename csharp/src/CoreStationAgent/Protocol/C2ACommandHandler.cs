using CoreStationAgent.Configuration;
using CoreStationAgent.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreStationAgent.Protocol;

/// <summary>
/// Dispatches chassis-to-agent commands arriving on the "c2a, " channel.
///
/// The serial link is a fixed PCB trace to the MEC chip with no user-accessible
/// endpoint, so input here is treated as trusted chassis input.
/// </summary>
public sealed class C2ACommandHandler : IAsyncDisposable
{
    private const string CommandPrefix = "c2a,";

    private readonly IBmcChannel _channel;
    private readonly ISystemInformation _systemInformation;
    private readonly IPowerActions _powerActions;
    private readonly AgentOptions _options;
    private readonly ILogger<C2ACommandHandler> _logger;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private CancellationTokenSource? _pendingCancellation;
    private Task? _pendingAction;
    private string? _pendingVerb;

    public C2ACommandHandler(
        IBmcChannel channel,
        ISystemInformation systemInformation,
        IPowerActions powerActions,
        IOptions<AgentOptions> options,
        ILogger<C2ACommandHandler> logger)
    {
        _channel = channel;
        _systemInformation = systemInformation;
        _powerActions = powerActions;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// True when <paramref name="line"/> carries a C2A payload. Anything else
    /// on the wire is inbound chatter the agent only logs.
    /// </summary>
    public static bool TryExtractPayload(string line, out string payload)
    {
        payload = string.Empty;

        if (!line.StartsWith(CommandPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        payload = line[CommandPrefix.Length..].Trim();
        return payload.Length > 0;
    }

    /// <summary>Handles one payload (the text after the "c2a, " prefix).</summary>
    public async Task HandleAsync(string payload, CancellationToken cancellationToken)
    {
        var tokens = payload.Split(',').Select(t => t.Trim()).ToArray();
        if (tokens.Length == 0 || tokens[0].Length == 0)
        {
            await ShowFallbackAsync(payload, cancellationToken).ConfigureAwait(false);
            return;
        }

        var verb = tokens[0];

        if (Matches(verb, "ping"))
        {
            _channel.Send("pong");
            return;
        }

        if (Matches(verb, "status"))
        {
            _channel.Send(
                $"status, cpu={_systemInformation.GetCpuUsagePercent()}%, " +
                $"ram={_systemInformation.GetRamUsagePercent()}%, " +
                $"uptime={_systemInformation.GetSystemUptime()}");
            return;
        }

        if (Matches(verb, "ct"))
        {
            _channel.Send("ct", DurationParser.Format(DateTimeOffset.Now));
            return;
        }

        if (Matches(verb, "shutdown") || Matches(verb, "restart"))
        {
            await HandlePowerVerbAsync(verb, tokens, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (Matches(verb, "cancel"))
        {
            await CancelPendingAsync().ConfigureAwait(false);
            return;
        }

        if (Matches(verb, "lock"))
        {
            _logger.LogInformation("C2A command: lock active session");
            _channel.Send("locking");
            await _powerActions.LockActiveSessionAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        if (Matches(verb, "logoff"))
        {
            _logger.LogInformation("C2A command: log off active session");
            _channel.Send("loggingOff");
            await _powerActions.LogoffActiveSessionAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        await ShowFallbackAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    private async Task HandlePowerVerbAsync(string verb, string[] tokens, CancellationToken cancellationToken)
    {
        var modifier = tokens.Length > 1 ? tokens[1] : string.Empty;

        if (Matches(modifier, "force"))
        {
            var reason = JoinFrom(tokens, 2);
            _logger.LogInformation("C2A {Verb} received (forced). Reason: {Reason}",
                verb, string.IsNullOrEmpty(reason) ? "(none)" : reason);
            _channel.Send($"{verb}Executing");
            await InvokeActionAsync(verb, reason, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (Matches(modifier, "timeout"))
        {
            if (tokens.Length <= 2 || tokens[2].Length == 0)
            {
                _channel.Send($"{verb}Rejected, missing-timeout-value");
                return;
            }

            if (!DurationParser.TryParseDuration(tokens[2], out var duration))
            {
                _logger.LogWarning("C2A {Verb} rejected: invalid timeout '{Value}'", verb, tokens[2]);
                _channel.Send($"{verb}Rejected, invalid-timeout");
                return;
            }

            await ScheduleAsync(verb, DateTimeOffset.Now + duration, JoinFrom(tokens, 3)).ConfigureAwait(false);
            return;
        }

        if (Matches(modifier, "time"))
        {
            if (tokens.Length <= 2 || tokens[2].Length == 0)
            {
                _channel.Send($"{verb}Rejected, missing-time-value");
                return;
            }

            if (!DurationParser.TryParseLocalDateTime(tokens[2], out var deadline))
            {
                _logger.LogWarning("C2A {Verb} rejected: invalid time '{Value}'", verb, tokens[2]);
                _channel.Send($"{verb}Rejected, invalid-time");
                return;
            }

            await ScheduleAsync(verb, deadline, JoinFrom(tokens, 3)).ConfigureAwait(false);
            return;
        }

        // No modifier: warn the user, then act after the default grace period.
        var graceDeadline = DateTimeOffset.Now + TimeSpan.FromSeconds(_options.DefaultGracePeriodSeconds);
        await ScheduleAsync(verb, graceDeadline, JoinFrom(tokens, 1)).ConfigureAwait(false);
    }

    private async Task ScheduleAsync(string verb, DateTimeOffset deadline, string reason)
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            // A second scheduled action supersedes the first, matching the
            // single-pending-action model the BMC assumes.
            await CancelPendingCoreAsync().ConfigureAwait(false);

            var cts = new CancellationTokenSource();
            _pendingCancellation = cts;
            _pendingVerb = verb;
            _pendingAction = RunScheduledAsync(verb, deadline, reason, cts.Token);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task RunScheduledAsync(
        string verb,
        DateTimeOffset deadline,
        string reason,
        CancellationToken cancellationToken)
    {
        var deadlineText = DurationParser.Format(deadline);
        var reasonSuffix = string.IsNullOrEmpty(reason) ? string.Empty : $", {reason}";

        _logger.LogInformation("C2A {Verb} scheduled for {Deadline}. Reason: {Reason}",
            verb, deadlineText, string.IsNullOrEmpty(reason) ? "(none)" : reason);

        _channel.Send($"{verb}Pending, {deadlineText}{reasonSuffix}");

        await _powerActions.ShowMessageAsync(
            "Command from Chassis Controller",
            $"The chassis controller has scheduled a {verb} for {deadlineText}." +
            (string.IsNullOrEmpty(reason) ? string.Empty : $" Reason: {reason}"),
            CancellationToken.None).ConfigureAwait(false);

        var delay = deadline - DateTimeOffset.Now;
        if (delay > TimeSpan.Zero)
        {
            try
            {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("C2A {Verb} cancelled before execution", verb);
                _channel.Send($"{verb}Cancelled");
                return;
            }
        }

        if (cancellationToken.IsCancellationRequested)
        {
            _logger.LogInformation("C2A {Verb} cancelled before execution", verb);
            _channel.Send($"{verb}Cancelled");
            return;
        }

        _logger.LogInformation("C2A {Verb} scheduled time reached; executing", verb);
        _channel.Send($"{verb}Executing");
        await InvokeActionAsync(verb, reason, CancellationToken.None).ConfigureAwait(false);
    }

    private async Task CancelPendingAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_pendingCancellation is null)
            {
                _channel.Send("cancelled, none-pending");
                return;
            }

            // RunScheduledAsync emits "<verb>Cancelled" on its way out, so the
            // acknowledgement to the BMC is already covered.
            await CancelPendingCoreAsync().ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Cancels and reaps the pending action. Callers must hold <see cref="_gate"/>.
    /// </summary>
    private async Task CancelPendingCoreAsync()
    {
        var cts = _pendingCancellation;
        var action = _pendingAction;

        if (cts is null)
        {
            return;
        }

        _logger.LogInformation("Cancelling pending C2A {Verb}", _pendingVerb ?? "action");

        await cts.CancelAsync().ConfigureAwait(false);

        if (action is not null)
        {
            try
            {
                await action.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected: the scheduled delay was cancelled.
            }
        }

        cts.Dispose();
        _pendingCancellation = null;
        _pendingAction = null;
        _pendingVerb = null;
    }

    private Task InvokeActionAsync(string verb, string reason, CancellationToken cancellationToken) =>
        Matches(verb, "shutdown")
            ? _powerActions.ShutdownAsync(reason, cancellationToken)
            : _powerActions.RestartAsync(reason, cancellationToken);

    private Task ShowFallbackAsync(string message, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Unrecognized C2A command, surfacing to user: {Message}", message);
        return _powerActions.ShowMessageAsync("Command from BMC", message, cancellationToken);
    }

    private static bool Matches(string value, string expected) =>
        string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);

    private static string JoinFrom(string[] tokens, int index) =>
        tokens.Length <= index ? string.Empty : string.Join(", ", tokens.Skip(index));

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            await CancelPendingCoreAsync().ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }
}
