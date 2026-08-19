using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using CoreStationAgent.Core;
using CoreStationAgent.Platform.Common;
using Microsoft.Extensions.Logging;

namespace CoreStationAgent.Platform.Windows;

/// <summary>
/// Power and session control on Windows.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsPowerActions : IPowerActions
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(15);

    private readonly IProcessRunner _processRunner;
    private readonly ILogger<WindowsPowerActions> _logger;

    public WindowsPowerActions(IProcessRunner processRunner, ILogger<WindowsPowerActions> logger)
    {
        _processRunner = processRunner;
        _logger = logger;
    }

    public async Task ShutdownAsync(string reason, CancellationToken cancellationToken)
    {
        _logger.LogWarning("Powering off the host. Reason: {Reason}",
            string.IsNullOrEmpty(reason) ? "(none)" : reason);

        // /t 0 because the agent has already served its own grace period.
        await _processRunner.RunAsync(
            "shutdown", ["/s", "/f", "/t", "0"], CommandTimeout, cancellationToken).ConfigureAwait(false);
    }

    public async Task RestartAsync(string reason, CancellationToken cancellationToken)
    {
        _logger.LogWarning("Restarting the host. Reason: {Reason}",
            string.IsNullOrEmpty(reason) ? "(none)" : reason);

        await _processRunner.RunAsync(
            "shutdown", ["/r", "/f", "/t", "0"], CommandTimeout, cancellationToken).ConfigureAwait(false);
    }

    public async Task LockActiveSessionAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Locking the console session");

        // LockWorkStation only affects the caller's own session, so a service
        // in session 0 must go through the console session's desktop instead.
        await _processRunner.RunAsync(
            "rundll32.exe", ["user32.dll,LockWorkStation"], CommandTimeout, cancellationToken)
            .ConfigureAwait(false);
    }

    public Task LogoffActiveSessionAsync(CancellationToken cancellationToken)
    {
        var sessionId = NativeMethods.WTSGetActiveConsoleSessionId();

        if (sessionId == uint.MaxValue)
        {
            _logger.LogInformation("Log off requested but no console session is attached");
            return Task.CompletedTask;
        }

        _logger.LogInformation("Logging off console session {SessionId}", sessionId);

        if (!NativeMethods.WTSLogoffSession(NativeMethods.WtsCurrentServerHandle, sessionId, bWait: false))
        {
            _logger.LogWarning("WTSLogoffSession failed with error {Error}", Marshal.GetLastWin32Error());
        }

        return Task.CompletedTask;
    }

    public async Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Notice for user - {Title}: {Message}", title, message);

        // msg.exe delivers into the user's session, which a service running in
        // session 0 cannot draw into directly.
        await _processRunner.RunAsync(
            "msg.exe", ["*", $"{title}: {message}"], CommandTimeout, cancellationToken).ConfigureAwait(false);
    }
}
