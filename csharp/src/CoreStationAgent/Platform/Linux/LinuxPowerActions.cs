using CoreStationAgent.Core;
using CoreStationAgent.Platform.Common;
using Microsoft.Extensions.Logging;

namespace CoreStationAgent.Platform.Linux;

/// <summary>
/// Power and session control through systemd-logind.
/// </summary>
public sealed class LinuxPowerActions : IPowerActions
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(15);

    private readonly IProcessRunner _processRunner;
    private readonly ILogger<LinuxPowerActions> _logger;

    public LinuxPowerActions(IProcessRunner processRunner, ILogger<LinuxPowerActions> logger)
    {
        _processRunner = processRunner;
        _logger = logger;
    }

    public async Task ShutdownAsync(string reason, CancellationToken cancellationToken)
    {
        _logger.LogWarning("Powering off the host. Reason: {Reason}",
            string.IsNullOrEmpty(reason) ? "(none)" : reason);

        await _processRunner.RunAsync("systemctl", ["poweroff"], CommandTimeout, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task RestartAsync(string reason, CancellationToken cancellationToken)
    {
        _logger.LogWarning("Restarting the host. Reason: {Reason}",
            string.IsNullOrEmpty(reason) ? "(none)" : reason);

        await _processRunner.RunAsync("systemctl", ["reboot"], CommandTimeout, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task LockActiveSessionAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Locking active sessions");

        await _processRunner.RunAsync("loginctl", ["lock-sessions"], CommandTimeout, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task LogoffActiveSessionAsync(CancellationToken cancellationToken)
    {
        var sessionId = await GetActiveSessionIdAsync(cancellationToken).ConfigureAwait(false);

        if (sessionId is null)
        {
            _logger.LogInformation("Log off requested but no active session was found");
            return;
        }

        _logger.LogInformation("Terminating session {SessionId}", sessionId);

        await _processRunner.RunAsync(
            "loginctl", ["terminate-session", sessionId], CommandTimeout, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Notice for user - {Title}: {Message}", title, message);

        // wall reaches every logged-in terminal without needing a desktop
        // session, which a service running outside the user's session lacks.
        await _processRunner.RunAsync(
            "wall", ["--nobanner", $"{title}: {message}"], CommandTimeout, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<string?> GetActiveSessionIdAsync(CancellationToken cancellationToken)
    {
        var output = await _processRunner.RunAsync(
            "loginctl", ["list-sessions", "--no-legend"], CommandTimeout, cancellationToken)
            .ConfigureAwait(false);

        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length >= 1 && !string.IsNullOrWhiteSpace(fields[0]))
            {
                return fields[0];
            }
        }

        return null;
    }
}
