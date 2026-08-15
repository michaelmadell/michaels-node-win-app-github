namespace CoreStationAgent.Core;

/// <summary>
/// State-changing operations a C2A command can trigger on the host.
/// </summary>
public interface IPowerActions
{
    Task ShutdownAsync(string reason, CancellationToken cancellationToken);

    Task RestartAsync(string reason, CancellationToken cancellationToken);

    Task LockActiveSessionAsync(CancellationToken cancellationToken);

    Task LogoffActiveSessionAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Shows a notice to the signed-in user. Best-effort: a service in
    /// session 0 has no desktop, so implementations may only log.
    /// </summary>
    Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken);
}
