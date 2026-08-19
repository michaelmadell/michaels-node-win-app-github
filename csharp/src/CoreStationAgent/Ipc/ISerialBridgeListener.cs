namespace CoreStationAgent.Ipc;

/// <summary>
/// Platform-agnostic contract for the authenticated serial IPC bridge
/// listener. <see cref="Workers.SerialBridgeService"/> selects the right
/// implementation at runtime (Windows named pipe vs. Linux Unix domain
/// socket) the same way the rest of this project picks platform
/// implementations (see Program.cs's IMetricsProvider factories), rather
/// than compiling two separate binaries.
/// </summary>
public interface ISerialBridgeListener
{
    /// <summary>
    /// Listens and accepts connections until <paramref name="cancellationToken"/>
    /// is cancelled. For each authenticated client, forwards every complete
    /// line it sends to <paramref name="onAuthenticatedLine"/> -- one call
    /// per message, in arrival order, with no re-authentication required
    /// per message (spec.md FR-009, Acceptance Scenario US1.2). Rejected
    /// connections never reach this callback at all.
    /// </summary>
    Task RunAsync(Action<string> onAuthenticatedLine, CancellationToken cancellationToken);
}
