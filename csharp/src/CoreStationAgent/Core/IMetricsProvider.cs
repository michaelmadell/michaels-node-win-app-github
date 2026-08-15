namespace CoreStationAgent.Core;

/// <summary>
/// The expensive metrics tier: disk, network, GPU and update state. Kept
/// separate from <see cref="ISystemInformation"/> so it can be switched off
/// wholesale (Agent:EnableMetrics) without disabling C2A status replies.
/// </summary>
public interface IMetricsProvider
{
    /// <summary>
    /// Takes the baseline sample that rate-style counters need. Called once
    /// before the first collection and again ahead of each heartbeat.
    /// </summary>
    void UpdateCounters();

    Task<SystemMetrics> CollectAllAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Stand-in used when metrics collection is disabled, so the heartbeat loop
/// does not need a null check.
/// </summary>
public sealed class NullMetricsProvider : IMetricsProvider
{
    public void UpdateCounters()
    {
    }

    public Task<SystemMetrics> CollectAllAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new SystemMetrics());
}
