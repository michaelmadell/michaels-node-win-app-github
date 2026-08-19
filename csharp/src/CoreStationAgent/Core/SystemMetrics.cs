namespace CoreStationAgent.Core;

/// <summary>Performance counters sampled once per heartbeat.</summary>
public sealed record PerformanceMetrics
{
    public int CpuUsagePercent { get; init; }

    public int RamUsagePercent { get; init; }

    public float DiskQueueLength { get; init; }

    /// <summary>TCP retransmissions as a percentage of segments sent.</summary>
    public float NetworkRetransRate { get; init; }

    /// <summary>Formatted as "0d 00h 00m 00s".</summary>
    public string Uptime { get; init; } = "Unknown";

    /// <summary>Free space on the system drive, in GB, to one decimal place.</summary>
    public string FreeDiskSpaceGb { get; init; } = "0.0";
}

public sealed record GpuMetrics
{
    public string DriverInfo { get; init; } = "Unknown";

    public float UsagePercent { get; init; }
}

public sealed record ProcessMetrics
{
    /// <summary>Top RAM consumers, pipe-separated.</summary>
    public string HighRamProcesses { get; init; } = "none";
}

public sealed record UpdateStatus
{
    public string State { get; init; } = "Unknown";
}

/// <summary>A complete metrics snapshot for one heartbeat.</summary>
public sealed record SystemMetrics
{
    public PerformanceMetrics Performance { get; init; } = new();

    public GpuMetrics Gpu { get; init; } = new();

    public ProcessMetrics Processes { get; init; } = new();

    public UpdateStatus Updates { get; init; } = new();
}
