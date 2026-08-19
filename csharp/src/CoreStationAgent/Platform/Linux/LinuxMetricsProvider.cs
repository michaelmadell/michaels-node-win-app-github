using System.Globalization;
using CoreStationAgent.Core;
using CoreStationAgent.Platform.Common;
using Microsoft.Extensions.Logging;

namespace CoreStationAgent.Platform.Linux;

/// <summary>
/// The expensive metrics tier on Linux: /proc and /sys where possible, vendor
/// tools where there is no other source.
/// </summary>
public sealed class LinuxMetricsProvider : IMetricsProvider
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(5);

    // Querying the package manager reads a large database and routinely takes
    // longer than the other probes. Timing it out would silently downgrade the
    // answer to "Up to Date", so it gets its own budget.
    private static readonly TimeSpan PackageQueryTimeout = TimeSpan.FromSeconds(30);

    private readonly ISystemInformation _systemInformation;
    private readonly IProcessRunner _processRunner;
    private readonly ILogger<LinuxMetricsProvider> _logger;

    // TCP counters are cumulative; a rate needs the previous sample.
    private ulong _previousSegmentsOut;
    private ulong _previousRetransSegments;

    public LinuxMetricsProvider(
        ISystemInformation systemInformation,
        IProcessRunner processRunner,
        ILogger<LinuxMetricsProvider> logger)
    {
        _systemInformation = systemInformation;
        _processRunner = processRunner;
        _logger = logger;
    }

    public void UpdateCounters()
    {
        var (segmentsOut, retransSegments) = ReadTcpCounters();
        _previousSegmentsOut = segmentsOut;
        _previousRetransSegments = retransSegments;
    }

    public async Task<SystemMetrics> CollectAllAsync(CancellationToken cancellationToken)
    {
        var gpuTask = CollectGpuAsync(cancellationToken);
        var updatesTask = CheckUpdatesAsync(cancellationToken);
        var processesTask = CollectProcessesAsync(cancellationToken);

        await Task.WhenAll(gpuTask, updatesTask, processesTask).ConfigureAwait(false);

        return new SystemMetrics
        {
            Performance = new PerformanceMetrics
            {
                CpuUsagePercent = _systemInformation.GetCpuUsagePercent(),
                RamUsagePercent = _systemInformation.GetRamUsagePercent(),
                Uptime = _systemInformation.GetSystemUptime(),
                FreeDiskSpaceGb = GetFreeDiskSpaceGb("/"),
                DiskQueueLength = GetDiskQueueLength(),
                NetworkRetransRate = GetNetworkRetransRate(),
            },
            Gpu = await gpuTask.ConfigureAwait(false),
            Updates = await updatesTask.ConfigureAwait(false),
            Processes = await processesTask.ConfigureAwait(false),
        };
    }

    private string GetFreeDiskSpaceGb(string path)
    {
        try
        {
            var drive = new DriveInfo(path);
            var freeGb = drive.AvailableFreeSpace / (1024.0 * 1024.0 * 1024.0);
            return freeGb.ToString("F1", CultureInfo.InvariantCulture);
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not read free disk space for {Path}: {Message}", path, ex.Message);
            return "Error";
        }
    }

    /// <summary>
    /// Sums the in-flight request count across whole disks, the closest
    /// analogue to the Windows "Avg. Disk Queue Length" counter.
    /// </summary>
    private float GetDiskQueueLength()
    {
        const string path = "/proc/diskstats";
        var total = 0f;

        try
        {
            foreach (var line in File.ReadLines(path))
            {
                var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                // major, minor, name, then the read/write stat columns.
                if (fields.Length < 12)
                {
                    continue;
                }

                var deviceName = fields[2];
                if (IsVirtualDevice(deviceName) || IsPartition(deviceName))
                {
                    continue;
                }

                // Column 12 overall (index 11) is in_flight.
                if (ulong.TryParse(fields[11], out var inFlight))
                {
                    total += inFlight;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not read {Path}: {Message}", path, ex.Message);
        }

        return total;
    }

    private static bool IsVirtualDevice(string deviceName) =>
        deviceName.StartsWith("loop", StringComparison.Ordinal) ||
        deviceName.StartsWith("ram", StringComparison.Ordinal) ||
        deviceName.StartsWith("zram", StringComparison.Ordinal) ||
        deviceName.StartsWith("dm-", StringComparison.Ordinal);

    /// <summary>
    /// Distinguishes partitions from whole disks. NVMe and eMMC whole-disk
    /// names already end in a digit, so only a "p&lt;N&gt;" suffix marks a
    /// partition there; elsewhere a trailing digit is enough.
    /// </summary>
    private static bool IsPartition(string deviceName)
    {
        if (deviceName.Length == 0)
        {
            return false;
        }

        if (deviceName.StartsWith("nvme", StringComparison.Ordinal) ||
            deviceName.StartsWith("mmcblk", StringComparison.Ordinal))
        {
            var firstDigit = deviceName.IndexOfAny("0123456789".ToCharArray());
            return firstDigit >= 0 && deviceName.IndexOf('p', firstDigit) >= 0;
        }

        return char.IsDigit(deviceName[^1]);
    }

    private float GetNetworkRetransRate()
    {
        var (segmentsOut, retransSegments) = ReadTcpCounters();

        var outDelta = segmentsOut - _previousSegmentsOut;
        var retransDelta = retransSegments - _previousRetransSegments;

        _previousSegmentsOut = segmentsOut;
        _previousRetransSegments = retransSegments;

        // Counters reset on overflow or interface reload; a retransmit count
        // above the send count means the baseline is stale, not a 100% rate.
        if (outDelta == 0 || retransDelta > outDelta)
        {
            return 0f;
        }

        return (float)retransDelta / outDelta * 100f;
    }

    /// <summary>
    /// Reads OutSegs and RetransSegs from the Tcp: block of /proc/net/snmp,
    /// which is a header row followed by a values row.
    /// </summary>
    private (ulong SegmentsOut, ulong RetransSegments) ReadTcpCounters()
    {
        const string path = "/proc/net/snmp";

        try
        {
            string? headerLine = null;

            foreach (var line in File.ReadLines(path))
            {
                if (!line.StartsWith("Tcp:", StringComparison.Ordinal))
                {
                    continue;
                }

                if (headerLine is null)
                {
                    headerLine = line;
                    continue;
                }

                var headers = headerLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                var values = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                // Look the columns up by name rather than position: the kernel
                // has added fields to this table before.
                return (
                    ReadColumn(headers, values, "OutSegs"),
                    ReadColumn(headers, values, "RetransSegs"));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not read {Path}: {Message}", path, ex.Message);
        }

        return (0, 0);
    }

    private static ulong ReadColumn(string[] headers, string[] values, string columnName)
    {
        var index = Array.IndexOf(headers, columnName);
        if (index < 0 || index >= values.Length)
        {
            return 0;
        }

        return ulong.TryParse(values[index], out var value) ? value : 0;
    }

    private async Task<GpuMetrics> CollectGpuAsync(CancellationToken cancellationToken)
    {
        // NVIDIA: nvidia-smi answers both questions directly.
        var nvidiaDriver = await _processRunner.RunAsync(
            "nvidia-smi",
            ["--query-gpu=driver_version", "--format=csv,noheader"],
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(nvidiaDriver))
        {
            var usageText = await _processRunner.RunAsync(
                "nvidia-smi",
                ["--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
                CommandTimeout,
                cancellationToken).ConfigureAwait(false);

            return new GpuMetrics
            {
                DriverInfo = $"NVIDIA Driver: {nvidiaDriver.Split('\n')[0].Trim()}",
                UsagePercent = AverageOfLines(usageText),
            };
        }

        // AMD: amdgpu exposes a busy percentage in sysfs, no tooling needed.
        var amdBusy = ReadFirstSysfsValue("/sys/class/drm", "device/gpu_busy_percent");
        if (amdBusy is not null)
        {
            return new GpuMetrics
            {
                DriverInfo = "AMD/Radeon GPU Detected (amdgpu Kernel Driver)",
                UsagePercent = amdBusy.Value,
            };
        }

        // Intel integrated graphics: presence is visible in sysfs, but the
        // busy percentage needs intel_gpu_top, which may not be installed.
        if (Directory.Exists("/sys/module/i915"))
        {
            return new GpuMetrics
            {
                DriverInfo = "Intel Integrated Graphics (i915 Kernel Driver)",
                UsagePercent = 0f,
            };
        }

        return new GpuMetrics { DriverInfo = "Unknown/Unsupported GPU Driver", UsagePercent = 0f };
    }

    private float? ReadFirstSysfsValue(string root, string relativePath)
    {
        try
        {
            if (!Directory.Exists(root))
            {
                return null;
            }

            foreach (var cardDirectory in Directory.EnumerateDirectories(root, "card*"))
            {
                var file = Path.Combine(cardDirectory, relativePath);
                if (!File.Exists(file))
                {
                    continue;
                }

                var text = File.ReadAllText(file).Trim();
                if (float.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var value))
                {
                    return value;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug("Could not read sysfs value {Path}: {Message}", relativePath, ex.Message);
        }

        return null;
    }

    private static float AverageOfLines(string text)
    {
        var values = text
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => float.TryParse(line.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var v)
                ? v
                : (float?)null)
            .Where(v => v.HasValue)
            .Select(v => v!.Value)
            .ToList();

        return values.Count == 0 ? 0f : values.Average();
    }

    private async Task<ProcessMetrics> CollectProcessesAsync(CancellationToken cancellationToken)
    {
        var output = await _processRunner.RunAsync(
            "ps",
            ["ax", "--sort=-rss", "-o", "pid,user,rss,comm", "--no-headers"],
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(output))
        {
            return new ProcessMetrics { HighRamProcesses = "none" };
        }

        var top = output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Take(5)
            .Select(line => string.Join(' ', line.Split(' ', StringSplitOptions.RemoveEmptyEntries)));

        // Pipe-separated so the whole list stays on one comma-delimited line.
        return new ProcessMetrics { HighRamProcesses = string.Join('|', top) };
    }

    private async Task<UpdateStatus> CheckUpdatesAsync(CancellationToken cancellationToken)
    {
        if (File.Exists("/var/run/reboot-required"))
        {
            return new UpdateStatus { State = "Reboot Required" };
        }

        var pending = await CountPendingUpdatesAsync(cancellationToken).ConfigureAwait(false);

        // A failed query is reported as unknown rather than as "Up to Date":
        // the two mean very different things to whoever reads the dashboard,
        // and the value would otherwise flap whenever the query was slow.
        return new UpdateStatus
        {
            State = pending switch
            {
                null => "Unknown",
                0 => "Up to Date",
                _ => $"Pending Upgrades ({pending})",
            },
        };
    }

    /// <summary>
    /// Counts upgradable packages, or returns null when no supported package
    /// manager answered.
    /// </summary>
    private async Task<int?> CountPendingUpdatesAsync(CancellationToken cancellationToken)
    {
        // Debian/Ubuntu.
        var aptOutput = await _processRunner.RunAsync(
            "apt-get", ["--simulate", "--quiet", "upgrade"], PackageQueryTimeout, cancellationToken)
            .ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(aptOutput))
        {
            return aptOutput
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Count(line => line.StartsWith("Inst ", StringComparison.Ordinal));
        }

        // RHEL/Fedora. "check-update" exits 100 when updates exist, which the
        // runner treats as failure, so ask for a list instead.
        var dnfOutput = await _processRunner.RunAsync(
            "dnf", ["--quiet", "list", "--upgrades"], PackageQueryTimeout, cancellationToken)
            .ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(dnfOutput))
        {
            return dnfOutput
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Count(line => !line.StartsWith("Last metadata", StringComparison.Ordinal) &&
                               !line.StartsWith("Available", StringComparison.OrdinalIgnoreCase));
        }

        return null;
    }
}
