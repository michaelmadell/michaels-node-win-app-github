using System.Diagnostics;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using CoreStationAgent.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace CoreStationAgent.Platform.Windows;

/// <summary>
/// The expensive metrics tier on Windows, sourced from performance counters
/// and the TCP/IP stack statistics.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsMetricsProvider : IMetricsProvider, IDisposable
{
    private readonly ISystemInformation _systemInformation;
    private readonly ILogger<WindowsMetricsProvider> _logger;

    private PerformanceCounter? _diskQueueCounter;
    private bool _diskCounterInitialized;

    // TCP statistics are cumulative, so a rate needs the previous sample.
    private long _previousSegmentsSent;
    private long _previousSegmentsResent;

    public WindowsMetricsProvider(
        ISystemInformation systemInformation,
        ILogger<WindowsMetricsProvider> logger)
    {
        _systemInformation = systemInformation;
        _logger = logger;
    }

    public void UpdateCounters()
    {
        var (sent, resent) = ReadTcpStatistics();
        _previousSegmentsSent = sent;
        _previousSegmentsResent = resent;

        // Rate counters return 0 on their first read; take a throwaway sample
        // now so the heartbeat's read has a baseline to difference against.
        _ = ReadDiskQueueLength();
    }

    public Task<SystemMetrics> CollectAllAsync(CancellationToken cancellationToken)
    {
        var metrics = new SystemMetrics
        {
            Performance = new PerformanceMetrics
            {
                CpuUsagePercent = _systemInformation.GetCpuUsagePercent(),
                RamUsagePercent = _systemInformation.GetRamUsagePercent(),
                Uptime = _systemInformation.GetSystemUptime(),
                FreeDiskSpaceGb = GetFreeDiskSpaceGb(),
                DiskQueueLength = ReadDiskQueueLength(),
                NetworkRetransRate = GetNetworkRetransRate(),
            },
            Gpu = CollectGpu(),
            Processes = CollectProcesses(),
            Updates = CheckUpdates(),
        };

        return Task.FromResult(metrics);
    }

    private string GetFreeDiskSpaceGb()
    {
        try
        {
            var systemRoot = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
            var drive = new DriveInfo(systemRoot);
            var freeGb = drive.AvailableFreeSpace / (1024.0 * 1024.0 * 1024.0);
            return freeGb.ToString("F1", CultureInfo.InvariantCulture);
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not read free disk space: {Message}", ex.Message);
            return "Error";
        }
    }

    private float ReadDiskQueueLength()
    {
        if (!_diskCounterInitialized)
        {
            _diskCounterInitialized = true;

            try
            {
                _diskQueueCounter = new PerformanceCounter(
                    "PhysicalDisk", "Avg. Disk Queue Length", "_Total", readOnly: true);
            }
            catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException
                                           or System.ComponentModel.Win32Exception)
            {
                // Counters can be disabled or corrupted; the rest of the
                // snapshot is still worth sending.
                _logger.LogWarning("Disk queue counter unavailable: {Message}", ex.Message);
                _diskQueueCounter = null;
            }
        }

        if (_diskQueueCounter is null)
        {
            return 0f;
        }

        try
        {
            return _diskQueueCounter.NextValue();
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not sample disk queue counter: {Message}", ex.Message);
            return 0f;
        }
    }

    private float GetNetworkRetransRate()
    {
        var (sent, resent) = ReadTcpStatistics();

        var sentDelta = sent - _previousSegmentsSent;
        var resentDelta = resent - _previousSegmentsResent;

        _previousSegmentsSent = sent;
        _previousSegmentsResent = resent;

        // Counters reset when the stack reloads; treat an impossible ratio as
        // a stale baseline rather than a 100% retransmit rate.
        if (sentDelta <= 0 || resentDelta < 0 || resentDelta > sentDelta)
        {
            return 0f;
        }

        return (float)resentDelta / sentDelta * 100f;
    }

    private (long Sent, long Resent) ReadTcpStatistics()
    {
        try
        {
            var statistics = IPGlobalProperties.GetIPGlobalProperties().GetTcpIPv4Statistics();
            return (statistics.SegmentsSent, statistics.SegmentsResent);
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException)
        {
            _logger.LogWarning("Could not read TCP statistics: {Message}", ex.Message);
            return (0, 0);
        }
    }

    private GpuMetrics CollectGpu()
    {
        var driverInfo = ReadGpuDriverInfo();
        var usage = ReadGpuUsagePercent();

        return new GpuMetrics { DriverInfo = driverInfo, UsagePercent = usage };
    }

    private string ReadGpuDriverInfo()
    {
        // Each adapter gets a numbered subkey under the display class. The
        // first one with a driver version is the primary adapter.
        const string displayClassKey =
            @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";

        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(displayClassKey);
            if (root is null)
            {
                return "Unknown";
            }

            foreach (var subKeyName in root.GetSubKeyNames())
            {
                if (!int.TryParse(subKeyName, out _))
                {
                    continue;
                }

                using var adapterKey = root.OpenSubKey(subKeyName);
                var description = adapterKey?.GetValue("DriverDesc")?.ToString();
                var version = adapterKey?.GetValue("DriverVersion")?.ToString();

                if (!string.IsNullOrEmpty(description) && !string.IsNullOrEmpty(version))
                {
                    return $"{description} (Driver {version})";
                }
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException
                                       or IOException)
        {
            _logger.LogWarning("Could not read GPU driver info: {Message}", ex.Message);
        }

        return "Unknown";
    }

    private float ReadGpuUsagePercent()
    {
        try
        {
            var category = new PerformanceCounterCategory("GPU Engine");

            // Utilisation is reported per engine instance per process; the
            // machine-wide figure is the sum across the 3D engines.
            var total = 0f;

            foreach (var instanceName in category.GetInstanceNames())
            {
                if (!instanceName.Contains("engtype_3D", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (var counter in category.GetCounters(instanceName))
                {
                    using (counter)
                    {
                        if (counter.CounterName == "Utilization Percentage")
                        {
                            total += counter.NextValue();
                        }
                    }
                }
            }

            return Math.Clamp(total, 0f, 100f);
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException
                                       or System.ComponentModel.Win32Exception)
        {
            _logger.LogDebug("GPU usage counters unavailable: {Message}", ex.Message);
            return 0f;
        }
    }

    private ProcessMetrics CollectProcesses()
    {
        try
        {
            var top = Process.GetProcesses()
                .Select(process =>
                {
                    try
                    {
                        return (Name: process.ProcessName, Id: process.Id, WorkingSet: process.WorkingSet64);
                    }
                    catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
                    {
                        // The process exited between enumeration and inspection.
                        return (Name: string.Empty, Id: 0, WorkingSet: 0L);
                    }
                    finally
                    {
                        process.Dispose();
                    }
                })
                .Where(entry => entry.WorkingSet > 0)
                .OrderByDescending(entry => entry.WorkingSet)
                .Take(5)
                .Select(entry => $"{entry.Id} {entry.Name} {entry.WorkingSet / 1024}");

            var formatted = string.Join('|', top);
            return new ProcessMetrics { HighRamProcesses = formatted.Length == 0 ? "none" : formatted };
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            _logger.LogWarning("Could not enumerate processes: {Message}", ex.Message);
            return new ProcessMetrics { HighRamProcesses = "none" };
        }
    }

    private UpdateStatus CheckUpdates()
    {
        try
        {
            using var rebootRequired = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired");

            if (rebootRequired is not null)
            {
                return new UpdateStatus { State = "Reboot Required" };
            }

            using var pending = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired\Pending");

            return new UpdateStatus { State = pending is not null ? "Pending Updates" : "Up to Date" };
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException
                                       or IOException)
        {
            _logger.LogWarning("Could not read Windows Update state: {Message}", ex.Message);
            return new UpdateStatus { State = "Unknown" };
        }
    }

    public void Dispose() => _diskQueueCounter?.Dispose();
}
