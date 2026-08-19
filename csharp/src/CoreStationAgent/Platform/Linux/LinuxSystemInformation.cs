using System.Globalization;
using CoreStationAgent.Core;
using CoreStationAgent.Platform.Common;
using Microsoft.Extensions.Logging;

namespace CoreStationAgent.Platform.Linux;

/// <summary>
/// Host facts sourced from /proc, /sys and logind.
/// </summary>
public sealed class LinuxSystemInformation : ISystemInformation
{
    private readonly NetworkInterfaceReader _networkReader;
    private readonly IProcessRunner _processRunner;
    private readonly ILogger<LinuxSystemInformation> _logger;

    // Baseline for the CPU delta; /proc/stat reports cumulative jiffies, so a
    // percentage only exists relative to a previous sample.
    private ulong _previousTotalTime;
    private ulong _previousIdleTime;

    public LinuxSystemInformation(
        NetworkInterfaceReader networkReader,
        IProcessRunner processRunner,
        ILogger<LinuxSystemInformation> logger)
    {
        _networkReader = networkReader;
        _processRunner = processRunner;
        _logger = logger;
    }

    public string GetHostname()
    {
        try
        {
            return Environment.MachineName;
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning("Could not read hostname: {Message}", ex.Message);
            return "unknown";
        }
    }

    public string GetLoggedInUser()
    {
        // loginctl reports the seat's active session even though this process
        // runs as root, which "whoami" would not.
        var output = _processRunner.Run(
            "loginctl", ["list-sessions", "--no-legend"], TimeSpan.FromSeconds(5));

        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            // Columns: SESSION UID USER SEAT TTY
            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length >= 3 && !string.IsNullOrWhiteSpace(fields[2]))
            {
                return fields[2];
            }
        }

        return "none";
    }

    public string GetOsVersion()
    {
        const string path = "/etc/os-release";
        try
        {
            if (File.Exists(path))
            {
                foreach (var line in File.ReadLines(path))
                {
                    if (line.StartsWith("PRETTY_NAME=", StringComparison.Ordinal))
                    {
                        return line["PRETTY_NAME=".Length..].Trim('"', ' ');
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not read {Path}: {Message}", path, ex.Message);
        }

        return Environment.OSVersion.VersionString;
    }

    public string GetOsBuild()
    {
        try
        {
            return File.Exists("/proc/sys/kernel/osrelease")
                ? File.ReadAllText("/proc/sys/kernel/osrelease").Trim()
                : Environment.OSVersion.Version.ToString();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not read kernel release: {Message}", ex.Message);
            return "unknown";
        }
    }

    public string GetCurrentSessionState()
    {
        var output = _processRunner.Run(
            "loginctl", ["list-sessions", "--no-legend"], TimeSpan.FromSeconds(5));

        // Map logind onto the WTS vocabulary the BMC already speaks: any live
        // graphical session counts as logged on, otherwise nobody is signed in.
        return string.IsNullOrWhiteSpace(output) ? SessionState.Logoff : SessionState.Logon;
    }

    public IReadOnlyList<NetworkInterfaceInfo> GetNetworkInterfaces() => _networkReader.Read();

    public int GetCpuUsagePercent()
    {
        if (!TryReadCpuTimes(out var totalTime, out var idleTime))
        {
            return 0;
        }

        var totalDelta = totalTime - _previousTotalTime;
        var idleDelta = idleTime - _previousIdleTime;

        _previousTotalTime = totalTime;
        _previousIdleTime = idleTime;

        if (totalDelta == 0)
        {
            return 0;
        }

        var usage = (int)Math.Round((1.0 - ((double)idleDelta / totalDelta)) * 100.0);
        return Math.Clamp(usage, 0, 100);
    }

    public int GetRamUsagePercent()
    {
        long totalKb = 0;
        long availableKb = 0;

        try
        {
            foreach (var line in File.ReadLines("/proc/meminfo"))
            {
                var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length < 2)
                {
                    continue;
                }

                if (fields[0] == "MemTotal:" && long.TryParse(fields[1], out var total))
                {
                    totalKb = total;
                }
                else if (fields[0] == "MemAvailable:" && long.TryParse(fields[1], out var available))
                {
                    availableKb = available;
                }

                if (totalKb > 0 && availableKb > 0)
                {
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not read /proc/meminfo: {Message}", ex.Message);
            return 0;
        }

        if (totalKb <= 0)
        {
            return 0;
        }

        var usedKb = totalKb - availableKb;
        return Math.Clamp((int)Math.Round((double)usedKb / totalKb * 100.0), 0, 100);
    }

    public string GetSystemUptime()
    {
        try
        {
            var content = File.ReadAllText("/proc/uptime");
            var firstField = content.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();

            if (double.TryParse(firstField, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds))
            {
                return UptimeFormatter.Format(TimeSpan.FromSeconds(seconds));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not read /proc/uptime: {Message}", ex.Message);
        }

        return "Unknown";
    }

    private bool TryReadCpuTimes(out ulong totalTime, out ulong idleTime)
    {
        totalTime = 0;
        idleTime = 0;

        try
        {
            using var reader = new StreamReader("/proc/stat");
            var line = reader.ReadLine();

            if (line is null || !line.StartsWith("cpu ", StringComparison.Ordinal))
            {
                return false;
            }

            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            // fields[0] is the "cpu" label; the rest are cumulative jiffies:
            // user, nice, system, idle, iowait, irq, softirq, steal, guest.
            for (var i = 1; i < fields.Length; i++)
            {
                if (!ulong.TryParse(fields[i], out var value))
                {
                    continue;
                }

                totalTime += value;

                // Index 4 is the idle column once the label is accounted for.
                if (i == 4)
                {
                    idleTime = value;
                }
            }

            return totalTime > 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not read /proc/stat: {Message}", ex.Message);
            return false;
        }
    }
}
