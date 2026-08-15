using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace CoreStationAgent.Platform.Common;

/// <summary>Reads the CPU model string used to identify the board generation.</summary>
public interface ICpuModelReader
{
    string GetCpuModel();
}

public sealed class CpuModelReader : ICpuModelReader
{
    private readonly ILogger<CpuModelReader> _logger;
    private string? _cached;

    public CpuModelReader(ILogger<CpuModelReader> logger) => _logger = logger;

    public string GetCpuModel() => _cached ??= ReadCpuModel();

    private string ReadCpuModel()
    {
        try
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? ReadFromRegistry()
                : ReadFromProcCpuInfo();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not determine CPU model: {Message}", ex.Message);
            return string.Empty;
        }
    }

    private static string ReadFromProcCpuInfo()
    {
        const string path = "/proc/cpuinfo";
        if (!File.Exists(path))
        {
            return string.Empty;
        }

        foreach (var line in File.ReadLines(path))
        {
            if (!line.StartsWith("model name", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var separator = line.IndexOf(':');
            if (separator >= 0)
            {
                return line[(separator + 1)..].Trim();
            }
        }

        return string.Empty;
    }

    private string ReadFromRegistry()
    {
        if (!OperatingSystem.IsWindows())
        {
            return string.Empty;
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            return key?.GetValue("ProcessorNameString") as string ?? string.Empty;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not read CPU model from registry: {Message}", ex.Message);
            return string.Empty;
        }
    }
}
