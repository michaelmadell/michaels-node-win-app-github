using System.ComponentModel.DataAnnotations;

namespace CoreStationAgent.Configuration;

/// <summary>
/// Settings bound from the "Agent" section of appsettings.json, overridable
/// by environment variables (e.g. <c>Agent__PortName=/dev/ttyUSB0</c>).
/// </summary>
public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    /// <summary>
    /// Serial device to use. Leave empty to auto-detect from the CPU model,
    /// which is what the shipped configuration does.
    /// </summary>
    public string? PortName { get; set; }

    [Range(300, 4_000_000)]
    public int BaudRate { get; set; } = 115200;

    /// <summary>Delay between reconnect attempts once the port drops.</summary>
    [Range(100, 600_000)]
    public int ReconnectDelayMilliseconds { get; set; } = 5_000;

    /// <summary>
    /// Pause inserted before each line. The BMC's receive buffer is small and
    /// drops input when lines arrive back to back.
    /// </summary>
    [Range(0, 10_000)]
    public int SendPacingMilliseconds { get; set; } = 250;

    [Range(1, 86_400)]
    public int HeartbeatIntervalSeconds { get; set; } = 30;

    [Range(1, 86_400)]
    public int StatePollIntervalSeconds { get; set; } = 30;

    /// <summary>Collect the expensive disk/network/GPU metrics tier.</summary>
    public bool EnableMetrics { get; set; } = true;

    /// <summary>Act on inbound "c2a, ..." commands.</summary>
    public bool EnableC2A { get; set; } = true;

    /// <summary>
    /// Run the authenticated serial IPC bridge (Windows named pipe /
    /// Linux Unix domain socket) that lets other company applications
    /// forward messages to the serial port. See
    /// specs/001-secure-serial-ipc. Authentication itself cannot be
    /// disabled via this or any other runtime setting -- see
    /// Ipc/ClientAuthenticator.cs's IPC_AUTH_DEV_DISABLE compile-time flag.
    /// </summary>
    public bool EnableSerialBridge { get; set; } = true;

    /// <summary>
    /// Warning window before a shutdown/restart that arrives without an
    /// explicit "timeout" or "time" modifier.
    /// </summary>
    [Range(0, 86_400)]
    public int DefaultGracePeriodSeconds { get; set; } = 15;

    /// <summary>
    /// MAC address prefixes identifying chassis-managed adapters. Only these
    /// are reported; everything else is filtered out. Empty means report all.
    /// </summary>
    public IList<string> ReportedMacPrefixes { get; set; } = new List<string>
    {
        "00:17:FD", // Amulet Hotkey
        "00:13:95", // Congatec
        "00:07:32", // AAEON
    };

    /// <summary>
    /// CPU model substrings identifying HX2000 boards, which expose AMT SOL
    /// on a different port than HX3000 boards.
    /// </summary>
    public IList<string> Hx2000CpuModels { get; set; } = new List<string>
    {
        "Intel(R) Core(TM) Ultra 7 165H",
        "Intel(R) Core(TM) Ultra 7 165U",
        "Intel(R) Core(TM) Ultra 9 285H",
    };

    public string Hx2000PortWindows { get; set; } = "COM3";

    public string Hx3000PortWindows { get; set; } = "COM1";

    public string Hx2000PortLinux { get; set; } = "/dev/ttyS2";

    public string Hx3000PortLinux { get; set; } = "/dev/ttyS0";
}
