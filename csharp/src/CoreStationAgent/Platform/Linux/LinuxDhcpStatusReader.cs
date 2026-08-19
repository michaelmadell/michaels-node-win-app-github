using System.Net.NetworkInformation;
using CoreStationAgent.Platform.Common;

namespace CoreStationAgent.Platform.Linux;

/// <summary>
/// Determines DHCP vs static on Linux, where the managed
/// <c>IPv4InterfaceProperties.IsDhcpEnabled</c> property is not implemented.
/// </summary>
public sealed class LinuxDhcpStatusReader : IDhcpStatusReader
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(5);

    private readonly IProcessRunner _processRunner;

    public LinuxDhcpStatusReader(IProcessRunner processRunner) => _processRunner = processRunner;

    public string GetDhcpStatus(NetworkInterface adapter)
    {
        // A lease shows up as the "dynamic" flag on the address itself.
        var addressOutput = _processRunner.Run(
            "ip", ["-4", "-o", "addr", "show", "dev", adapter.Name], CommandTimeout);

        if (addressOutput.Contains(" dynamic ", StringComparison.Ordinal))
        {
            return "dhcp";
        }

        // Some configurations leave the flag off but still tag the route with
        // the protocol that installed it.
        var routeOutput = _processRunner.Run(
            "ip", ["-4", "-o", "route", "show", "dev", adapter.Name], CommandTimeout);

        return routeOutput.Contains("proto dhcp", StringComparison.Ordinal) ? "dhcp" : "static";
    }
}
