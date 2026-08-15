using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using CoreStationAgent.Platform.Common;

namespace CoreStationAgent.Platform.Windows;

/// <summary>
/// On Windows the managed API answers the DHCP question directly.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsDhcpStatusReader : IDhcpStatusReader
{
    public string GetDhcpStatus(NetworkInterface adapter)
    {
        try
        {
            return adapter.GetIPProperties().GetIPv4Properties().IsDhcpEnabled ? "dhcp" : "static";
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException)
        {
            // An adapter without IPv4 bound has no IPv4 properties to read.
            return "static";
        }
    }
}
