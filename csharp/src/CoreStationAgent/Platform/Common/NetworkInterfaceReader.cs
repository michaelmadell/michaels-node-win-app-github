using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using CoreStationAgent.Configuration;
using CoreStationAgent.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreStationAgent.Platform.Common;

/// <summary>
/// Whether an adapter's address was assigned by DHCP. The managed API answers
/// this only on Windows, so Linux needs its own lookup.
/// </summary>
public interface IDhcpStatusReader
{
    string GetDhcpStatus(NetworkInterface adapter);
}

/// <summary>
/// Enumerates adapters via the cross-platform managed API and filters them to
/// the chassis vendor OUIs the BMC cares about.
/// </summary>
public sealed class NetworkInterfaceReader
{
    private readonly IDhcpStatusReader _dhcpStatusReader;
    private readonly AgentOptions _options;
    private readonly ILogger<NetworkInterfaceReader> _logger;

    public NetworkInterfaceReader(
        IDhcpStatusReader dhcpStatusReader,
        IOptions<AgentOptions> options,
        ILogger<NetworkInterfaceReader> logger)
    {
        _dhcpStatusReader = dhcpStatusReader;
        _options = options.Value;
        _logger = logger;
    }

    public IReadOnlyList<NetworkInterfaceInfo> Read()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(adapter => adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(Describe)
                .Where(IsReportable)
                .OrderBy(adapter => adapter.Name, StringComparer.Ordinal)
                .ToList();
        }
        catch (NetworkInformationException ex)
        {
            _logger.LogWarning("Could not enumerate network interfaces: {Message}", ex.Message);
            return Array.Empty<NetworkInterfaceInfo>();
        }
    }

    private NetworkInterfaceInfo Describe(NetworkInterface adapter)
    {
        var ipv4 = "none";
        var ipv6 = "none";

        try
        {
            foreach (var address in adapter.GetIPProperties().UnicastAddresses)
            {
                switch (address.Address.AddressFamily)
                {
                    case AddressFamily.InterNetwork when ipv4 == "none":
                        ipv4 = address.Address.ToString();
                        break;

                    // Link-local addresses are per-link and carry no routing
                    // information the chassis can use, so they are skipped.
                    case AddressFamily.InterNetworkV6
                        when ipv6 == "none" && !address.Address.IsIPv6LinkLocal:
                        ipv6 = address.Address.ToString();
                        break;
                }
            }
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException)
        {
            _logger.LogDebug("Could not read addresses for {Adapter}: {Message}", adapter.Name, ex.Message);
        }

        return new NetworkInterfaceInfo
        {
            Name = adapter.Name,
            MacAddress = FormatMacAddress(adapter.GetPhysicalAddress()),
            LinkStatus = adapter.OperationalStatus == OperationalStatus.Up ? "up" : "down",
            Ipv4 = ipv4,
            Ipv6 = ipv6,
            Dhcp = _dhcpStatusReader.GetDhcpStatus(adapter),
        };
    }

    private bool IsReportable(NetworkInterfaceInfo adapter)
    {
        if (_options.ReportedMacPrefixes.Count == 0)
        {
            return true;
        }

        return _options.ReportedMacPrefixes.Any(
            prefix => adapter.MacAddress.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    internal static string FormatMacAddress(PhysicalAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (bytes.Length == 0)
        {
            return "none";
        }

        var builder = new StringBuilder(bytes.Length * 3);
        foreach (var value in bytes)
        {
            if (builder.Length > 0)
            {
                builder.Append(':');
            }

            builder.Append(value.ToString("X2", CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }
}
