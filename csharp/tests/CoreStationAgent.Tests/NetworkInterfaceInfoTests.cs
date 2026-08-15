using System.Net.NetworkInformation;
using CoreStationAgent.Core;
using CoreStationAgent.Platform.Common;
using Xunit;

namespace CoreStationAgent.Tests;

public class NetworkInterfaceInfoTests
{
    [Fact]
    public void SerialPayload_MatchesTheFieldOrderTheBmcParses()
    {
        var adapter = new NetworkInterfaceInfo
        {
            Name = "Ethernet 2",
            MacAddress = "00:17:FD:60:02:E1",
            LinkStatus = "up",
            Ipv4 = "192.168.203.82",
            Ipv6 = "fe80::98d7:656:a39:8ad3",
            Dhcp = "dhcp",
        };

        Assert.Equal(
            "network, 00:17:FD:60:02:E1, up, 192.168.203.82, fe80::98d7:656:a39:8ad3, dhcp, Ethernet 2",
            adapter.ToSerialPayload());
    }

    [Fact]
    public void Defaults_ReportNoneRatherThanEmptyFields()
    {
        var adapter = new NetworkInterfaceInfo { Name = "Ethernet" };

        Assert.Equal("network, none, down, none, none, static, Ethernet", adapter.ToSerialPayload());
    }

    [Fact]
    public void ValueEquality_DrivesChangeDetection()
    {
        var first = new NetworkInterfaceInfo { Name = "eth0", Ipv4 = "10.0.0.1" };
        var same = new NetworkInterfaceInfo { Name = "eth0", Ipv4 = "10.0.0.1" };
        var different = new NetworkInterfaceInfo { Name = "eth0", Ipv4 = "10.0.0.2" };

        // The telemetry loop only re-sends when this comparison changes.
        Assert.Equal(first, same);
        Assert.NotEqual(first, different);
    }

    [Fact]
    public void MacFormatting_IsUpperCaseColonSeparated()
    {
        var address = PhysicalAddress.Parse("0017FD6002E1");

        Assert.Equal("00:17:FD:60:02:E1", NetworkInterfaceReader.FormatMacAddress(address));
    }

    [Fact]
    public void MacFormatting_OfAnAdapterWithoutHardwareAddress_IsNone()
    {
        Assert.Equal("none", NetworkInterfaceReader.FormatMacAddress(PhysicalAddress.None));
    }
}
