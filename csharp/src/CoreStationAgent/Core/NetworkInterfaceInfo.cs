namespace CoreStationAgent.Core;

/// <summary>
/// One network adapter as reported to the BMC. Mirrors the C++ agent's
/// <c>NetworkInterface</c> struct so the wire format stays identical.
/// </summary>
public sealed record NetworkInterfaceInfo
{
    public required string Name { get; init; }

    public string Ipv4 { get; init; } = "none";

    public string Ipv6 { get; init; } = "none";

    /// <summary>"dhcp" or "static".</summary>
    public string Dhcp { get; init; } = "static";

    /// <summary>"up" or "down".</summary>
    public string LinkStatus { get; init; } = "down";

    /// <summary>Colon-separated upper-case MAC, e.g. "00:17:FD:60:02:E1".</summary>
    public string MacAddress { get; init; } = "none";

    /// <summary>
    /// Renders the "network, ..." payload in the field order the BMC parses:
    /// mac, link, ipv4, ipv6, dhcp, name.
    /// </summary>
    public string ToSerialPayload() =>
        $"network, {MacAddress}, {LinkStatus}, {Ipv4}, {Ipv6}, {Dhcp}, {Name}";
}
