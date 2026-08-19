namespace CoreStationAgent.Protocol;

/// <summary>
/// The outbound half of the BMC link. Callers queue logical lines; the
/// transport adds framing and paces them onto the wire.
/// </summary>
public interface IBmcChannel
{
    /// <summary>
    /// Queues one line. Returns immediately — delivery happens on the
    /// transport's writer loop, so a stalled port never blocks a caller.
    /// </summary>
    void Send(string line);
}

public static class BmcChannelExtensions
{
    /// <summary>Queues "key, value", the shape every message in this protocol takes.</summary>
    public static void Send(this IBmcChannel channel, string key, string value) =>
        channel.Send($"{key}, {value}");
}
