namespace CoreStationAgent.Serial;

/// <summary>
/// The byte-level serial connection, behind an interface so the protocol and
/// worker layers can be tested without a real port.
/// </summary>
public interface ISerialLink : IDisposable
{
    bool IsOpen { get; }

    string PortName { get; }

    /// <summary>Opens the port. Returns false rather than throwing when the
    /// device is missing or busy, so callers can retry on a timer.</summary>
    bool Open(string portName, int baudRate);

    void Close();

    /// <summary>Writes raw text. Returns false and closes the port on I/O
    /// failure so the reconnect loop takes over.</summary>
    bool Write(string data);

    /// <summary>
    /// Reads whatever is buffered, returning an empty string when nothing has
    /// arrived. Never blocks for longer than the port's read timeout.
    /// </summary>
    string Read();
}
