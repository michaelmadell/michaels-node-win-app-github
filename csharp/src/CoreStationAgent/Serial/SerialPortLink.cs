using System.IO.Ports;
using System.Text;
using Microsoft.Extensions.Logging;

namespace CoreStationAgent.Serial;

/// <summary>
/// <see cref="ISerialLink"/> over <see cref="SerialPort"/>, which talks to
/// Win32 COM handles on Windows and termios devices on Linux.
/// </summary>
public sealed class SerialPortLink : ISerialLink
{
    private readonly ILogger<SerialPortLink> _logger;
    private readonly object _gate = new();
    private SerialPort? _port;

    public SerialPortLink(ILogger<SerialPortLink> logger) => _logger = logger;

    public bool IsOpen
    {
        get
        {
            lock (_gate)
            {
                return _port is { IsOpen: true };
            }
        }
    }

    public string PortName { get; private set; } = string.Empty;

    public bool Open(string portName, int baudRate)
    {
        lock (_gate)
        {
            CloseCore();
            PortName = portName;

            try
            {
                var port = new SerialPort(portName, baudRate, Parity.None, 8, StopBits.One)
                {
                    // Both flow-control mechanisms are disabled deliberately. The
                    // far end is a MEC chip that never asserts CTS, so leaving
                    // handshaking on makes every write block until it times out
                    // and then report a partial write.
                    Handshake = Handshake.None,

                    // Reads poll rather than block so one loop can interleave
                    // reading with reconnect checks.
                    ReadTimeout = 50,
                    WriteTimeout = 1_000,
                    Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                };

                port.Open();

                AssertModemLines(port);

                // Drop anything the previous owner of the port left buffered.
                port.DiscardInBuffer();
                port.DiscardOutBuffer();

                _port = port;
                return true;
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException
                                           or ArgumentException or InvalidOperationException)
            {
                _logger.LogWarning("Failed to open serial port {PortName}: {Message}", portName, ex.Message);
                _port = null;
                return false;
            }
        }
    }

    public void Close()
    {
        lock (_gate)
        {
            CloseCore();
        }
    }

    public bool Write(string data)
    {
        lock (_gate)
        {
            if (_port is not { IsOpen: true })
            {
                return false;
            }

            try
            {
                _port.Write(data);
                return true;
            }
            catch (Exception ex) when (ex is IOException or TimeoutException
                                           or InvalidOperationException or UnauthorizedAccessException)
            {
                _logger.LogWarning("Serial write failed on {PortName}, closing port: {Message}",
                    PortName, ex.Message);

                // Drop the handle so the reconnect loop rebuilds it; a port left
                // in a faulted state returns zero bytes forever otherwise.
                CloseCore();
                return false;
            }
        }
    }

    public string Read()
    {
        lock (_gate)
        {
            if (_port is not { IsOpen: true })
            {
                return string.Empty;
            }

            try
            {
                var available = _port.BytesToRead;
                if (available <= 0)
                {
                    return string.Empty;
                }

                var buffer = new byte[available];
                var read = _port.Read(buffer, 0, buffer.Length);
                return read <= 0 ? string.Empty : Encoding.UTF8.GetString(buffer, 0, read);
            }
            catch (TimeoutException)
            {
                return string.Empty;
            }
            catch (Exception ex) when (ex is IOException or InvalidOperationException
                                           or UnauthorizedAccessException)
            {
                _logger.LogWarning("Serial read failed on {PortName}, closing port: {Message}",
                    PortName, ex.Message);
                CloseCore();
                return string.Empty;
            }
        }
    }

    /// <summary>
    /// Raises DTR and RTS, which real hardware expects, but treats failure as
    /// non-fatal: pseudo-terminals and some USB adapters have no modem-control
    /// lines at all, and the port is perfectly usable for data without them.
    /// </summary>
    private void AssertModemLines(SerialPort port)
    {
        foreach (var (name, setter) in new (string, Action)[]
                 {
                     ("DTR", () => port.DtrEnable = true),
                     ("RTS", () => port.RtsEnable = true),
                 })
        {
            try
            {
                setter();
            }
            catch (Exception ex) when (ex is IOException or InvalidOperationException
                                           or UnauthorizedAccessException)
            {
                _logger.LogDebug("{PortName} does not support the {Line} line: {Message}",
                    port.PortName, name, ex.Message);
            }
        }
    }

    public void Dispose() => Close();

    private void CloseCore()
    {
        if (_port is null)
        {
            return;
        }

        try
        {
            if (_port.IsOpen)
            {
                _port.Close();
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException
                                       or UnauthorizedAccessException)
        {
            _logger.LogDebug("Ignoring error while closing {PortName}: {Message}", PortName, ex.Message);
        }
        finally
        {
            _port.Dispose();
            _port = null;
        }
    }
}
