using System.Threading.Channels;
using CoreStationAgent.Configuration;
using CoreStationAgent.Protocol;
using CoreStationAgent.Serial;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreStationAgent.Workers;

/// <summary>
/// Owns the serial connection: keeps it open, paces outbound lines onto it,
/// and reassembles inbound ones.
///
/// Every write in the process funnels through this one loop, so the port is
/// only ever touched by a single thread and no interleaving of partial lines
/// is possible.
/// </summary>
public sealed class SerialTransportService : BackgroundService, IBmcChannel
{
    private const int OutboundCapacity = 256;

    private readonly ISerialLink _link;
    private readonly SerialPortResolver _portResolver;
    private readonly AgentOptions _options;
    private readonly ILogger<SerialTransportService> _logger;

    private readonly Channel<string> _outbound;
    private readonly Channel<string> _inbound;
    private readonly LineFramer _framer = new();

    private int _connectionGeneration;

    public SerialTransportService(
        ISerialLink link,
        SerialPortResolver portResolver,
        IOptions<AgentOptions> options,
        ILogger<SerialTransportService> logger)
    {
        _link = link;
        _portResolver = portResolver;
        _options = options.Value;
        _logger = logger;

        // Bounded so an outage cannot grow without limit. Dropping the oldest
        // line is the right trade here: the queue holds periodic telemetry,
        // and a fresh reading supersedes a stale one.
        _outbound = Channel.CreateBounded<string>(new BoundedChannelOptions(OutboundCapacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        });

        _inbound = Channel.CreateUnbounded<string>(new UnboundedChannelOptions
        {
            SingleWriter = true,
        });
    }

    /// <summary>Lines received from the BMC, in arrival order.</summary>
    public ChannelReader<string> InboundLines => _inbound.Reader;

    public bool IsConnected => _link.IsOpen;

    /// <summary>
    /// Increments on each successful open. Consumers compare against their own
    /// copy to notice that a fresh session began and re-send initial state.
    /// </summary>
    public int ConnectionGeneration => Volatile.Read(ref _connectionGeneration);

    public void Send(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return;
        }

        if (!_outbound.Writer.TryWrite(line))
        {
            _logger.LogWarning("Dropped outbound line, queue closed: {Line}", line);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var portName = _portResolver.Resolve();

        _logger.LogInformation("Serial transport starting on {PortName} at {BaudRate} baud",
            portName, _options.BaudRate);

        var reconnectDelay = TimeSpan.FromMilliseconds(_options.ReconnectDelayMilliseconds);
        var pacing = TimeSpan.FromMilliseconds(_options.SendPacingMilliseconds);
        var lastConnectAttempt = DateTimeOffset.MinValue;

        while (!stoppingToken.IsCancellationRequested)
        {
            if (!_link.IsOpen)
            {
                // Rate-limit reconnects so a permanently absent device does not
                // spin the loop.
                if (DateTimeOffset.UtcNow - lastConnectAttempt < reconnectDelay)
                {
                    await DelayQuietlyAsync(TimeSpan.FromMilliseconds(100), stoppingToken).ConfigureAwait(false);
                    continue;
                }

                lastConnectAttempt = DateTimeOffset.UtcNow;

                if (_link.Open(portName, _options.BaudRate))
                {
                    _framer.Reset();
                    Interlocked.Increment(ref _connectionGeneration);
                    _logger.LogInformation("Serial port {PortName} opened", portName);
                }
                else
                {
                    _logger.LogDebug("Serial port {PortName} unavailable, retrying in {Delay}",
                        portName, reconnectDelay);
                    continue;
                }
            }

            PumpInbound();

            // One line per pass keeps the pacing gap between writes and lets
            // inbound data be serviced in between.
            if (_outbound.Reader.TryRead(out var line))
            {
                WriteLine(line);
                await DelayQuietlyAsync(pacing, stoppingToken).ConfigureAwait(false);
            }
            else
            {
                await DelayQuietlyAsync(TimeSpan.FromMilliseconds(50), stoppingToken).ConfigureAwait(false);
            }
        }

        _inbound.Writer.TryComplete();
        _link.Close();
        _logger.LogInformation("Serial transport stopped");
    }

    /// <summary>
    /// Waits until the outbound queue has drained, so a line queued during
    /// shutdown reaches the BMC before the port closes. Returns early once
    /// <paramref name="timeout"/> elapses or the port drops.
    ///
    /// This only observes the queue depth — draining stays the sole
    /// responsibility of <see cref="ExecuteAsync"/>, which is the channel's
    /// single reader.
    /// </summary>
    public async Task WaitForDrainAsync(TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;

        while (DateTimeOffset.UtcNow < deadline)
        {
            if (_outbound.Reader.Count == 0 || !_link.IsOpen)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(50)).ConfigureAwait(false);
        }

        _logger.LogWarning("Timed out waiting for {Count} outbound lines to drain", _outbound.Reader.Count);
    }

    private void WriteLine(string line)
    {
        _logger.LogDebug("TX {Line}", line);

        // CRLF is the frame terminator the BMC scans for.
        if (!_link.Write(line + "\r\n"))
        {
            _logger.LogWarning("Failed to write line, port will be reopened: {Line}", line);
        }
    }

    private void PumpInbound()
    {
        var chunk = _link.Read();
        if (chunk.Length == 0)
        {
            return;
        }

        foreach (var line in _framer.Append(chunk))
        {
            _logger.LogDebug("RX {Line}", line);
            _inbound.Writer.TryWrite(line);
        }
    }

    private static async Task DelayQuietlyAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Shutdown; the enclosing loop checks the token and exits.
        }
    }
}
