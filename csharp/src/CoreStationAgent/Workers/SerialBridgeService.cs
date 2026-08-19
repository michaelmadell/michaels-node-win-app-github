using CoreStationAgent.Configuration;
using CoreStationAgent.Ipc;
using CoreStationAgent.Protocol;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreStationAgent.Workers;

/// <summary>
/// Hosts the authenticated serial IPC bridge -- picks the Windows or Linux
/// <see cref="ISerialBridgeListener"/> at runtime (same pattern as
/// Program.cs's platform service registration) and forwards every
/// authenticated line to the BMC through the existing outbound channel.
///
/// Deliberately does NOT write to <see cref="Serial.ISerialLink"/> directly
/// -- <see cref="SerialTransportService"/> is documented as the port's sole
/// writer, and a second writer here would risk interleaved/corrupted
/// writes. Queuing through <see cref="IBmcChannel"/> means bridged messages
/// share the same single-writer guarantee as telemetry and C2A replies
/// (specs/001-secure-serial-ipc/research.md Decision 5).
/// </summary>
public sealed class SerialBridgeService : BackgroundService
{
    private readonly IBmcChannel _bmcChannel;
    private readonly AgentOptions _options;
    private readonly ILogger<SerialBridgeService> _logger;
    private readonly IServiceProvider _services;

    public SerialBridgeService(
        IBmcChannel bmcChannel,
        IOptions<AgentOptions> options,
        ILogger<SerialBridgeService> logger,
        IServiceProvider services)
    {
        _bmcChannel = bmcChannel;
        _options = options.Value;
        _logger = logger;
        _services = services;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.EnableSerialBridge)
        {
            _logger.LogInformation("Serial bridge disabled (Agent:EnableSerialBridge=false)");
            return;
        }

        ISerialBridgeListener listener;
        if (OperatingSystem.IsWindows())
        {
            listener = ActivatorUtilities.GetServiceOrCreateInstance<WindowsSerialBridgeListener>(_services);
        }
        else if (OperatingSystem.IsLinux())
        {
            listener = ActivatorUtilities.GetServiceOrCreateInstance<LinuxSerialBridgeListener>(_services);
        }
        else
        {
            _logger.LogWarning("Serial bridge not supported on this platform, skipping");
            return;
        }

        try
        {
            await listener.RunAsync(OnAuthenticatedLine, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Serial bridge listener stopped unexpectedly");
        }
    }

    private void OnAuthenticatedLine(string line)
    {
        // Forward the client's content unmodified -- no reformatting,
        // escaping, or CSV-ification. The transport applies its own
        // standard line terminator when this is actually written, same as
        // every other outbound line (spec.md FR-009; research.md Decision 5).
        _bmcChannel.Send(line);
    }
}
