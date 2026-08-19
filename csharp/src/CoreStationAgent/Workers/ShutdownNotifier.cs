using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CoreStationAgent.Workers;

/// <summary>
/// Announces the agent's exit to the BMC.
///
/// Its position in the registration order matters: hosted services stop in
/// reverse order, so this one is registered before the telemetry and inbound
/// services (which therefore stop first, and stop queueing new lines) but
/// after the transport, which stays alive to carry the farewell.
/// </summary>
public sealed class ShutdownNotifier : IHostedService
{
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(5);

    private readonly SerialTransportService _transport;
    private readonly ILogger<ShutdownNotifier> _logger;

    public ShutdownNotifier(SerialTransportService transport, ILogger<ShutdownNotifier> logger)
    {
        _transport = transport;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (!_transport.IsConnected)
        {
            _logger.LogInformation("Shutting down with no serial connection; nothing to notify");
            return;
        }

        _logger.LogInformation("Notifying BMC of shutdown");
        _transport.Send("appExit, shutting down");

        await _transport.WaitForDrainAsync(DrainTimeout).ConfigureAwait(false);
    }
}
