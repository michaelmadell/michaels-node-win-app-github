using CoreStationAgent.Configuration;
using CoreStationAgent.Protocol;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreStationAgent.Workers;

/// <summary>
/// Consumes lines from the BMC and dispatches the C2A ones.
/// </summary>
public sealed class InboundCommandService : BackgroundService
{
    private readonly SerialTransportService _transport;
    private readonly C2ACommandHandler _commandHandler;
    private readonly AgentOptions _options;
    private readonly ILogger<InboundCommandService> _logger;

    public InboundCommandService(
        SerialTransportService transport,
        C2ACommandHandler commandHandler,
        IOptions<AgentOptions> options,
        ILogger<InboundCommandService> logger)
    {
        _transport = transport;
        _commandHandler = commandHandler;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var line in _transport.InboundLines.ReadAllAsync(stoppingToken).ConfigureAwait(false))
            {
                await DispatchAsync(line, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    private async Task DispatchAsync(string line, CancellationToken cancellationToken)
    {
        if (!C2ACommandHandler.TryExtractPayload(line, out var payload))
        {
            _logger.LogInformation("Received: {Line}", line);
            return;
        }

        if (!_options.EnableC2A)
        {
            _logger.LogInformation("Ignoring C2A command, dispatch is disabled: {Payload}", payload);
            return;
        }

        _logger.LogInformation("Received C2A command: {Payload}", payload);

        try
        {
            await _commandHandler.HandleAsync(payload, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // One malformed command must not take the dispatch loop down.
            _logger.LogError(ex, "Failed to handle C2A command: {Payload}", payload);
        }
    }
}
