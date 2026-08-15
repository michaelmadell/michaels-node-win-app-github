using System.Reflection;
using CoreStationAgent.Configuration;
using CoreStationAgent.Core;
using CoreStationAgent.Protocol;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreStationAgent.Workers;

/// <summary>
/// Drives everything the agent sends on its own initiative: the session
/// preamble on each new connection, the periodic heartbeat with metrics, and
/// change notifications for hostname, user and network configuration.
/// </summary>
public sealed class TelemetryService : BackgroundService
{
    private readonly SerialTransportService _transport;
    private readonly ISystemInformation _systemInformation;
    private readonly IMetricsProvider _metricsProvider;
    private readonly AgentOptions _options;
    private readonly ILogger<TelemetryService> _logger;

    // Last values sent, so only changes go on the wire.
    private string? _lastHostname;
    private string? _lastUsername;
    private string? _lastSessionState;
    private IReadOnlyList<NetworkInterfaceInfo> _lastInterfaces = Array.Empty<NetworkInterfaceInfo>();

    private int _observedConnectionGeneration;

    public TelemetryService(
        SerialTransportService transport,
        ISystemInformation systemInformation,
        IMetricsProvider metricsProvider,
        IOptions<AgentOptions> options,
        ILogger<TelemetryService> logger)
    {
        _transport = transport;
        _systemInformation = systemInformation;
        _metricsProvider = metricsProvider;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Seed the rate counters so the first heartbeat reports a real delta
        // rather than the meaningless value a single sample produces.
        _metricsProvider.UpdateCounters();

        var heartbeatInterval = TimeSpan.FromSeconds(_options.HeartbeatIntervalSeconds);
        var statePollInterval = TimeSpan.FromSeconds(_options.StatePollIntervalSeconds);

        var nextHeartbeat = DateTimeOffset.UtcNow + heartbeatInterval;
        var nextStatePoll = DateTimeOffset.UtcNow + statePollInterval;

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await SendPreambleIfReconnectedAsync(stoppingToken).ConfigureAwait(false);

                var now = DateTimeOffset.UtcNow;

                if (now >= nextHeartbeat)
                {
                    nextHeartbeat = now + heartbeatInterval;
                    await SendHeartbeatAsync(stoppingToken).ConfigureAwait(false);
                }

                if (now >= nextStatePoll)
                {
                    nextStatePoll = now + statePollInterval;
                    SendStateChanges();
                }

                await Task.Delay(TimeSpan.FromMilliseconds(200), stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    /// <summary>
    /// Re-sends the full preamble whenever the transport establishes a new
    /// connection, since a BMC that just came up has no prior state.
    /// </summary>
    private Task SendPreambleIfReconnectedAsync(CancellationToken cancellationToken)
    {
        var generation = _transport.ConnectionGeneration;

        if (generation == _observedConnectionGeneration || !_transport.IsConnected)
        {
            return Task.CompletedTask;
        }

        _observedConnectionGeneration = generation;
        _logger.LogInformation("Serial session {Generation} established, sending preamble", generation);

        _transport.Send("appVersion", GetAgentVersion());
        _transport.Send("winVersion", _systemInformation.GetOsVersion());
        _transport.Send("osBuild", _systemInformation.GetOsBuild());

        // Force a full re-send of state on the fresh connection.
        _lastHostname = null;
        _lastUsername = null;
        _lastSessionState = null;
        _lastInterfaces = Array.Empty<NetworkInterfaceInfo>();

        SendStateChanges();

        return Task.CompletedTask;
    }

    private async Task SendHeartbeatAsync(CancellationToken cancellationToken)
    {
        if (_options.EnableMetrics)
        {
            try
            {
                var metrics = await _metricsProvider.CollectAllAsync(cancellationToken).ConfigureAwait(false);
                SendMetrics(metrics);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // A failed collection must not stop the heartbeat itself; the
                // BMC treats missing heartbeats as a dead host.
                _logger.LogError(ex, "Metrics collection failed");
            }
        }

        _transport.Send("HB");
    }

    private void SendMetrics(SystemMetrics metrics)
    {
        var performance = metrics.Performance;

        _transport.Send("cpuUsage", $"{performance.CpuUsagePercent}%");
        _transport.Send("ramUsage", $"{performance.RamUsagePercent}%");
        _transport.Send("freeDisk", $"{performance.FreeDiskSpaceGb}GB");
        _transport.Send("wuState", metrics.Updates.State);
        _transport.Send("diskQueue", performance.DiskQueueLength.ToString("F2"));
        _transport.Send("netRetrans", $"{performance.NetworkRetransRate:F2}/s");
        _transport.Send("uptime", performance.Uptime);
        _transport.Send("gpuInfo", metrics.Gpu.DriverInfo);
        _transport.Send("gpuUsage", $"{metrics.Gpu.UsagePercent:F0}%");
        _transport.Send("highRamProcs", metrics.Processes.HighRamProcesses);

        _logger.LogInformation(
            "Metrics: CPU={Cpu}%, RAM={Ram}%, Disk={Disk}GB, Update={Update}, DiskQ={DiskQueue:F2}, " +
            "NetRetrans={NetRetrans:F2}/s, Uptime={Uptime}, GPU={GpuUsage:F0}% ({GpuInfo})",
            performance.CpuUsagePercent, performance.RamUsagePercent, performance.FreeDiskSpaceGb,
            metrics.Updates.State, performance.DiskQueueLength, performance.NetworkRetransRate,
            performance.Uptime, metrics.Gpu.UsagePercent, metrics.Gpu.DriverInfo);

        // Re-baseline the rate counters for the next interval.
        _metricsProvider.UpdateCounters();
    }

    private void SendStateChanges()
    {
        var sessionState = _systemInformation.GetCurrentSessionState();
        if (sessionState != _lastSessionState)
        {
            _lastSessionState = sessionState;
            _transport.Send("sessionState", sessionState);
        }

        var hostname = _systemInformation.GetHostname();
        if (hostname != _lastHostname)
        {
            _lastHostname = hostname;
            _transport.Send("hostname", hostname);
            _logger.LogInformation("Hostname is now {Hostname}", hostname);
        }

        var username = _systemInformation.GetLoggedInUser();
        if (username != _lastUsername)
        {
            _lastUsername = username;
            _transport.Send("username", username);
            _logger.LogInformation("Logged-in user is now {Username}", username);
        }

        var interfaces = _systemInformation.GetNetworkInterfaces();
        if (!interfaces.SequenceEqual(_lastInterfaces))
        {
            _lastInterfaces = interfaces;
            _logger.LogInformation("Network configuration changed, sending {Count} interfaces", interfaces.Count);

            foreach (var adapter in interfaces)
            {
                _transport.Send(adapter.ToSerialPayload());
            }
        }
    }

    internal static string GetAgentVersion()
    {
        var assembly = Assembly.GetExecutingAssembly();

        // InformationalVersion carries the full product version, including any
        // suffix such as "_rc1"; it falls back to the assembly version.
        var informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

        if (!string.IsNullOrWhiteSpace(informational))
        {
            // Strip the source-control metadata the SDK appends.
            var separator = informational.IndexOf('+');
            return separator > 0 ? informational[..separator] : informational;
        }

        return assembly.GetName().Version?.ToString() ?? "0.0.0.0";
    }
}
