using System.Runtime.InteropServices;
using CoreStationAgent.Configuration;
using CoreStationAgent.Core;
using CoreStationAgent.Platform.Common;
using CoreStationAgent.Platform.Linux;
using CoreStationAgent.Platform.Windows;
using CoreStationAgent.Protocol;
using CoreStationAgent.Serial;
using CoreStationAgent.Workers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

var builder = Host.CreateApplicationBuilder(args);

// Run as a native service on either platform. Both calls are no-ops when the
// process is started from a terminal, so the same binary debugs interactively.
builder.Services.AddWindowsService(options => options.ServiceName = "CoreStationAgent");
builder.Services.AddSystemd();

builder.Services
    .AddOptions<AgentOptions>()
    .Bind(builder.Configuration.GetSection(AgentOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddSingleton<IProcessRunner, ProcessRunner>();
builder.Services.AddSingleton<ICpuModelReader, CpuModelReader>();
builder.Services.AddSingleton<NetworkInterfaceReader>();
builder.Services.AddSingleton<SerialPortResolver>();
builder.Services.AddSingleton<ISerialLink, SerialPortLink>();

RegisterPlatformServices(builder.Services);

// The transport is one object playing two roles: a hosted service that owns
// the port, and the outbound channel everything else writes to.
builder.Services.AddSingleton<SerialTransportService>();
builder.Services.AddSingleton<IBmcChannel>(sp => sp.GetRequiredService<SerialTransportService>());
builder.Services.AddSingleton<C2ACommandHandler>();

// Hosted services stop in reverse registration order, and this order is what
// makes a clean goodbye possible: telemetry and inbound dispatch stop first so
// nothing new is queued, then the notifier sends "appExit" and waits for the
// queue to drain, and only then does the transport close the port.
builder.Services.AddHostedService(sp => sp.GetRequiredService<SerialTransportService>());
builder.Services.AddHostedService<ShutdownNotifier>();
builder.Services.AddHostedService<InboundCommandService>();
builder.Services.AddHostedService<TelemetryService>();
builder.Services.AddHostedService<SerialBridgeService>();

var host = builder.Build();

var startupLogger = host.Services.GetRequiredService<ILogger<Program>>();
startupLogger.LogInformation(
    "CoreStation Agent {Version} starting on {Platform}",
    TelemetryService.GetAgentVersion(),
    RuntimeInformation.OSDescription);

await host.RunAsync();

return;

static void RegisterPlatformServices(IServiceCollection services)
{
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        RegisterWindowsServices(services);
    }
    else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
    {
        services.AddSingleton<IDhcpStatusReader, LinuxDhcpStatusReader>();
        services.AddSingleton<ISystemInformation, LinuxSystemInformation>();
        services.AddSingleton<IPowerActions, LinuxPowerActions>();
        services.AddSingleton<IMetricsProvider>(CreateLinuxMetricsProvider);
    }
    else
    {
        throw new PlatformNotSupportedException(
            $"CoreStation Agent supports Windows and Linux; this host reports {RuntimeInformation.OSDescription}.");
    }
}

// Split out so the Windows-only types are never touched during JIT on Linux.
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
static void RegisterWindowsServices(IServiceCollection services)
{
    services.AddSingleton<IDhcpStatusReader, WindowsDhcpStatusReader>();
    services.AddSingleton<ISystemInformation, WindowsSystemInformation>();
    services.AddSingleton<IPowerActions, WindowsPowerActions>();
    services.AddSingleton<IMetricsProvider>(CreateWindowsMetricsProvider);
}

// The platform guard lives inside the factory rather than on the enclosing
// method: the delegate is invoked later by the container, so the analyzer
// cannot carry an attribute on the registration site across that boundary.
static IMetricsProvider CreateWindowsMetricsProvider(IServiceProvider sp)
{
    if (!OperatingSystem.IsWindows() ||
        !sp.GetRequiredService<IOptions<AgentOptions>>().Value.EnableMetrics)
    {
        return new NullMetricsProvider();
    }

    return ActivatorUtilities.CreateInstance<WindowsMetricsProvider>(sp);
}

static IMetricsProvider CreateLinuxMetricsProvider(IServiceProvider sp) =>
    sp.GetRequiredService<IOptions<AgentOptions>>().Value.EnableMetrics
        ? ActivatorUtilities.CreateInstance<LinuxMetricsProvider>(sp)
        : new NullMetricsProvider();

/// <summary>Marker type so <c>ILogger&lt;Program&gt;</c> resolves.</summary>
public partial class Program;
