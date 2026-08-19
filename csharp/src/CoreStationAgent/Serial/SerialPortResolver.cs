using System.Runtime.InteropServices;
using CoreStationAgent.Configuration;
using CoreStationAgent.Platform.Common;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CoreStationAgent.Serial;

/// <summary>
/// Picks the serial device to talk to. HX2000 boards expose AMT serial-over-LAN
/// on a different port than HX3000 boards, so the CPU model decides.
/// </summary>
public sealed class SerialPortResolver
{
    private readonly AgentOptions _options;
    private readonly ICpuModelReader _cpuModelReader;
    private readonly ILogger<SerialPortResolver> _logger;

    public SerialPortResolver(
        IOptions<AgentOptions> options,
        ICpuModelReader cpuModelReader,
        ILogger<SerialPortResolver> logger)
    {
        _options = options.Value;
        _cpuModelReader = cpuModelReader;
        _logger = logger;
    }

    public string Resolve()
    {
        if (!string.IsNullOrWhiteSpace(_options.PortName))
        {
            _logger.LogInformation("Using configured serial port {PortName}", _options.PortName);
            return _options.PortName;
        }

        var isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        var cpuModel = _cpuModelReader.GetCpuModel();
        var isHx2000 = _options.Hx2000CpuModels.Any(
            model => cpuModel.Contains(model, StringComparison.OrdinalIgnoreCase));

        var port = (isHx2000, isWindows) switch
        {
            (true, true) => _options.Hx2000PortWindows,
            (true, false) => _options.Hx2000PortLinux,
            (false, true) => _options.Hx3000PortWindows,
            (false, false) => _options.Hx3000PortLinux,
        };

        _logger.LogInformation(
            "CPU \"{CpuModel}\" detected as {Board}; using serial port {PortName}",
            cpuModel, isHx2000 ? "HX2000" : "HX3000", port);

        return port;
    }
}
