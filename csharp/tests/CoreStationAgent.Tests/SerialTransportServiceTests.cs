using CoreStationAgent.Configuration;
using CoreStationAgent.Platform.Common;
using CoreStationAgent.Protocol;
using CoreStationAgent.Serial;
using CoreStationAgent.Workers;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace CoreStationAgent.Tests;

public class SerialTransportServiceTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private sealed class FixedCpuModelReader : ICpuModelReader
    {
        private readonly string _model;

        public FixedCpuModelReader(string model) => _model = model;

        public string GetCpuModel() => _model;
    }

    private static (SerialTransportService Transport, FakeSerialLink Link) CreateTransport(
        AgentOptions? options = null,
        string cpuModel = "Intel(R) Xeon(R) W-2295")
    {
        options ??= new AgentOptions
        {
            PortName = "/dev/null-test",
            SendPacingMilliseconds = 0,
            ReconnectDelayMilliseconds = 100,
        };

        var link = new FakeSerialLink();

        var resolver = new SerialPortResolver(
            Options.Create(options),
            new FixedCpuModelReader(cpuModel),
            NullLogger<SerialPortResolver>.Instance);

        var transport = new SerialTransportService(
            link,
            resolver,
            Options.Create(options),
            NullLogger<SerialTransportService>.Instance);

        return (transport, link);
    }

    [Fact]
    public async Task QueuedLines_AreWrittenWithCrLfFraming()
    {
        var (transport, link) = CreateTransport();

        await transport.StartAsync(CancellationToken.None);
        try
        {
            transport.Send("appVersion", "1.2.3.4");
            transport.Send("HB");

            await WaitUntilAsync(() => link.Written.Count >= 2);

            Assert.Equal(["appVersion, 1.2.3.4\r\n", "HB\r\n"], link.Written);
        }
        finally
        {
            await transport.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task IncomingBytes_AreSurfacedAsLines()
    {
        var (transport, link) = CreateTransport();

        await transport.StartAsync(CancellationToken.None);
        try
        {
            link.EnqueueIncoming("c2a, ping\r\nc2a, status\r\n");

            var first = await ReadLineAsync(transport);
            var second = await ReadLineAsync(transport);

            Assert.Equal("c2a, ping", first);
            Assert.Equal("c2a, status", second);
        }
        finally
        {
            await transport.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task BlankLines_AreNotSent()
    {
        var (transport, link) = CreateTransport();

        await transport.StartAsync(CancellationToken.None);
        try
        {
            transport.Send("   ");
            transport.Send(string.Empty);
            transport.Send("real");

            await WaitUntilAsync(() => link.Written.Count >= 1);
            await Task.Delay(100);

            Assert.Equal(["real\r\n"], link.Written);
        }
        finally
        {
            await transport.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task ConnectionGeneration_IncrementsOnEachOpen()
    {
        var (transport, link) = CreateTransport();

        await transport.StartAsync(CancellationToken.None);
        try
        {
            await WaitUntilAsync(() => transport.ConnectionGeneration == 1);
            Assert.True(transport.IsConnected);

            // Simulate the far end dropping: the loop should reopen the port
            // and report a new generation so the preamble is re-sent.
            link.Close();

            await WaitUntilAsync(() => transport.ConnectionGeneration == 2);
            Assert.True(transport.IsConnected);
        }
        finally
        {
            await transport.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task PortThatNeverOpens_DoesNotFaultTheService()
    {
        var (transport, link) = CreateTransport();
        link.OpenSucceeds = false;

        await transport.StartAsync(CancellationToken.None);
        try
        {
            transport.Send("HB");

            await WaitUntilAsync(() => link.OpenCount >= 2);

            Assert.False(transport.IsConnected);
            Assert.Empty(link.Written);
        }
        finally
        {
            await transport.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task ResolverPicksTheHx2000Port_ForAnHx2000Cpu()
    {
        var options = new AgentOptions
        {
            PortName = null,
            SendPacingMilliseconds = 0,
            Hx2000PortLinux = "/dev/ttyS2",
            Hx3000PortLinux = "/dev/ttyS0",
        };

        var (transport, link) = CreateTransport(options, cpuModel: "Intel(R) Core(TM) Ultra 7 165H");

        await transport.StartAsync(CancellationToken.None);
        try
        {
            await WaitUntilAsync(() => link.OpenCount >= 1);

            var expected = OperatingSystem.IsWindows() ? "COM3" : "/dev/ttyS2";
            Assert.Equal(expected, link.PortName);
        }
        finally
        {
            await transport.StopAsync(CancellationToken.None);
        }
    }

    private static async Task<string> ReadLineAsync(SerialTransportService transport)
    {
        using var cts = new CancellationTokenSource(Timeout);
        return await transport.InboundLines.ReadAsync(cts.Token);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTimeOffset.UtcNow + Timeout;

        while (DateTimeOffset.UtcNow < deadline)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(10);
        }

        Assert.Fail("Condition was not met within the timeout.");
    }
}
