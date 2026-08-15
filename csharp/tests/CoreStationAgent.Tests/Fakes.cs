using System.Collections.Concurrent;
using CoreStationAgent.Core;
using CoreStationAgent.Protocol;

namespace CoreStationAgent.Tests;

/// <summary>Captures everything the agent would have put on the wire.</summary>
public sealed class FakeBmcChannel : IBmcChannel
{
    private readonly ConcurrentQueue<string> _lines = new();

    public IReadOnlyList<string> Lines => _lines.ToArray();

    public void Send(string line) => _lines.Enqueue(line);

    public bool Contains(string line) => _lines.Contains(line);

    /// <summary>Waits for a line to appear, for assertions on scheduled work.</summary>
    public async Task<bool> WaitForAsync(string line, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;

        while (DateTimeOffset.UtcNow < deadline)
        {
            if (Contains(line))
            {
                return true;
            }

            await Task.Delay(10);
        }

        return false;
    }
}

public sealed class FakeSystemInformation : ISystemInformation
{
    public string Hostname { get; set; } = "TEST-NODE";
    public string Username { get; set; } = "testuser";
    public string OsVersion { get; set; } = "10.0.26100";
    public string OsBuild { get; set; } = "Build 26100";
    public string SessionStateValue { get; set; } = SessionState.Logon;
    public int CpuUsage { get; set; } = 12;
    public int RamUsage { get; set; } = 34;
    public string Uptime { get; set; } = "2d 04h 13m 09s";
    public IReadOnlyList<NetworkInterfaceInfo> Interfaces { get; set; } = Array.Empty<NetworkInterfaceInfo>();

    public string GetHostname() => Hostname;

    public string GetLoggedInUser() => Username;

    public string GetOsVersion() => OsVersion;

    public string GetOsBuild() => OsBuild;

    public string GetCurrentSessionState() => SessionStateValue;

    public IReadOnlyList<NetworkInterfaceInfo> GetNetworkInterfaces() => Interfaces;

    public int GetCpuUsagePercent() => CpuUsage;

    public int GetRamUsagePercent() => RamUsage;

    public string GetSystemUptime() => Uptime;
}

public sealed class FakePowerActions : IPowerActions
{
    private readonly ConcurrentQueue<string> _invocations = new();

    public IReadOnlyList<string> Invocations => _invocations.ToArray();

    public Task ShutdownAsync(string reason, CancellationToken cancellationToken)
    {
        _invocations.Enqueue($"shutdown:{reason}");
        return Task.CompletedTask;
    }

    public Task RestartAsync(string reason, CancellationToken cancellationToken)
    {
        _invocations.Enqueue($"restart:{reason}");
        return Task.CompletedTask;
    }

    public Task LockActiveSessionAsync(CancellationToken cancellationToken)
    {
        _invocations.Enqueue("lock");
        return Task.CompletedTask;
    }

    public Task LogoffActiveSessionAsync(CancellationToken cancellationToken)
    {
        _invocations.Enqueue("logoff");
        return Task.CompletedTask;
    }

    public Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken)
    {
        _invocations.Enqueue($"message:{title}:{message}");
        return Task.CompletedTask;
    }

    public bool Invoked(string invocation) => _invocations.Contains(invocation);

    public async Task<bool> WaitForAsync(string invocation, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;

        while (DateTimeOffset.UtcNow < deadline)
        {
            if (Invoked(invocation))
            {
                return true;
            }

            await Task.Delay(10);
        }

        return false;
    }
}

/// <summary>In-memory serial link, so transport behaviour is testable.</summary>
public sealed class FakeSerialLink : CoreStationAgent.Serial.ISerialLink
{
    private readonly object _gate = new();
    private readonly List<string> _written = [];
    private string _pendingRead = string.Empty;

    public bool IsOpen { get; private set; }

    public string PortName { get; private set; } = string.Empty;

    public bool OpenSucceeds { get; set; } = true;

    public int OpenCount { get; private set; }

    public IReadOnlyList<string> Written
    {
        get
        {
            lock (_gate)
            {
                return _written.ToArray();
            }
        }
    }

    public bool Open(string portName, int baudRate)
    {
        lock (_gate)
        {
            PortName = portName;
            OpenCount++;
            IsOpen = OpenSucceeds;
            return OpenSucceeds;
        }
    }

    public void Close()
    {
        lock (_gate)
        {
            IsOpen = false;
        }
    }

    public bool Write(string data)
    {
        lock (_gate)
        {
            if (!IsOpen)
            {
                return false;
            }

            _written.Add(data);
            return true;
        }
    }

    public string Read()
    {
        lock (_gate)
        {
            var pending = _pendingRead;
            _pendingRead = string.Empty;
            return pending;
        }
    }

    /// <summary>Queues bytes for the transport to read on its next pass.</summary>
    public void EnqueueIncoming(string data)
    {
        lock (_gate)
        {
            _pendingRead += data;
        }
    }

    public void Dispose() => Close();
}
