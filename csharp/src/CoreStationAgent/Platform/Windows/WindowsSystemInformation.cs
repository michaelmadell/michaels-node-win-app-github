using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using CoreStationAgent.Core;
using CoreStationAgent.Platform.Common;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace CoreStationAgent.Platform.Windows;

/// <summary>
/// Host facts from Win32 and the registry.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsSystemInformation : ISystemInformation
{
    private const string CurrentVersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    private readonly NetworkInterfaceReader _networkReader;
    private readonly ILogger<WindowsSystemInformation> _logger;

    // GetSystemTimes reports cumulative totals, so CPU load is a delta.
    private ulong _previousIdleTime;
    private ulong _previousTotalTime;

    public WindowsSystemInformation(
        NetworkInterfaceReader networkReader,
        ILogger<WindowsSystemInformation> logger)
    {
        _networkReader = networkReader;
        _logger = logger;
    }

    public string GetHostname() => Environment.MachineName;

    public string GetLoggedInUser()
    {
        var sessionId = NativeMethods.WTSGetActiveConsoleSessionId();

        // 0xFFFFFFFF means no session is attached to the console, which is the
        // normal state at the sign-in screen.
        if (sessionId == uint.MaxValue)
        {
            return "none";
        }

        var userName = QuerySessionString(sessionId, NativeMethods.WtsInfoClass.UserName);
        return string.IsNullOrWhiteSpace(userName) ? "none" : userName;
    }

    /// <summary>
    /// The friendly edition name, e.g. "Windows 11 Pro 24H2".
    /// </summary>
    public string GetOsVersion()
    {
        // On .NET Core and later this is backed by RtlGetVersion, so it reports
        // the true build rather than a value shimmed by the app manifest.
        var version = Environment.OSVersion.Version;
        var fallback = $"{version.Major}.{version.Minor}.{version.Build}";

        return WindowsVersionFormatter.Format(
            ReadRegistryString("ProductName"),
            ReadRegistryString("DisplayVersion"),
            version.Build,
            fallback);
    }

    /// <summary>
    /// The numeric version, e.g. "10.0.26100".
    /// </summary>
    public string GetOsBuild()
    {
        var version = Environment.OSVersion.Version;
        return $"{version.Major}.{version.Minor}.{version.Build}";
    }

    public string GetCurrentSessionState()
    {
        var sessionId = NativeMethods.WTSGetActiveConsoleSessionId();
        if (sessionId == uint.MaxValue)
        {
            return SessionState.Logoff;
        }

        if (!TryQuerySessionConnectState(sessionId, out var state))
        {
            return SessionState.AppStarting;
        }

        return state switch
        {
            NativeMethods.WtsConnectState.Active => SessionState.Logon,
            NativeMethods.WtsConnectState.Connected => SessionState.ConsoleConnect,
            NativeMethods.WtsConnectState.Disconnected => SessionState.ConsoleDisconnect,
            NativeMethods.WtsConnectState.Shadow => SessionState.RemoteControl,
            _ => SessionState.AppStarting,
        };
    }

    public IReadOnlyList<NetworkInterfaceInfo> GetNetworkInterfaces() => _networkReader.Read();

    public int GetCpuUsagePercent()
    {
        if (!NativeMethods.GetSystemTimes(out var idle, out var kernel, out var user))
        {
            _logger.LogWarning("GetSystemTimes failed with error {Error}", Marshal.GetLastWin32Error());
            return 0;
        }

        var idleTime = idle.ToUInt64();

        // Kernel time already includes idle time, so the two sum to the total.
        var totalTime = kernel.ToUInt64() + user.ToUInt64();

        var idleDelta = idleTime - _previousIdleTime;
        var totalDelta = totalTime - _previousTotalTime;

        _previousIdleTime = idleTime;
        _previousTotalTime = totalTime;

        if (totalDelta == 0)
        {
            return 0;
        }

        var usage = (int)Math.Round((1.0 - ((double)idleDelta / totalDelta)) * 100.0);
        return Math.Clamp(usage, 0, 100);
    }

    public int GetRamUsagePercent()
    {
        var status = new NativeMethods.MemoryStatusEx
        {
            DwLength = (uint)Marshal.SizeOf<NativeMethods.MemoryStatusEx>(),
        };

        if (!NativeMethods.GlobalMemoryStatusEx(ref status))
        {
            _logger.LogWarning("GlobalMemoryStatusEx failed with error {Error}", Marshal.GetLastWin32Error());
            return 0;
        }

        return Math.Clamp((int)status.DwMemoryLoad, 0, 100);
    }

    public string GetSystemUptime() =>
        UptimeFormatter.Format(TimeSpan.FromMilliseconds(NativeMethods.GetTickCount64()));

    private string ReadRegistryString(string valueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(CurrentVersionKey);
            return key?.GetValue(valueName)?.ToString() ?? string.Empty;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException
                                       or IOException)
        {
            _logger.LogWarning("Could not read registry value {ValueName}: {Message}", valueName, ex.Message);
            return string.Empty;
        }
    }

    private string QuerySessionString(uint sessionId, NativeMethods.WtsInfoClass infoClass)
    {
        var buffer = IntPtr.Zero;

        try
        {
            if (!NativeMethods.WTSQuerySessionInformation(
                    NativeMethods.WtsCurrentServerHandle, sessionId, infoClass, out buffer, out _))
            {
                _logger.LogDebug("WTSQuerySessionInformation({InfoClass}) failed with error {Error}",
                    infoClass, Marshal.GetLastWin32Error());
                return string.Empty;
            }

            return Marshal.PtrToStringUni(buffer) ?? string.Empty;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                NativeMethods.WTSFreeMemory(buffer);
            }
        }
    }

    private bool TryQuerySessionConnectState(uint sessionId, out NativeMethods.WtsConnectState state)
    {
        state = default;
        var buffer = IntPtr.Zero;

        try
        {
            if (!NativeMethods.WTSQuerySessionInformation(
                    NativeMethods.WtsCurrentServerHandle,
                    sessionId,
                    NativeMethods.WtsInfoClass.ConnectState,
                    out buffer,
                    out var returned) || returned < sizeof(int))
            {
                return false;
            }

            state = (NativeMethods.WtsConnectState)Marshal.ReadInt32(buffer);
            return true;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                NativeMethods.WTSFreeMemory(buffer);
            }
        }
    }
}
