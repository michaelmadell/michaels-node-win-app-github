namespace CoreStationAgent.Core;

/// <summary>
/// Host facts that change rarely and are polled for changes, plus the cheap
/// CPU/RAM/uptime trio that must work even when metrics collection is disabled
/// (the C2A "status" command depends on it).
/// </summary>
public interface ISystemInformation
{
    string GetHostname();

    /// <summary>Console user, or "none" when nobody is signed in.</summary>
    string GetLoggedInUser();

    string GetOsVersion();

    string GetOsBuild();

    /// <summary>
    /// Numeric session state matching the WTS_* constants the BMC expects.
    /// See <see cref="SessionState"/>.
    /// </summary>
    string GetCurrentSessionState();

    /// <summary>
    /// Adapters to report. Implementations filter to the chassis vendor OUIs
    /// so unrelated virtual adapters never reach the BMC.
    /// </summary>
    IReadOnlyList<NetworkInterfaceInfo> GetNetworkInterfaces();

    /// <summary>
    /// CPU busy percentage since the previous call. The first call has no
    /// baseline to compare against and returns 0.
    /// </summary>
    int GetCpuUsagePercent();

    int GetRamUsagePercent();

    string GetSystemUptime();
}
