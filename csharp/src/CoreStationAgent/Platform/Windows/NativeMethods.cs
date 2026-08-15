using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace CoreStationAgent.Platform.Windows;

/// <summary>
/// The handful of Win32 entry points with no managed equivalent. Using these
/// directly avoids taking a WMI dependency for facts the kernel answers
/// immediately.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class NativeMethods
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct FileTime
    {
        public uint DwLowDateTime;
        public uint DwHighDateTime;

        public readonly ulong ToUInt64() => ((ulong)DwHighDateTime << 32) | DwLowDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MemoryStatusEx
    {
        public uint DwLength;
        public uint DwMemoryLoad;
        public ulong UllTotalPhys;
        public ulong UllAvailPhys;
        public ulong UllTotalPageFile;
        public ulong UllAvailPageFile;
        public ulong UllTotalVirtual;
        public ulong UllAvailVirtual;
        public ulong UllAvailExtendedVirtual;
    }

    internal enum WtsInfoClass
    {
        UserName = 5,
        DomainName = 7,
        ConnectState = 8,
    }

    internal enum WtsConnectState
    {
        Active = 0,
        Connected = 1,
        ConnectQuery = 2,
        Shadow = 3,
        Disconnected = 4,
        Idle = 5,
        Listen = 6,
        Reset = 7,
        Down = 8,
        Init = 9,
    }

    internal const int WtsCurrentServerHandle = 0;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetSystemTimes(
        out FileTime lpIdleTime,
        out FileTime lpKernelTime,
        out FileTime lpUserTime);

    [LibraryImport("kernel32.dll", EntryPoint = "GlobalMemoryStatusEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GlobalMemoryStatusEx(ref MemoryStatusEx lpBuffer);

    [LibraryImport("kernel32.dll")]
    internal static partial ulong GetTickCount64();

    [LibraryImport("kernel32.dll")]
    internal static partial uint WTSGetActiveConsoleSessionId();

    [LibraryImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool WTSQuerySessionInformation(
        IntPtr hServer,
        uint sessionId,
        WtsInfoClass wtsInfoClass,
        out IntPtr ppBuffer,
        out uint pBytesReturned);

    [LibraryImport("wtsapi32.dll")]
    internal static partial void WTSFreeMemory(IntPtr pMemory);

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool WTSLogoffSession(IntPtr hServer, uint sessionId, [MarshalAs(UnmanagedType.Bool)] bool bWait);
}
