using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace CoreStationAgent.Platform.Windows;

/// <summary>
/// Authenticode verification (WinVerifyTrust) and named-pipe client identity
/// P/Invokes for the authenticated serial IPC bridge
/// (see Ipc/WindowsSerialBridgeListener.cs, specs/001-secure-serial-ipc).
///
/// Kept in a separate file from <see cref="NativeMethods"/> because
/// WinVerifyTrust's WINTRUST_DATA parameter is a non-blittable struct
/// (embeds an LPCWSTR field), which needs the classic marshaler
/// (<c>[DllImport]</c>) rather than the source-generated
/// <c>[LibraryImport]</c> style used elsewhere in this project -- forcing
/// LibraryImport's blittable-struct constraints onto this particular
/// signature would mean hand-rolling the marshaling anyway, with none of
/// the safety net.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class WinTrustNativeMethods
{
    // WINTRUST_ACTION_GENERIC_VERIFY_V2, from wintrust.h -- constant well
    // known/stable across Windows versions.
    internal static readonly Guid ActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    internal const uint WtdUiNone = 2;
    internal const uint WtdRevokeNone = 0;
    internal const uint WtdChoiceFile = 1;
    internal const uint WtdStateActionVerify = 1;
    internal const uint WtdStateActionClose = 2;
    internal const uint WtdSaferFlag = 0x100;

    internal const int ErrorSuccess = 0;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WintrustFileInfo
    {
        public uint CbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string PszFilePath;
        public IntPtr HFile;
        public IntPtr PgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WintrustData
    {
        public uint CbStruct;
        public IntPtr PPolicyCallbackData;
        public IntPtr PSipClientData;
        public uint DwUiChoice;
        public uint FdwRevocationChecks;
        public uint DwUnionChoice;
        public IntPtr PFile; // union: only WTD_CHOICE_FILE is used here
        public uint DwStateAction;
        public IntPtr HWvtStateData;
        public IntPtr PwszUrlReference;
        public uint DwProvFlags;
        public uint DwUiContext;
        public IntPtr PSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WintrustData pWVTData);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetNamedPipeClientProcessId(
        Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint clientProcessId);
}
