using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using CoreStationAgent.Platform.Windows;
using CoreStationAgent.Serial;
using Microsoft.Extensions.Logging;

namespace CoreStationAgent.Ipc;

/// <summary>
/// Windows named-pipe implementation of <see cref="ISerialBridgeListener"/>
/// -- the C# counterpart of the C++ agent's SerialBridgePipe. Same pipe
/// name, so a client application doesn't need to know or care which agent
/// implementation is running on a given node
/// (specs/001-secure-serial-ipc/contracts/serial-bridge-ipc.md).
///
/// Authentication verifies the connecting process's executable carries a
/// valid Authenticode signature whose signer Subject matches
/// <see cref="TrustedSigningIdentity"/> -- never the OS user/privilege
/// level the caller is running as (spec.md FR-001..FR-005).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsSerialBridgeListener : ISerialBridgeListener
{
    private const string PipeName = "corestation_serial_bridge";

    private readonly ILogger<WindowsSerialBridgeListener> _logger;

    public WindowsSerialBridgeListener(ILogger<WindowsSerialBridgeListener> logger)
    {
        _logger = logger;
    }

    public async Task RunAsync(Action<string> onAuthenticatedLine, CancellationToken cancellationToken)
    {
        if (ClientAuthenticator.DevAuthDisabled)
        {
            _logger.LogWarning(
                "DEV MODE: IPC authentication disabled (IPC_AUTH_DEV_DISABLE) -- " +
                "this build MUST NOT be used in production");
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            using var pipe = CreatePipe();

            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException ex)
            {
                _logger.LogWarning(ex, "Serial bridge pipe connect failed, retrying");
                continue;
            }

            await HandleConnectionAsync(pipe, onAuthenticatedLine, cancellationToken).ConfigureAwait(false);
        }
    }

    private static NamedPipeServerStream CreatePipe()
    {
        // Defense-in-depth only (spec.md FR-010) -- restricts the OS-level
        // ability to even attempt a connection to Administrators, same
        // intent as the C++ agent's D:(A;;GA;;;BA) SDDL. The signature
        // check in HandleConnectionAsync is the actual control.
        var security = new PipeSecurity();
        security.SetAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            PipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            security);
    }

    private async Task HandleConnectionAsync(
        NamedPipeServerStream pipe, Action<string> onAuthenticatedLine, CancellationToken cancellationToken)
    {
        var identity = ResolveClientIdentity(pipe, _logger);

        if (!ClientAuthenticator.IsAuthenticated(identity))
        {
            _logger.LogWarning(
                "Rejected unauthenticated IPC bridge connection (CN='{Cn}', O='{O}', OU='{Ou}', signatureValid={Valid})",
                identity.CommonName, identity.Organization, identity.OrganizationalUnit, identity.SignatureValid);
            return;
        }

        // Authenticated: forward every complete line, as-is, until the
        // client disconnects. No re-authentication per message. The line
        // terminator applied when this is actually sent to the BMC is the
        // transport's own (SerialTransportService.WriteLine), not added
        // here -- see research.md Decision 5.
        var framer = new LineFramer();
        var buffer = new byte[4096];
        try
        {
            while (true)
            {
                int bytesRead = await pipe.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) break;

                string chunk = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                foreach (var line in framer.Append(chunk))
                {
                    onAuthenticatedLine(line);
                }
            }
        }
        catch (IOException)
        {
            // Client disconnected abruptly -- a normal termination path for
            // this kind of fire-and-forget bridge, not an error worth logging.
        }
        catch (OperationCanceledException)
        {
            // Shutdown.
        }
    }

    private static ConnectingClientIdentity ResolveClientIdentity(
        NamedPipeServerStream pipe, ILogger logger)
    {
        try
        {
            if (!WinTrustNativeMethods.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint pid))
            {
                logger.LogWarning(
                    "GetNamedPipeClientProcessId failed, error={Error}", Marshal.GetLastWin32Error());
                return new ConnectingClientIdentity(false, "", "", "");
            }

            string? imagePath;
            try
            {
                using var process = Process.GetProcessById(unchecked((int)pid));
                imagePath = process.MainModule?.FileName;
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException
                                            or System.ComponentModel.Win32Exception)
            {
                logger.LogWarning(ex, "Could not resolve image path for pid={Pid}", pid);
                return new ConnectingClientIdentity(false, "", "", "");
            }

            if (string.IsNullOrEmpty(imagePath) || !VerifyAuthenticode(imagePath))
            {
                return new ConnectingClientIdentity(false, "", "", "");
            }

            var (cn, o, ou) = ExtractSubjectFields(imagePath);
            return new ConnectingClientIdentity(true, cn, o, ou);
        }
        catch (Exception ex)
        {
            // Fail closed on anything unexpected -- never treat an
            // unresolvable identity as a wildcard match.
            logger.LogWarning(ex, "Unexpected error resolving IPC client identity");
            return new ConnectingClientIdentity(false, "", "", "");
        }
    }

    private static bool VerifyAuthenticode(string filePath)
    {
        var fileInfo = new WinTrustNativeMethods.WintrustFileInfo
        {
            CbStruct = (uint)Marshal.SizeOf<WinTrustNativeMethods.WintrustFileInfo>(),
            PszFilePath = filePath,
            HFile = IntPtr.Zero,
            PgKnownSubject = IntPtr.Zero,
        };

        IntPtr fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustNativeMethods.WintrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var trustData = new WinTrustNativeMethods.WintrustData
            {
                CbStruct = (uint)Marshal.SizeOf<WinTrustNativeMethods.WintrustData>(),
                DwUiChoice = WinTrustNativeMethods.WtdUiNone,
                FdwRevocationChecks = WinTrustNativeMethods.WtdRevokeNone,
                DwUnionChoice = WinTrustNativeMethods.WtdChoiceFile,
                PFile = fileInfoPtr,
                DwStateAction = WinTrustNativeMethods.WtdStateActionVerify,
                DwProvFlags = WinTrustNativeMethods.WtdSaferFlag,
            };

            var guid = WinTrustNativeMethods.ActionGenericVerifyV2;
            int result = WinTrustNativeMethods.WinVerifyTrust(IntPtr.Zero, ref guid, ref trustData);

            // Always release the WinVerifyTrust state, regardless of outcome.
            trustData.DwStateAction = WinTrustNativeMethods.WtdStateActionClose;
            WinTrustNativeMethods.WinVerifyTrust(IntPtr.Zero, ref guid, ref trustData);

            return result == WinTrustNativeMethods.ErrorSuccess;
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    private static (string cn, string o, string ou) ExtractSubjectFields(string filePath)
    {
        using var baseCert = X509Certificate.CreateFromSignedFile(filePath);
        using var cert = new X509Certificate2(baseCert);

        string cn = "", o = "", ou = "";
        foreach (var rdn in cert.SubjectName.EnumerateRelativeDistinguishedNames())
        {
            var value = rdn.GetSingleElementValue() ?? "";
            switch (rdn.GetSingleElementType().Value)
            {
                case "2.5.4.3": cn = value; break;   // commonName
                case "2.5.4.10": o = value; break;   // organizationName
                case "2.5.4.11": ou = value; break;  // organizationalUnitName
            }
        }

        return (cn, o, ou);
    }
}
