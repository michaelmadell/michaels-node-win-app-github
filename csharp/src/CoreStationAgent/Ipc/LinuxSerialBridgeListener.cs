using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CoreStationAgent.Serial;
using Microsoft.Extensions.Logging;

namespace CoreStationAgent.Ipc;

/// <summary>
/// Linux Unix-domain-socket implementation of <see cref="ISerialBridgeListener"/>
/// -- new capability, mirroring the C++ agent's SerialBridgeSocket. Same
/// socket path, so a client application doesn't need to know or care which
/// agent implementation is running on a given node
/// (specs/001-secure-serial-ipc/contracts/serial-bridge-ipc.md).
///
/// Authentication verifies a detached CMS/PKCS#7 signature file
/// ("&lt;image&gt;.sig", see tools/sign-linux-release.sh) accompanying the
/// connecting process's executable, chained to the embedded trust anchor
/// (Ipc/digicert_ca_chain.pem -- see Ipc/README.md), whose signer Subject
/// matches <see cref="TrustedSigningIdentity"/> -- never the OS user the
/// caller is running as (spec.md FR-001..FR-005, FR-011, FR-012).
/// </summary>
[SupportedOSPlatform("linux")]
public sealed partial class LinuxSerialBridgeListener : ISerialBridgeListener
{
    private const string SocketPath = "/run/corestation/serial_bridge.sock";
    private const string IpcGroupName = "corestation-ipc";

    // SOL_SOCKET / SO_PEERCRED, Linux x86_64/arm64 kernel header values.
    private const int SolSocket = 1;
    private const int SoPeerCred = 17;

    private readonly ILogger<LinuxSerialBridgeListener> _logger;
    private readonly Lazy<X509Certificate2Collection?> _trustAnchor;

    public LinuxSerialBridgeListener(ILogger<LinuxSerialBridgeListener> logger)
    {
        _logger = logger;
        _trustAnchor = new Lazy<X509Certificate2Collection?>(() => LoadTrustAnchor(_logger));
    }

    public async Task RunAsync(Action<string> onAuthenticatedLine, CancellationToken cancellationToken)
    {
        if (ClientAuthenticator.DevAuthDisabled)
        {
            _logger.LogWarning(
                "DEV MODE: IPC authentication disabled (IPC_AUTH_DEV_DISABLE) -- " +
                "this build MUST NOT be used in production");
        }
        else if (_trustAnchor.Value is null)
        {
            // Fail closed: refuse to start rather than silently reject (or,
            // if some future change introduced a bug, silently accept)
            // every connection forever with no obvious cause.
            _logger.LogCritical("Serial bridge socket will not start: trust anchor unusable");
            return;
        }

        using var listenSocket = CreateListenSocket();
        if (listenSocket is null)
        {
            return;
        }

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                Socket clientSocket;
                try
                {
                    clientSocket = await listenSocket.AcceptAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                using (clientSocket)
                {
                    await HandleConnectionAsync(clientSocket, onAuthenticatedLine, cancellationToken)
                        .ConfigureAwait(false);
                }
            }
        }
        finally
        {
            try { File.Delete(SocketPath); } catch { /* best effort cleanup */ }
        }
    }

    private Socket? CreateListenSocket()
    {
        try
        {
            Directory.CreateDirectory("/run/corestation");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not ensure /run/corestation exists");
        }

        try { File.Delete(SocketPath); } catch { /* no stale socket to remove */ }

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            socket.Bind(new UnixDomainSocketEndPoint(SocketPath));
            socket.Listen(4);
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Failed to bind/listen on '{Path}'", SocketPath);
            socket.Dispose();
            return null;
        }

        ApplySocketPermissions();
        return socket;
    }

    private void ApplySocketPermissions()
    {
        // Defense-in-depth only (spec.md FR-010) -- restricts which local
        // principals may even attempt a connection. The signature check in
        // HandleConnectionAsync is the actual control. Same group-based
        // model as the C++ agent's SerialBridgeSocket (falls back to
        // root-only if the group doesn't exist yet).
        uint? gid = LookupGroupId(IpcGroupName);

        try
        {
            File.SetUnixFileMode(SocketPath, gid.HasValue
                ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite
                : UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to set socket file permissions on '{Path}'", SocketPath);
        }

        if (gid.HasValue)
        {
            if (Chown(SocketPath, unchecked((uint)-1), gid.Value) != 0)
            {
                _logger.LogWarning(
                    "chown to group '{Group}' failed, errno={Errno} -- continuing with default group ownership",
                    IpcGroupName, Marshal.GetLastPInvokeError());
            }
        }
        else
        {
            _logger.LogWarning(
                "Group '{Group}' does not exist -- socket left root-only. Create the group to allow " +
                "non-root company applications to connect.", IpcGroupName);
        }
    }

    private static uint? LookupGroupId(string groupName)
    {
        try
        {
            foreach (var line in File.ReadLines("/etc/group"))
            {
                var parts = line.Split(':');
                if (parts.Length >= 3 && parts[0] == groupName && uint.TryParse(parts[2], out var gid))
                {
                    return gid;
                }
            }
        }
        catch
        {
            // Best effort -- treated the same as "group not found".
        }
        return null;
    }

    private async Task HandleConnectionAsync(
        Socket clientSocket, Action<string> onAuthenticatedLine, CancellationToken cancellationToken)
    {
        var identity = ResolveClientIdentity(clientSocket, _trustAnchor.Value, _logger);

        if (!ClientAuthenticator.IsAuthenticated(identity))
        {
            _logger.LogWarning(
                "Rejected unauthenticated IPC bridge connection (CN='{Cn}', O='{O}', OU='{Ou}', signatureValid={Valid})",
                identity.CommonName, identity.Organization, identity.OrganizationalUnit, identity.SignatureValid);
            return;
        }

        // Authenticated: forward every complete line, as-is, until the
        // client disconnects. No re-authentication per message.
        var framer = new LineFramer();
        var buffer = new byte[4096];
        try
        {
            while (true)
            {
                int bytesRead = await clientSocket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken)
                    .ConfigureAwait(false);
                if (bytesRead == 0) break;

                string chunk = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                foreach (var line in framer.Append(chunk))
                {
                    onAuthenticatedLine(line);
                }
            }
        }
        catch (SocketException)
        {
            // Client disconnected abruptly -- normal termination path.
        }
        catch (OperationCanceledException)
        {
            // Shutdown.
        }
    }

    private static ConnectingClientIdentity ResolveClientIdentity(
        Socket clientSocket, X509Certificate2Collection? trustAnchor, ILogger logger)
    {
        if (trustAnchor is null)
        {
            return new ConnectingClientIdentity(false, "", "", "");
        }

        try
        {
            Span<byte> credBuf = stackalloc byte[12]; // struct ucred { int pid, uid, gid; }
            clientSocket.GetRawSocketOption(SolSocket, SoPeerCred, credBuf);
            int pid = BitConverter.ToInt32(credBuf[..4]);

            string linkPath = $"/proc/{pid}/exe";
            string imagePath;
            try
            {
                var target = File.ResolveLinkTarget(linkPath, returnFinalTarget: true);
                if (target is null)
                {
                    logger.LogWarning("Could not resolve {LinkPath}", linkPath);
                    return new ConnectingClientIdentity(false, "", "", "");
                }
                imagePath = target.FullName;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Could not resolve {LinkPath}", linkPath);
                return new ConnectingClientIdentity(false, "", "", "");
            }

            string sigPath = imagePath + ".sig";
            if (!File.Exists(sigPath))
            {
                logger.LogWarning("No detached signature at '{SigPath}'", sigPath);
                return new ConnectingClientIdentity(false, "", "", "");
            }

            byte[] content;
            byte[] sig;
            try
            {
                content = File.ReadAllBytes(imagePath);
                sig = File.ReadAllBytes(sigPath);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Could not read client image or signature");
                return new ConnectingClientIdentity(false, "", "", "");
            }

            var cms = new SignedCms(new ContentInfo(content), detached: true);
            try
            {
                cms.Decode(sig);
                // Cryptographic integrity only here; chain trust is
                // verified separately below against OUR trust anchor, not
                // whatever happens to be in the OS trust store.
                cms.CheckSignature(verifySignatureOnly: true);
            }
            catch (CryptographicException ex)
            {
                logger.LogWarning(ex, "'{SigPath}' is not a valid signature for '{ImagePath}'", sigPath, imagePath);
                return new ConnectingClientIdentity(false, "", "", "");
            }

            if (cms.SignerInfos.Count == 0 || cms.SignerInfos[0].Certificate is not { } signerCert)
            {
                logger.LogWarning("Signature verified but no signer certificate could be extracted");
                return new ConnectingClientIdentity(false, "", "", "");
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(trustAnchor);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            if (!chain.Build(signerCert))
            {
                logger.LogWarning(
                    "Signer certificate for '{ImagePath}' does not chain to the trust anchor", imagePath);
                return new ConnectingClientIdentity(false, "", "", "");
            }

            string cn = "", o = "", ou = "";
            foreach (var rdn in signerCert.SubjectName.EnumerateRelativeDistinguishedNames())
            {
                var value = rdn.GetSingleElementValue() ?? "";
                switch (rdn.GetSingleElementType().Value)
                {
                    case "2.5.4.3": cn = value; break;   // commonName
                    case "2.5.4.10": o = value; break;   // organizationName
                    case "2.5.4.11": ou = value; break;  // organizationalUnitName
                }
            }

            return new ConnectingClientIdentity(true, cn, o, ou);
        }
        catch (Exception ex)
        {
            // Fail closed on anything unexpected.
            logger.LogWarning(ex, "Unexpected error resolving IPC client identity");
            return new ConnectingClientIdentity(false, "", "", "");
        }
    }

    private static X509Certificate2Collection? LoadTrustAnchor(ILogger logger)
    {
        string path = Path.Combine(AppContext.BaseDirectory, "Ipc", "digicert_ca_chain.pem");
        if (!File.Exists(path))
        {
            logger.LogCritical(
                "FATAL: trust anchor '{Path}' not found -- see Ipc/README.md. IPC bridge authentication " +
                "cannot function without it.", path);
            return null;
        }

        try
        {
            var collection = new X509Certificate2Collection();
            collection.ImportFromPemFile(path);
            if (collection.Count == 0)
            {
                logger.LogCritical("FATAL: trust anchor '{Path}' contained no certificates.", path);
                return null;
            }
            logger.LogInformation("Loaded {Count} trust anchor certificate(s) from '{Path}'", collection.Count, path);
            return collection;
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "FATAL: failed to load trust anchor '{Path}'", path);
            return null;
        }
    }

    [LibraryImport("libc", EntryPoint = "chown", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Chown(string pathname, uint owner, uint group);
}
