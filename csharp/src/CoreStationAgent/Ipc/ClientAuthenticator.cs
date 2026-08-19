namespace CoreStationAgent.Ipc;

/// <summary>
/// The company's trusted code-signing identity, asserted by an
/// <see cref="ConnectingClientIdentity"/>. Matched on the certificate's
/// Subject (CN/O/OU), not its thumbprint, so a routine EV certificate
/// renewal never requires touching this file -- see
/// specs/001-secure-serial-ipc/research.md Decision 1.
///
/// *** DEV/TEST CERTIFICATE -- MUST BE REPLACED BEFORE THIS FEATURE SHIPS ***
/// Same values as (and MUST stay in sync with) src/modules/serialpipe/TrustedIdentity.h.
/// Currently match a locally-generated, throwaway dev CA + code-signing cert
/// (see .devcerts/, gitignored) used only to compile and exercise this
/// feature end-to-end without the company's real EV certificate. MUST be
/// replaced with the real EV certificate's Subject before release -- a
/// build using these values accepts only clients signed by the throwaway
/// dev CA, nothing else.
/// </summary>
public static class TrustedSigningIdentity
{
    public const string CommonName = "CoreStation Dev Code Signing (NOT FOR PRODUCTION)";
    public const string Organization = "Amulet Hotkey Ltd (DEV TEST ONLY)";
    public const string OrganizationalUnit = "CoreStation Dev Signing";
}

/// <summary>
/// The identity resolved for one connecting IPC client, before any of its
/// data is forwarded. See specs/001-secure-serial-ipc/data-model.md
/// (ConnectingClientIdentity).
/// </summary>
/// <param name="SignatureValid">
/// True only if the platform-specific signature check (Authenticode on
/// Windows, detached CMS on Linux) succeeded. If false, the Subject fields
/// are meaningless and MUST NOT be treated as a match by coincidence.
/// </param>
public sealed record ConnectingClientIdentity(
    bool SignatureValid,
    string CommonName,
    string Organization,
    string OrganizationalUnit);

/// <summary>
/// Platform-agnostic half of client authentication: given a resolved
/// identity, decides authenticated/not. The platform-specific halves
/// (Ipc/WindowsSerialBridgeListener.cs, Ipc/LinuxSerialBridgeListener.cs) do
/// the actual signature verification and hand the result here.
/// </summary>
public static class ClientAuthenticator
{
    /// <summary>
    /// True iff IPC_AUTH_DEV_DISABLE was defined at compile time -- see
    /// CoreStationAgent.csproj (Debug-configuration-only) and
    /// specs/001-secure-serial-ipc/research.md Decision 6. Exposed so
    /// callers can log the one-time dev-mode notice (spec.md FR-007)
    /// without duplicating the #if.
    /// </summary>
    public static bool DevAuthDisabled =>
#if IPC_AUTH_DEV_DISABLE
        true;
#else
        false;
#endif

    /// <summary>
    /// Returns true only if <paramref name="identity"/> represents a
    /// verified signature whose Subject exactly matches
    /// <see cref="TrustedSigningIdentity"/> -- or unconditionally true when
    /// compiled with IPC_AUTH_DEV_DISABLE (spec.md FR-006).
    /// </summary>
    public static bool IsAuthenticated(ConnectingClientIdentity identity)
    {
        if (DevAuthDisabled)
        {
            return true;
        }

        return identity.SignatureValid && SubjectMatchesTrustedIdentity(identity);
    }

    /// <summary>
    /// Pure Subject comparison, factored out for unit testing without a
    /// real signed file or a live platform verification call -- see
    /// csharp/tests/CoreStationAgent.Tests/ClientAuthenticatorTests.cs.
    /// Deliberately ignores <see cref="ConnectingClientIdentity.SignatureValid"/>
    /// so it can be tested independently of that flag; production callers
    /// MUST go through <see cref="IsAuthenticated"/>, which checks both.
    /// </summary>
    public static bool SubjectMatchesTrustedIdentity(ConnectingClientIdentity identity) =>
        identity.CommonName == TrustedSigningIdentity.CommonName &&
        identity.Organization == TrustedSigningIdentity.Organization &&
        identity.OrganizationalUnit == TrustedSigningIdentity.OrganizationalUnit;
}
