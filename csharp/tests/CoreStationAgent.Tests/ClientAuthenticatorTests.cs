using CoreStationAgent.Ipc;
using Xunit;

namespace CoreStationAgent.Tests;

// Deliberately does not exercise real WinVerifyTrust / SignedCms / a real
// signed file -- see specs/001-secure-serial-ipc/tasks.md T024. The
// IPC_AUTH_DEV_DISABLE short-circuit is a compile-time constant
// (ClientAuthenticator.DevAuthDisabled), so a single test run only ever
// exercises the configuration it was built with (Debug vs Release) -- these
// tests target SubjectMatchesTrustedIdentity directly, which is unaffected
// by that flag, rather than IsAuthenticated's dev-mode branch.
public class ClientAuthenticatorTests
{
    private static readonly ConnectingClientIdentity TrustedMatch = new(
        SignatureValid: true,
        CommonName: TrustedSigningIdentity.CommonName,
        Organization: TrustedSigningIdentity.Organization,
        OrganizationalUnit: TrustedSigningIdentity.OrganizationalUnit);

    [Fact]
    public void ExactMatch_IsAuthenticated()
    {
        Assert.True(ClientAuthenticator.SubjectMatchesTrustedIdentity(TrustedMatch));
    }

    [Fact]
    public void WrongCommonName_IsRejected()
    {
        var identity = TrustedMatch with { CommonName = "Some Other Company" };
        Assert.False(ClientAuthenticator.SubjectMatchesTrustedIdentity(identity));
    }

    [Fact]
    public void WrongOrganization_IsRejected()
    {
        var identity = TrustedMatch with { Organization = "Some Other Org" };
        Assert.False(ClientAuthenticator.SubjectMatchesTrustedIdentity(identity));
    }

    [Fact]
    public void WrongOrganizationalUnit_IsRejected()
    {
        var identity = TrustedMatch with { OrganizationalUnit = "Some Other OU" };
        Assert.False(ClientAuthenticator.SubjectMatchesTrustedIdentity(identity));
    }

    [Fact]
    public void EmptyFields_AreRejected()
    {
        var identity = new ConnectingClientIdentity(true, "", "", "");
        Assert.False(ClientAuthenticator.SubjectMatchesTrustedIdentity(identity));
    }

    [Fact]
    public void IsAuthenticated_RequiresSignatureValid_UnlessDevAuthDisabled()
    {
        // IsAuthenticated (unlike the pure SubjectMatchesTrustedIdentity
        // helper) also checks SignatureValid -- except when compiled with
        // IPC_AUTH_DEV_DISABLE, which short-circuits everything to true.
        // ClientAuthenticator.DevAuthDisabled reflects whichever
        // configuration *this test run* was actually built with (it flows
        // from CoreStationAgent.csproj's Debug-only DefineConstants via the
        // project reference), so assert against it rather than a fixed
        // expectation -- a hardcoded "must be false" would fail under a
        // Debug test run for a reason that has nothing to do with a real bug.
        var identity = TrustedMatch with { SignatureValid = false };

        Assert.Equal(ClientAuthenticator.DevAuthDisabled, ClientAuthenticator.IsAuthenticated(identity));
    }
}
