// Unit tests for WindowsIpcClientAuth's pure comparison logic. Deliberately
// does NOT exercise WinVerifyTrust or a real signed file -- those require a
// live Windows trust store and an actual signed binary, which this test
// binary doesn't have. See specs/001-secure-serial-ipc/tasks.md T014.
//
// The IPC_AUTH_DEV_DISABLE short-circuit is a compile-time #ifdef, not a
// runtime branch, so it can't be exercised from a single test binary --
// verifying it means building the unit_tests target twice (with and
// without -DIPC_AUTH_DEV_DISABLE=ON), which is a build-matrix concern, not
// something this file can assert on.
#ifdef _WIN32

#include <gtest/gtest.h>
#include "../src/modules/serialpipe/WindowsIpcClientAuth.h"
#include "../src/modules/serialpipe/TrustedIdentity.h"

TEST(WindowsIpcClientAuth, ExactMatchIsAuthenticated) {
    EXPECT_TRUE(IpcAuth::SubjectMatchesTrustedIdentity(
        IpcAuth::TrustedSigningIdentity::CommonName,
        IpcAuth::TrustedSigningIdentity::Organization,
        IpcAuth::TrustedSigningIdentity::OrganizationalUnit));
}

TEST(WindowsIpcClientAuth, WrongCommonNameIsRejected) {
    EXPECT_FALSE(IpcAuth::SubjectMatchesTrustedIdentity(
        "Some Other Company",
        IpcAuth::TrustedSigningIdentity::Organization,
        IpcAuth::TrustedSigningIdentity::OrganizationalUnit));
}

TEST(WindowsIpcClientAuth, WrongOrganizationIsRejected) {
    EXPECT_FALSE(IpcAuth::SubjectMatchesTrustedIdentity(
        IpcAuth::TrustedSigningIdentity::CommonName,
        "Some Other Org",
        IpcAuth::TrustedSigningIdentity::OrganizationalUnit));
}

TEST(WindowsIpcClientAuth, WrongOrganizationalUnitIsRejected) {
    EXPECT_FALSE(IpcAuth::SubjectMatchesTrustedIdentity(
        IpcAuth::TrustedSigningIdentity::CommonName,
        IpcAuth::TrustedSigningIdentity::Organization,
        "Some Other OU"));
}

TEST(WindowsIpcClientAuth, EmptyFieldsAreRejected) {
    EXPECT_FALSE(IpcAuth::SubjectMatchesTrustedIdentity("", "", ""));
}

TEST(WindowsIpcClientAuth, CaseSensitiveComparison) {
    // Subject fields are compared exactly, not case-folded -- a
    // near-miss capitalization difference must not be treated as a match.
    std::string lowered = IpcAuth::TrustedSigningIdentity::CommonName;
    for (auto& c : lowered) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    if (lowered == IpcAuth::TrustedSigningIdentity::CommonName) {
        GTEST_SKIP() << "Trusted CommonName has no letters to case-flip";
    }
    EXPECT_FALSE(IpcAuth::SubjectMatchesTrustedIdentity(
        lowered,
        IpcAuth::TrustedSigningIdentity::Organization,
        IpcAuth::TrustedSigningIdentity::OrganizationalUnit));
}

#endif  // _WIN32
