// Unit tests for LinuxIpcClientAuth's pure comparison logic. Deliberately
// does NOT exercise CMS_verify, SO_PEERCRED, or a real trust anchor / signed
// file -- those require live OpenSSL calls against real files, which this
// test binary doesn't have. See specs/001-secure-serial-ipc/tasks.md T015.
//
// The IPC_AUTH_DEV_DISABLE short-circuit is a compile-time #ifdef, not a
// runtime branch -- see the equivalent note in test_ipc_client_auth.cpp.
#if defined(__linux__)

#include <gtest/gtest.h>
#include "../src/modules/serialpipe/LinuxIpcClientAuth.h"
#include "../src/modules/serialpipe/TrustedIdentity.h"

TEST(LinuxIpcClientAuth, ExactMatchIsAuthenticated) {
    EXPECT_TRUE(IpcAuth::SubjectMatchesTrustedIdentity(
        IpcAuth::TrustedSigningIdentity::CommonName,
        IpcAuth::TrustedSigningIdentity::Organization,
        IpcAuth::TrustedSigningIdentity::OrganizationalUnit));
}

TEST(LinuxIpcClientAuth, WrongCommonNameIsRejected) {
    EXPECT_FALSE(IpcAuth::SubjectMatchesTrustedIdentity(
        "Some Other Company",
        IpcAuth::TrustedSigningIdentity::Organization,
        IpcAuth::TrustedSigningIdentity::OrganizationalUnit));
}

TEST(LinuxIpcClientAuth, WrongOrganizationIsRejected) {
    EXPECT_FALSE(IpcAuth::SubjectMatchesTrustedIdentity(
        IpcAuth::TrustedSigningIdentity::CommonName,
        "Some Other Org",
        IpcAuth::TrustedSigningIdentity::OrganizationalUnit));
}

TEST(LinuxIpcClientAuth, WrongOrganizationalUnitIsRejected) {
    EXPECT_FALSE(IpcAuth::SubjectMatchesTrustedIdentity(
        IpcAuth::TrustedSigningIdentity::CommonName,
        IpcAuth::TrustedSigningIdentity::Organization,
        "Some Other OU"));
}

TEST(LinuxIpcClientAuth, EmptyFieldsAreRejected) {
    EXPECT_FALSE(IpcAuth::SubjectMatchesTrustedIdentity("", "", ""));
}

#endif  // __linux__
