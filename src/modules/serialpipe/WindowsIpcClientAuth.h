#pragma once

#ifdef _WIN32
#include <windows.h>
#include <expected>
#include <string>
#include "../../core/Errors.h"

// Resolves and authenticates the identity of a process connected to the
// serial bridge named pipe. See specs/001-secure-serial-ipc/data-model.md
// (ConnectingClientIdentity) and research.md Decision 1/3.
//
// A client is authenticated only if:
//   1. Its process image can be resolved from the connected pipe handle.
//   2. That image carries a currently-valid Authenticode signature
//      (WinVerifyTrust).
//   3. The signer certificate's Subject (CN/O/OU) matches
//      IpcAuth::TrustedSigningIdentity (TrustedIdentity.h) exactly.
//
// Any failure at any step is treated as "not authenticated" -- there is no
// partial-trust state. When compiled with IPC_AUTH_DEV_DISABLE defined,
// AuthenticateClient() always succeeds with devBypass set (see spec.md
// FR-006/FR-007); the caller is responsible for the dev-mode notice.
namespace IpcAuth {

// The process on the other end of the pipe, once it has passed (or, in an
// IPC_AUTH_DEV_DISABLE build, bypassed) authentication.
struct AuthenticatedClient {
    DWORD pid = 0;
    std::wstring imagePath;
    bool devBypass = false;  // true only in IPC_AUTH_DEV_DISABLE builds
};

// Succeeds only if the process on the other end of hPipe is running an
// executable signed by the trusted company identity; otherwise the AuthError
// says which step failed and why. hPipe must already be connected (i.e.
// called after ConnectNamedPipe succeeds).
std::expected<AuthenticatedClient, core::AuthError> AuthenticateClient(HANDLE hPipe);

// Pure comparison logic, factored out so it's unit-testable without a real
// signed file or a live WinVerifyTrust call (see tests/test_ipc_client_auth.cpp).
// Returns true iff all three fields exactly match TrustedSigningIdentity.
bool SubjectMatchesTrustedIdentity(const std::string& cn, const std::string& o,
                                    const std::string& ou);

}  // namespace IpcAuth

#endif  // _WIN32
