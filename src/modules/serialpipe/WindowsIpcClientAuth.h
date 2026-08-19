#pragma once

#ifdef _WIN32
#include <windows.h>
#include <string>

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
// IsAuthenticated() always returns true (see spec.md FR-006/FR-007) and
// logs a one-time dev-mode notice.
namespace IpcAuth {

// Returns true only if the process on the other end of hPipe is running an
// executable signed by the trusted company identity. hPipe must already be
// connected (i.e. called after ConnectNamedPipe succeeds).
bool WindowsIsAuthenticated(HANDLE hPipe, const std::string& logPrefix,
                             void (*logFn)(const std::string&));

// Pure comparison logic, factored out so it's unit-testable without a real
// signed file or a live WinVerifyTrust call (see tests/test_ipc_client_auth.cpp).
// Returns true iff all three fields exactly match TrustedSigningIdentity.
bool SubjectMatchesTrustedIdentity(const std::string& cn, const std::string& o,
                                    const std::string& ou);

}  // namespace IpcAuth

#endif  // _WIN32
