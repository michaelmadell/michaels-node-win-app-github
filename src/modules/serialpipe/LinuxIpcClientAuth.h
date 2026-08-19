#pragma once

#if defined(__linux__)
#include <string>

// Linux counterpart to WindowsIpcClientAuth.h -- see
// specs/001-secure-serial-ipc/data-model.md (ConnectingClientIdentity) and
// research.md Decision 1/3.
//
// A client is authenticated only if:
//   1. Its process image can be resolved from the connected socket's peer
//      credentials (SO_PEERCRED -- kernel-supplied, not spoofable by the
//      client).
//   2. A detached CMS/PKCS#7 signature file ("<image>.sig", produced by
//      tools/sign-linux-release.sh) exists alongside that image and
//      verifies against the embedded trust anchor
//      (certs/digicert_ca_chain.pem).
//   3. The signer certificate's Subject (CN/O/OU) matches
//      IpcAuth::TrustedSigningIdentity (TrustedIdentity.h) exactly.
//
// Any failure at any step -- including a missing/unloadable trust anchor --
// is treated as "not authenticated". When compiled with
// IPC_AUTH_DEV_DISABLE defined, IsAuthenticated() always returns true (see
// spec.md FR-006/FR-007) and logs a one-time dev-mode notice.
namespace IpcAuth {

// Returns true only if the process on the other end of clientFd is running
// an executable with a valid, trusted detached signature. clientFd must be
// an already-accept()-ed connection.
bool LinuxIsAuthenticated(int clientFd, const std::string& logPrefix,
                           void (*logFn)(const std::string&));

// Attempts to load the trust anchor (certs/digicert_ca_chain.pem) once,
// logging the outcome. Returns false if the trust anchor is missing or
// unparseable -- callers (SerialBridgeSocket::Start) MUST treat that as a
// fatal startup condition and refuse to start the bridge rather than run
// with authentication silently broken.
bool LinuxTrustAnchorIsUsable(const std::string& logPrefix, void (*logFn)(const std::string&));

// Pure comparison logic, factored out so it's unit-testable without a real
// signed file or a live OpenSSL CMS_verify call (see
// tests/test_linux_ipc_client_auth.cpp). Returns true iff all three fields
// exactly match TrustedSigningIdentity.
bool SubjectMatchesTrustedIdentity(const std::string& cn, const std::string& o,
                                    const std::string& ou);

}  // namespace IpcAuth

#endif  // __linux__
