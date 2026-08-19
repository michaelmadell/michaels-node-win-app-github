#pragma once

// Shared trust anchor for the authenticated serial IPC bridge (both the
// Windows/Authenticode and Linux/detached-CMS verification paths compare
// against these same Subject fields -- see
// specs/001-secure-serial-ipc/research.md Decision 1).
//
// *** PLACEHOLDER VALUES -- MUST BE REPLACED BEFORE THIS FEATURE SHIPS ***
// These MUST be extracted from the company's actual, currently-active EV
// code-signing certificate (the same one build-production.bat/sign.bat
// already use via smctl), e.g.:
//   PowerShell:  (Get-AuthenticodeSignature .\CoreStationHXAgent.exe).SignerCertificate |
//                  Select-Object Subject
//   or:          signtool verify /v CoreStationHXAgent.exe
// Matching is done on these stable Subject fields, not the certificate's
// thumbprint/serial number, so a routine EV certificate renewal does not
// require touching this file (spec.md FR-004).

#include <string>

namespace IpcAuth {

struct TrustedSigningIdentity {
    // TODO(spec 001-secure-serial-ipc T001): replace with the real values
    // from the live EV certificate before this feature reaches a release
    // build. Left obviously-wrong on purpose -- these placeholders can
    // never accidentally match a real signer, so the bridge fails closed
    // (rejects everyone) until someone fills this in, rather than silently
    // trusting nothing-in-particular.
    static constexpr const char* CommonName = "REPLACE_ME_COMMON_NAME";
    static constexpr const char* Organization = "REPLACE_ME_ORGANIZATION";
    static constexpr const char* OrganizationalUnit = "REPLACE_ME_ORG_UNIT";
};

}  // namespace IpcAuth
