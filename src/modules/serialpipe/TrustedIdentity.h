#pragma once

// Shared trust anchor for the authenticated serial IPC bridge (both the
// Windows/Authenticode and Linux/detached-CMS verification paths compare
// against these same Subject fields -- see
// specs/001-secure-serial-ipc/research.md Decision 1).
//
// *** DEV/TEST CERTIFICATE -- MUST BE REPLACED BEFORE THIS FEATURE SHIPS ***
// These currently match a locally-generated, throwaway dev CA + code-signing
// cert (see .devcerts/, gitignored -- regenerate anytime with a plain
// `openssl req` self-signed CA + leaf, there is nothing precious about it)
// used only to compile and exercise this feature end-to-end without access
// to the company's real EV certificate. They MUST be replaced with values
// extracted from the actual, currently-active EV code-signing certificate
// (the same one build-production.bat/sign.bat use via smctl) before this
// reaches a release build, e.g.:
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
    // build. Currently a dev/test cert (see comment above), not the real
    // company identity -- a build using these values will accept only
    // clients signed by the throwaway dev CA in .devcerts/, nothing else.
    static constexpr const char* CommonName = "CoreStation Dev Code Signing (NOT FOR PRODUCTION)";
    static constexpr const char* Organization = "Amulet Hotkey Ltd (DEV TEST ONLY)";
    static constexpr const char* OrganizationalUnit = "CoreStation Dev Signing";
};

}  // namespace IpcAuth
