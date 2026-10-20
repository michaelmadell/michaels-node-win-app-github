#ifdef _WIN32
#include "WindowsIpcClientAuth.h"
#include "TrustedIdentity.h"

#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>

#include <format>
#include <utility>
#include <vector>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32")

namespace IpcAuth {

namespace {

core::AuthError ClientUnresolved(std::string message, DWORD err) {
    return core::AuthError{
        .code = core::CoreError::Code::Internal,
        .sub_code = core::AuthError::SubCode::ClientUnresolved,
        .message = std::move(message),
        .platform_error = err,
    };
}

core::AuthError Rejected(core::AuthError::SubCode subCode, std::string message, std::uint32_t err = 0) {
    return core::AuthError{
        .code = core::CoreError::Code::PermissionDenied,
        .sub_code = subCode,
        .message = std::move(message),
        .platform_error = err,
    };
}

// Resolves the pid and full image path of the process on the other end of an
// already-connected pipe handle. Any failure is an error -- never a wildcard.
std::expected<AuthenticatedClient, core::AuthError> ResolveClient(HANDLE hPipe) {
    DWORD clientPid = 0;
    if (!GetNamedPipeClientProcessId(hPipe, &clientPid)) {
        DWORD err = GetLastError();
        return std::unexpected(ClientUnresolved("GetNamedPipeClientProcessId failed", err));
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, clientPid);
    if (!hProcess) {
        DWORD err = GetLastError();
        return std::unexpected(ClientUnresolved(std::format("OpenProcess(pid={}) failed", clientPid), err));
    }

    wchar_t pathBuf[MAX_PATH] = {0};
    DWORD pathLen = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(hProcess, 0, pathBuf, &pathLen);
    DWORD err = GetLastError();
    CloseHandle(hProcess);

    if (!ok) {
        return std::unexpected(ClientUnresolved(
            std::format("QueryFullProcessImageNameW(pid={}) failed", clientPid), err));
    }

    return AuthenticatedClient{ .pid = clientPid, .imagePath = std::wstring(pathBuf, pathLen) };
}

// Narrow (UTF-8-ish, good enough for logging/comparison of cert Subject
// fields which are effectively ASCII/Latin-1 for this company's cert) copy
// of a Crypt32 name-string result.
std::string ToNarrow(const wchar_t* wide) {
    if (!wide) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string out(static_cast<size_t>(len) - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), len, nullptr, nullptr);
    return out;
}

std::string GetCertNameField(PCCERT_CONTEXT cert, LPCSTR oid) {
    DWORD len = CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0,
                                    const_cast<LPSTR>(oid), nullptr, 0);
    if (len <= 1) return "";
    std::vector<wchar_t> buf(len);
    CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, const_cast<LPSTR>(oid), buf.data(), len);
    return ToNarrow(buf.data());
}

// Runs WinVerifyTrust's generic Authenticode policy against imagePath, and
// if (and only if) it succeeds, extracts the signer certificate's Subject
// CN/O/OU and compares them against TrustedSigningIdentity. Always closes
// the WinVerifyTrust state it opens, on every return path.
std::expected<void, core::AuthError> VerifyAuthenticodeSignerMatches(const std::wstring& imagePath) {
    if (imagePath.empty()) {
        return std::unexpected(ClientUnresolved("client image path is empty", 0));
    }

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = imagePath.c_str();

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG verifyResult = WinVerifyTrust(nullptr, &policyGuid, &trustData);

    std::expected<void, core::AuthError> result;

    if (verifyResult == ERROR_SUCCESS) {
        CRYPT_PROVIDER_DATA const* provData = WTHelperProvDataFromStateData(trustData.hWVTStateData);
        CRYPT_PROVIDER_SGNR* signer = provData ? WTHelperGetProvSignerFromChain(
            const_cast<CRYPT_PROVIDER_DATA*>(provData), 0, FALSE, 0) : nullptr;

        if (signer && signer->csCertChain > 0 && signer->pasCertChain) {
            PCCERT_CONTEXT signerCert = signer->pasCertChain[0].pCert;
            std::string cn = GetCertNameField(signerCert, const_cast<LPSTR>(szOID_COMMON_NAME));
            std::string o = GetCertNameField(signerCert, const_cast<LPSTR>(szOID_ORGANIZATION_NAME));
            std::string ou = GetCertNameField(signerCert, const_cast<LPSTR>(szOID_ORGANIZATIONAL_UNIT_NAME));

            if (!SubjectMatchesTrustedIdentity(cn, o, ou)) {
                result = std::unexpected(Rejected(
                    core::AuthError::SubCode::TrustedIdentityMismatch,
                    std::format("signature valid but signer identity does not match (CN='{}', O='{}', OU='{}')",
                                cn, o, ou)));
            }
        } else {
            result = std::unexpected(Rejected(
                core::AuthError::SubCode::SignatureVerificationFailed,
                "signature verified but no signer certificate could be extracted"));
        }
    } else {
        // verifyResult is an HRESULT (TRUST_E_NOSIGNATURE, CERT_E_EXPIRED, ...);
        // core::describe() renders its text via FormatMessage.
        result = std::unexpected(Rejected(
            verifyResult == CERT_E_EXPIRED ? core::AuthError::SubCode::CertificateExpired
                                           : core::AuthError::SubCode::SignatureVerificationFailed,
            "WinVerifyTrust failed",
            static_cast<std::uint32_t>(verifyResult)));
    }

    // Always release the WinVerifyTrust state, regardless of outcome above.
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &trustData);

    return result;
}

}  // namespace

bool SubjectMatchesTrustedIdentity(const std::string& cn, const std::string& o,
                                    const std::string& ou) {
    return (cn == TrustedSigningIdentity::CommonName) &&
           (o == TrustedSigningIdentity::Organization) &&
           (ou == TrustedSigningIdentity::OrganizationalUnit);
}

std::expected<AuthenticatedClient, core::AuthError> AuthenticateClient(HANDLE hPipe) {
#ifdef IPC_AUTH_DEV_DISABLE
    (void)hPipe;
    return AuthenticatedClient{ .devBypass = true };
#else
    auto client = ResolveClient(hPipe);
    if (!client) {
        return std::unexpected(client.error());
    }
    if (auto verified = VerifyAuthenticodeSignerMatches(client->imagePath); !verified) {
        return std::unexpected(verified.error());
    }
    return client;
#endif
}

}  // namespace IpcAuth

#endif  // _WIN32
