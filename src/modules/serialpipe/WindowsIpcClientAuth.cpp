#ifdef _WIN32
#include "WindowsIpcClientAuth.h"
#include "TrustedIdentity.h"

#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>

#include <atomic>
#include <vector>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32")

namespace IpcAuth {

namespace {

// Resolves the full image path of the process on the other end of an
// already-connected pipe handle. Returns an empty string on any failure --
// callers must treat that as "not authenticated", not as a wildcard.
std::wstring ResolveClientImagePath(HANDLE hPipe, const std::string& logPrefix,
                                     const std::function<void(const std::string&)>& logFn) {
    DWORD clientPid = 0;
    if (!GetNamedPipeClientProcessId(hPipe, &clientPid)) {
        logFn(logPrefix + "GetNamedPipeClientProcessId failed, error=" + std::to_string(GetLastError()));
        return L"";
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, clientPid);
    if (!hProcess) {
        logFn(logPrefix + "OpenProcess(pid=" + std::to_string(clientPid) +
              ") failed, error=" + std::to_string(GetLastError()));
        return L"";
    }

    wchar_t pathBuf[MAX_PATH] = {0};
    DWORD pathLen = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(hProcess, 0, pathBuf, &pathLen);
    CloseHandle(hProcess);

    if (!ok) {
        logFn(logPrefix + "QueryFullProcessImageNameW(pid=" + std::to_string(clientPid) +
              ") failed, error=" + std::to_string(GetLastError()));
        return L"";
    }

    return std::wstring(pathBuf, pathLen);
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
bool VerifyAuthenticodeSignerMatches(const std::wstring& imagePath,
                                      const std::string& logPrefix,
                                      const std::function<void(const std::string&)>& logFn) {
    if (imagePath.empty()) return false;

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

    bool matched = false;

    if (verifyResult == ERROR_SUCCESS) {
        CRYPT_PROVIDER_DATA const* provData = WTHelperProvDataFromStateData(trustData.hWVTStateData);
        CRYPT_PROVIDER_SGNR* signer = provData ? WTHelperGetProvSignerFromChain(
            const_cast<CRYPT_PROVIDER_DATA*>(provData), 0, FALSE, 0) : nullptr;

        if (signer && signer->csCertChain > 0 && signer->pasCertChain) {
            PCCERT_CONTEXT signerCert = signer->pasCertChain[0].pCert;
            std::string cn = GetCertNameField(signerCert, const_cast<LPSTR>(szOID_COMMON_NAME));
            std::string o = GetCertNameField(signerCert, const_cast<LPSTR>(szOID_ORGANIZATION_NAME));
            std::string ou = GetCertNameField(signerCert, const_cast<LPSTR>(szOID_ORGANIZATIONAL_UNIT_NAME));

            matched = SubjectMatchesTrustedIdentity(cn, o, ou);

            if (!matched) {
                logFn(logPrefix + "signature valid but signer identity does not match "
                      "(CN='" + cn + "', O='" + o + "', OU='" + ou + "')");
            }
        } else {
            logFn(logPrefix + "signature verified but no signer certificate could be extracted");
        }
    } else {
        logFn(logPrefix + "WinVerifyTrust failed, code=" + std::to_string(verifyResult));
    }

    // Always release the WinVerifyTrust state, regardless of outcome above.
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &trustData);

    return matched;
}

}  // namespace

bool SubjectMatchesTrustedIdentity(const std::string& cn, const std::string& o,
                                    const std::string& ou) {
    return (cn == TrustedSigningIdentity::CommonName) &&
           (o == TrustedSigningIdentity::Organization) &&
           (ou == TrustedSigningIdentity::OrganizationalUnit);
}

bool WindowsIsAuthenticated(HANDLE hPipe, const std::string& logPrefix,
                             const std::function<void(const std::string&)>& logFn) {
#ifdef IPC_AUTH_DEV_DISABLE
    static std::atomic<bool> warned{false};
    if (!warned.exchange(true)) {
        logFn(logPrefix + "DEV MODE: IPC authentication disabled (IPC_AUTH_DEV_DISABLE) -- "
              "this build MUST NOT be used in production");
    }
    (void)hPipe;
    return true;
#else
    std::wstring imagePath = ResolveClientImagePath(hPipe, logPrefix, logFn);
    return VerifyAuthenticodeSignerMatches(imagePath, logPrefix, logFn);
#endif
}

}  // namespace IpcAuth

#endif  // _WIN32
