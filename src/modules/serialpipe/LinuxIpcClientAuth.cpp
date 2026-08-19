#if defined(__linux__)
#include "LinuxIpcClientAuth.h"
#include "TrustedIdentity.h"

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <mutex>

namespace IpcAuth {

namespace {

// Trust anchor path is relative to the installed agent's certs/ directory
// alongside the binary -- see certs/README.md for provisioning.
constexpr const char* kCaChainPath = "certs/digicert_ca_chain.pem";

std::once_flag g_trustAnchorInit;
X509_STORE* g_trustAnchor = nullptr;  // owned for process lifetime once loaded

// Loads certs/digicert_ca_chain.pem into an X509_STORE, once. Leaves
// g_trustAnchor null on any failure (missing file, empty file, no valid
// certs parsed) -- callers must treat null as "cannot authenticate anyone".
void LoadTrustAnchorOnce(const std::string& logPrefix, void (*logFn)(const std::string&)) {
    BIO* bio = BIO_new_file(kCaChainPath, "r");
    if (!bio) {
        logFn(logPrefix + "FATAL: cannot open trust anchor '" + kCaChainPath +
              "' -- see src/modules/serialpipe/certs/README.md. IPC bridge authentication "
              "cannot function without it.");
        return;
    }

    X509_STORE* store = X509_STORE_new();
    int loaded = 0;
    X509* cert = nullptr;
    while ((cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) != nullptr) {
        if (X509_STORE_add_cert(store, cert) == 1) {
            ++loaded;
        }
        X509_free(cert);
    }
    BIO_free(bio);

    if (loaded == 0) {
        logFn(logPrefix + "FATAL: '" + kCaChainPath + "' contained no usable certificates.");
        X509_STORE_free(store);
        return;
    }

    g_trustAnchor = store;
    logFn(logPrefix + "Loaded " + std::to_string(loaded) + " trust anchor certificate(s) from '" +
          kCaChainPath + "'");
}

std::string ResolveClientImagePath(int clientFd, const std::string& logPrefix,
                                    void (*logFn)(const std::string&)) {
    struct ucred cred {};
    socklen_t credLen = sizeof(cred);
    if (getsockopt(clientFd, SOL_SOCKET, SO_PEERCRED, &cred, &credLen) != 0) {
        logFn(logPrefix + "getsockopt(SO_PEERCRED) failed: " + std::strerror(errno));
        return "";
    }

    char linkPath[64];
    std::snprintf(linkPath, sizeof(linkPath), "/proc/%d/exe", cred.pid);

    char imagePath[4096] = {0};
    ssize_t len = readlink(linkPath, imagePath, sizeof(imagePath) - 1);
    if (len <= 0) {
        logFn(logPrefix + "readlink(" + linkPath + ") failed: " + std::strerror(errno));
        return "";
    }
    imagePath[len] = '\0';
    return std::string(imagePath);
}

std::string ReadWholeFile(const std::string& path, bool& ok) {
    ok = false;
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return "";
    std::string contents;
    char buf[8192];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
        contents.append(buf, n);
    }
    ok = !std::ferror(f);
    std::fclose(f);
    return contents;
}

std::string GetX509NameField(X509_NAME* name, int nid) {
    if (!name) return "";
    char buf[256] = {0};
    int len = X509_NAME_get_text_by_NID(name, nid, buf, sizeof(buf));
    if (len <= 0) return "";
    return std::string(buf, static_cast<size_t>(len));
}

// Verifies imagePath's accompanying "<imagePath>.sig" (detached CMS, DER)
// against the process-wide trust anchor, then compares the signer's
// Subject to TrustedSigningIdentity. False on any failure.
bool VerifyDetachedSignatureMatches(const std::string& imagePath, const std::string& logPrefix,
                                     void (*logFn)(const std::string&)) {
    if (imagePath.empty() || !g_trustAnchor) return false;

    bool contentOk = false;
    std::string content = ReadWholeFile(imagePath, contentOk);
    if (!contentOk) {
        logFn(logPrefix + "could not read client image '" + imagePath + "'");
        return false;
    }

    std::string sigPath = imagePath + ".sig";
    bool sigOk = false;
    std::string sigBytes = ReadWholeFile(sigPath, sigOk);
    if (!sigOk || sigBytes.empty()) {
        logFn(logPrefix + "no usable detached signature at '" + sigPath + "'");
        return false;
    }

    BIO* sigBio = BIO_new_mem_buf(sigBytes.data(), static_cast<int>(sigBytes.size()));
    CMS_ContentInfo* cms = d2i_CMS_bio(sigBio, nullptr);
    BIO_free(sigBio);
    if (!cms) {
        logFn(logPrefix + "'" + sigPath + "' is not a valid DER CMS signature");
        return false;
    }

    BIO* contentBio = BIO_new_mem_buf(content.data(), static_cast<int>(content.size()));

    // Detached, binary content; full chain verification against our trust
    // anchor (not CMS_NO_SIGNER_CERT_VERIFY -- we want the chain checked).
    int verifyResult = CMS_verify(cms, nullptr, g_trustAnchor, contentBio, nullptr,
                                   CMS_DETACHED | CMS_BINARY);

    bool matched = false;
    if (verifyResult == 1) {
        STACK_OF(X509)* signers = CMS_get0_signers(cms);
        if (signers && sk_X509_num(signers) > 0) {
            X509* signerCert = sk_X509_value(signers, 0);
            X509_NAME* subject = X509_get_subject_name(signerCert);

            std::string cn = GetX509NameField(subject, NID_commonName);
            std::string o = GetX509NameField(subject, NID_organizationName);
            std::string ou = GetX509NameField(subject, NID_organizationalUnitName);

            matched = SubjectMatchesTrustedIdentity(cn, o, ou);

            if (!matched) {
                logFn(logPrefix + "signature valid but signer identity does not match "
                      "(CN='" + cn + "', O='" + o + "', OU='" + ou + "')");
            }
        } else {
            logFn(logPrefix + "signature verified but no signer certificate could be extracted");
        }
        sk_X509_free(signers);
    } else {
        logFn(logPrefix + "CMS_verify failed for '" + sigPath + "'");
    }

    BIO_free(contentBio);
    CMS_ContentInfo_free(cms);
    return matched;
}

}  // namespace

bool SubjectMatchesTrustedIdentity(const std::string& cn, const std::string& o,
                                    const std::string& ou) {
    return (cn == TrustedSigningIdentity::CommonName) &&
           (o == TrustedSigningIdentity::Organization) &&
           (ou == TrustedSigningIdentity::OrganizationalUnit);
}

bool LinuxTrustAnchorIsUsable(const std::string& logPrefix, void (*logFn)(const std::string&)) {
    std::call_once(g_trustAnchorInit, LoadTrustAnchorOnce, logPrefix, logFn);
    return g_trustAnchor != nullptr;
}

bool LinuxIsAuthenticated(int clientFd, const std::string& logPrefix,
                           void (*logFn)(const std::string&)) {
#ifdef IPC_AUTH_DEV_DISABLE
    static std::atomic<bool> warned{false};
    if (!warned.exchange(true)) {
        logFn(logPrefix + "DEV MODE: IPC authentication disabled (IPC_AUTH_DEV_DISABLE) -- "
              "this build MUST NOT be used in production");
    }
    (void)clientFd;
    return true;
#else
    if (!LinuxTrustAnchorIsUsable(logPrefix, logFn)) {
        return false;
    }
    std::string imagePath = ResolveClientImagePath(clientFd, logPrefix, logFn);
    return VerifyDetachedSignatureMatches(imagePath, logPrefix, logFn);
#endif
}

}  // namespace IpcAuth

#endif  // __linux__
