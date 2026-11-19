// Portable HTTPS client for paste.rs, built on mbedTLS's own net/ssl/x509
// modules (already statically linked into quark_core -- see
// cpp/common/CMakeLists.txt's `mbedtls` link) rather than a platform-specific
// HTTP stack (Windows' old implementation used WinHTTP) or a subprocess
// dependency on a system `curl` binary. One implementation, used identically
// by DRM_Wrapper (customer runtime), Dev_Keygen, and Paste_Test on every OS.
//
// Certificate pinning, not a CA bundle: Quark only ever talks to one fixed
// host (paste.rs), so bundling/maintaining a portable Mozilla root store is
// unnecessary complexity. Instead, this pins paste.rs's issuing CA
// certificate as the ONLY trusted root -- more restrictive (and therefore
// more secure for this one connection) than trusting arbitrary CAs, and it
// survives paste.rs's routine ~90-day LEAF certificate renewals because we
// pin the much-longer-lived issuing intermediate, not the leaf.
//
// This constant is crypto-load-bearing (CLAUDE.md rule 2's hardcoding
// exception): a config file would just move the attack surface (an attacker
// who can rewrite config can already MITM the connection) without adding
// real value. Captured via:
//   openssl s_client -connect paste.rs:443 -servername paste.rs -showcerts
// then taking the SECOND certificate in the chain (the issuing intermediate,
// not the leaf -- `subject=C=US, O=Let's Encrypt, CN=YR2` at capture time).
// Valid 2025-09-03 through 2028-09-02. If paste.rs's operator changes CA
// (or this expires), re-run the command above and replace the PEM below with
// whatever intermediate is now serving paste.rs's leaf certificate.

#include "quark/online.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <cstdlib>
#include <cstring>
#include <sstream>

namespace quark::online {

namespace {

constexpr const char* kHost = "paste.rs";
constexpr const char* kPort = "443";

constexpr char kPastersCaPem[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIE2jCCAsKgAwIBAgIQTr0klH4k05SALYSlL9WzGTANBgkqhkiG9w0BAQsFADAu\n"
"MQswCQYDVQQGEwJVUzENMAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZUjAe\n"
"Fw0yNTA5MDMwMDAwMDBaFw0yODA5MDIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYw\n"
"FAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQDEwNZUjIwggEiMA0GCSqGSIb3\n"
"DQEBAQUAA4IBDwAwggEKAoIBAQDZ0LxwBppqh84luqMerV/eeL/fXQ7mLQQv1Lnp\n"
"WKZbyvGpx6wh6AfnslAnF6ewTkcHA+gSOoBvm3Dfm06AuGiF+KRut4fAcowqnAQQ\n"
"CW98+QPP/eOv/wug7Iyk4NkOxf2I6g2f55T6nJoOTLFcukeRq80JGQEYan+dPFr9\n"
"OGUgQK2hGKgNkW87pappsOAuUJcroYhRt5uUis4qaZireiseu32gzDJNBAiKtsvd\n"
"6HX4v25bpkRNcS/B/Gtc9kVbUpD+2PLPxdei3Tim55k4tfAEXwD2qyiPTxrTNq6l\n"
"N+AMr5g2c1dNqkOTwjxeV6L5lpP1rGiYvLnRaPlOqyZRPW+5AgMBAAGjge4wgesw\n"
"DgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBIGA1UdEwEB/wQI\n"
"MAYBAf8CAQAwHQYDVR0OBBYEFEAVLSZ57TIgnt+ach3WMh+BDIEMMB8GA1UdIwQY\n"
"MBaAFN7nW2DQIm1AKH0/DQH+pLVStFGUMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEF\n"
"BQcwAoYWaHR0cDovL3lyLmkubGVuY3Iub3JnLzATBgNVHSAEDDAKMAgGBmeBDAEC\n"
"ATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veXIuYy5sZW5jci5vcmcvMA0GCSqG\n"
"SIb3DQEBCwUAA4ICAQB0ZUQWZ9/Yn9COEpo+JfecMnB0h0vwDm/M66IqXqw3LoaL\n"
"mx9lZvRTeDIS67PUeI3yCA2W6PKRD0/FE/G57lOmS+Xy5AaaL00ICGOqjNcCaMWW\n"
"8o8nevHOd4i4lqgtznE/28QwlcdJyF8yBiWHpnyjhEpmNWJURgOCOg2xpwRMBCsj\n"
"MScqYPtOhBeuYQvSwAEeTML2Ukh6uGuX4E14q65Ja8cdjF5bAldnP1eE4FBaAwsZ\n"
"G2fOqqrKV03Y85Nw2btedP1AtliQuJZs/Jo/gXxXdc7LrH3McgnpnbTiAncX7yES\n"
"hP6kzQejllqMCIt52HOjxDGWafS7Xw+DKwqmH+Eqy8dcbOuag/1AYlQoKNVK3F5q\n"
"Hh6tEDiMqQcLIibGKteE6iHo4A/bIScbzrhXUYuism42ZYzmc48FMVIH3qy4L84E\n"
"TdAH2gtxw0PAhvRVXp8HP7wfngpzsN/8xOTpeRSbM4+Qbc56G6+Bifmv6sk1ieQb\n"
"NA3wJdl4DDUuQSV8hBgx6zoI1ZSGORprDFux7c6rhc77QZMSRrEgomBeklervEve\n"
"86ylWmZ3WWHV6RLMi8xNvjd71r4EPIGgY7BZU/VPBkq+uA7Gb6mbJnFgV43uh3xy\n"
"LRFgxIAphIukwTGSMZZR+AI+Qnp0BYTWovHXozOf3H8r6hozEoT02JHn0AeTfA==\n"
"-----END CERTIFICATE-----\n";

// RAII wrapper owning every mbedTLS context a single request needs. One
// connection per request (paste.rs's operations are infrequent -- license
// issuance/revocation, or a launch-time witness fetch -- so there is no
// value in connection pooling here, only complexity).
struct TlsConnection {
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    TlsConnection() {
        mbedtls_net_init(&server_fd);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&cacert);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);
    }
    ~TlsConnection() {
        mbedtls_ssl_close_notify(&ssl);
        mbedtls_net_free(&server_fd);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
    }
    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;
};

// Strip trailing whitespace/newlines -- same behavior as the old WinHTTP
// implementation's TrimRight, kept so Paste_Test's exact-match checks and
// Dev_Keygen's paste-ID extraction see byte-identical results.
void TrimRight(std::string& s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
        s.pop_back();
}

bool Connect(TlsConnection& c) {
    if (mbedtls_ctr_drbg_seed(&c.ctr_drbg, mbedtls_entropy_func, &c.entropy, nullptr, 0) != 0) {
        return false;
    }
    if (mbedtls_x509_crt_parse(&c.cacert,
                               reinterpret_cast<const unsigned char*>(kPastersCaPem),
                               sizeof(kPastersCaPem)) != 0) {
        return false;
    }
    if (mbedtls_net_connect(&c.server_fd, kHost, kPort, MBEDTLS_NET_PROTO_TCP) != 0) {
        return false;
    }
    if (mbedtls_ssl_config_defaults(&c.conf, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        return false;
    }
    // VERIFY_REQUIRED against ONLY our pinned CA -- mbedTLS's normal chain
    // validation (signature, validity window, hostname) still runs in full;
    // the only difference from a default setup is which single CA it's
    // allowed to trust.
    mbedtls_ssl_conf_authmode(&c.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&c.conf, &c.cacert, nullptr);
    mbedtls_ssl_conf_rng(&c.conf, mbedtls_ctr_drbg_random, &c.ctr_drbg);

    if (mbedtls_ssl_setup(&c.ssl, &c.conf) != 0) return false;
    if (mbedtls_ssl_set_hostname(&c.ssl, kHost) != 0) return false;
    mbedtls_ssl_set_bio(&c.ssl, &c.server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);

    int ret;
    while ((ret = mbedtls_ssl_handshake(&c.ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return false;
        }
    }
    // Belt-and-suspenders: VERIFY_REQUIRED already fails the handshake on a
    // bad chain, but checking the result explicitly documents the intent and
    // guards against a future config change silently downgrading authmode.
    return mbedtls_ssl_get_verify_result(&c.ssl) == 0;
}

bool WriteAll(TlsConnection& c, const std::string& data) {
    size_t written = 0;
    while (written < data.size()) {
        int ret = mbedtls_ssl_write(&c.ssl,
                                     reinterpret_cast<const unsigned char*>(data.data()) + written,
                                     data.size() - written);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret <= 0) return false;
        written += static_cast<size_t>(ret);
    }
    return true;
}

// Reads until the peer closes the connection (paste.rs's responses are small
// and the request always sends "Connection: close", so read-until-EOF is
// correct and simpler than parsing Content-Length/chunked framing).
std::optional<std::string> ReadUntilClose(TlsConnection& c) {
    std::string raw;
    unsigned char buf[4096];
    for (;;) {
        int ret = mbedtls_ssl_read(&c.ssl, buf, sizeof(buf));
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) break;
        if (ret < 0) break;  // peer closed the TCP connection without close_notify
        raw.append(reinterpret_cast<char*>(buf), static_cast<size_t>(ret));
    }
    if (raw.empty()) return std::nullopt;
    return raw;
}

struct HttpResponse {
    int status = 0;
    std::string body;
};

std::optional<HttpResponse> ParseHttpResponse(const std::string& raw) {
    size_t header_end = raw.find("\r\n\r\n");
    if (header_end == std::string::npos) return std::nullopt;

    size_t status_line_end = raw.find("\r\n");
    if (status_line_end == std::string::npos) return std::nullopt;
    std::string status_line = raw.substr(0, status_line_end);

    size_t sp1 = status_line.find(' ');
    if (sp1 == std::string::npos) return std::nullopt;

    HttpResponse resp;
    resp.status = std::atoi(status_line.c_str() + sp1 + 1);
    resp.body = raw.substr(header_end + 4);
    return resp;
}

std::optional<HttpResponse> DoRequest(const std::string& method, const std::string& path,
                                       const std::string& body) {
    TlsConnection c;
    if (!Connect(c)) return std::nullopt;

    std::ostringstream req;
    req << method << " " << path << " HTTP/1.1\r\n"
        << "Host: " << kHost << "\r\n"
        << "User-Agent: quark-online/1.0\r\n"
        << "Connection: close\r\n";
    if (!body.empty()) {
        req << "Content-Type: text/plain; charset=utf-8\r\n"
            << "Content-Length: " << body.size() << "\r\n";
    }
    req << "\r\n" << body;

    if (!WriteAll(c, req.str())) return std::nullopt;

    auto raw = ReadUntilClose(c);
    if (!raw) return std::nullopt;
    return ParseHttpResponse(*raw);
}

}  // namespace

std::optional<std::string> PostPaste(const std::vector<uint8_t>& sealed_blob) {
    static const char kHexChars[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(sealed_blob.size() * 2);
    for (uint8_t b : sealed_blob) {
        hex.push_back(kHexChars[b >> 4]);
        hex.push_back(kHexChars[b & 0x0F]);
    }

    auto resp = DoRequest("POST", "/", hex);
    if (!resp || (resp->status != 201 && resp->status != 200)) return std::nullopt;

    std::string body = resp->body;
    TrimRight(body);
    if (body.empty()) return std::nullopt;

    // paste.rs responds with the full URL, e.g. "https://paste.rs/abc12".
    const std::string prefix = "https://paste.rs/";
    if (body.size() > prefix.size() && body.substr(0, prefix.size()) == prefix) {
        return body.substr(prefix.size());
    }
    // Fallback: treat the whole response as the ID if it looks short.
    if (body.size() <= 32) return body;
    return std::nullopt;
}

std::optional<std::string> FetchPaste(const std::string& paste_id) {
    auto resp = DoRequest("GET", "/" + paste_id, "");
    if (!resp || resp->status != 200) return std::nullopt;

    std::string body = resp->body;
    TrimRight(body);
    if (body.empty()) return std::nullopt;
    return body;
}

bool DeletePaste(const std::string& paste_id) {
    auto resp = DoRequest("DELETE", "/" + paste_id, "");
    return resp.has_value() && (resp->status == 200 || resp->status == 204);
}

}  // namespace quark::online
