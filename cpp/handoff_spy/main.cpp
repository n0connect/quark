// handoff_spy.exe
//
// End-to-end test stub that impersonates "javaw.exe" during testing.
// Placed at jre\bin\javaw.exe so DRM_Wrapper launches it without any code changes.
//
// Protocol: QKH2 (v2 bi-directional challenge-response)
//
//   1. Read 136-byte QKH2 initial frame from stdin.
//      Validate magic "QKH2" and version 2.
//      Print handoff_secret (32 B), session_id (32 B), initial_seal (32 B) as hex.
//
//   2. Enter challenge loop (mirrors QuarkHeartbeat):
//      Read 40-byte CHAL frame.
//      Derive HMAC response = HMAC-SHA256(content_key, "RESP"||session_id||counter||nonce).
//      Write 32-byte response to stdout.
//      Repeat up to kMaxChallenges times, then exit 0.
//
// This validates that:
//   - DRM_Wrapper wrote the correct QKH2 initial frame
//   - The challenge pipe is functional and frames arrive on schedule
//   - DRM_Wrapper correctly verifies responses (spy derives them the same way)
//
// Exit 0 = all checks passed.  Exit 1 = bad frame (test failure).
//
// Deliberately dependency-free of quark_core on every platform: this stub
// exists to prove interoperability with an INDEPENDENT implementation of the
// QKH2 protocol, not to reuse DRM_Wrapper's own crypto code (which would let
// a shared bug in that code hide from this test). The SHA-256/HMAC-SHA256
// below (non-Windows path) is therefore hand-rolled in this file, not linked
// from quark_core -- see Sha256Transform/HmacSha256.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <unistd.h>
#endif

// ─── constants ───────────────────────────────────────────────────────────────
static const char kInitialMagic[4]  = {'Q', 'K', 'H', '2'};
static const uint32_t kInitialVersion = 2;
static const size_t kInitialFrameSize = 136;  // 4+4+32+32+32+32

static const char kChallengeMagic[4] = {'C', 'H', 'A', 'L'};
static const size_t kChallengeFrameSize = 40;
static const size_t kResponseSize = 32;

// Default: 1 challenge cycle (30 s).  Override via QUARK_SPY_CHALLENGES env var.
static const int kDefaultChallenges = 1;

// ─── helpers ─────────────────────────────────────────────────────────────────
static void PrintHex(const char* label, const uint8_t* data, size_t len) {
    fprintf(stderr, "[handoff_spy] %s: ", label);
    for (size_t i = 0; i < len; i++) fprintf(stderr, "%02x", data[i]);
    fprintf(stderr, "\n");
}

static uint32_t ReadU32LE(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void SecureZeroLocal(void* buf, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)buf;
    while (len--) *p++ = 0;
}

#if defined(_WIN32)

static int ReadExact(HANDLE h, uint8_t* buf, size_t want) {
    size_t total = 0;
    while (total < want) {
        DWORD n = 0;
        BOOL ok = ReadFile(h, buf + total, (DWORD)(want - total), &n, NULL);
        if (!ok || n == 0) return 0;
        total += n;
    }
    return 1;
}

static int WriteExact(HANDLE h, const uint8_t* buf, size_t len) {
    DWORD written = 0;
    BOOL ok = WriteFile(h, buf, (DWORD)len, &written, NULL);
    return ok && written == len;
}

// ─── CNG HMAC-SHA256 (avoids a dependency on mbedTLS from the spy) ───────────
static int HmacSha256(const uint8_t* key, size_t key_len,
                      const uint8_t* msg, size_t msg_len,
                      uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    ULONG hmac_obj_len = 0, out_len = 0;
    ULONG cb = 0;
    int rc = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) goto done;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hmac_obj_len,
                          sizeof(hmac_obj_len), &cb, 0) != 0) goto done;
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&out_len,
                          sizeof(out_len), &cb, 0) != 0) goto done;
    if (out_len != 32) goto done;

    {
        PUCHAR obj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, hmac_obj_len);
        if (!obj) goto done;
        if (BCryptCreateHash(alg, &hash, obj, hmac_obj_len,
                             (PUCHAR)key, (ULONG)key_len, 0) == 0
            && BCryptHashData(hash, (PUCHAR)msg, (ULONG)msg_len, 0) == 0
            && BCryptFinishHash(hash, out, 32, 0) == 0) {
            rc = 1;
        }
        if (hash) BCryptDestroyHash(hash);
        HeapFree(GetProcessHeap(), 0, obj);
    }
done:
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return rc;
}

static void DeriveContentKey(const uint8_t* handoff_secret, uint8_t out_key[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    ULONG obj_len = 0, cb = 0;

    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0);
    PUCHAR obj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, obj_len);
    BCryptCreateHash(alg, &hash, obj, obj_len, NULL, 0, 0);
    BCryptHashData(hash, (PUCHAR)"QUARK-CORE-CONTENT-KEY", 22, 0);
    BCryptHashData(hash, (PUCHAR)handoff_secret, 32, 0);
    BCryptFinishHash(hash, out_key, 32, 0);
    BCryptDestroyHash(hash);
    HeapFree(GetProcessHeap(), 0, obj);
    BCryptCloseAlgorithmProvider(alg, 0);
}

#else  // !_WIN32

static int ReadExact(int fd, uint8_t* buf, size_t want) {
    size_t total = 0;
    while (total < want) {
        ssize_t n = read(fd, buf + total, want - total);
        if (n <= 0) return 0;
        total += (size_t)n;
    }
    return 1;
}

static int WriteExact(int fd, const uint8_t* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n <= 0) return 0;
        total += (size_t)n;
    }
    return 1;
}

// ─── Hand-rolled, dependency-free SHA-256 (FIPS 180-4) ───────────────────────
// Deliberately NOT quark::crypto::Sha256 -- see the file header. This is a
// standard, from-scratch SHA-256 implementation: 64-round compression
// function, standard round constants and initial hash values.
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} Sha256Ctx;

static const uint32_t kSha256K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define SHA256_ROTR(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define SHA256_CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTR(x,2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_EP1(x) (SHA256_ROTR(x,6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_SIG0(x) (SHA256_ROTR(x,7) ^ SHA256_ROTR(x,18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ ((x) >> 10))

static void Sha256Transform(Sha256Ctx* ctx, const uint8_t data[]) {
    uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) |
               ((uint32_t)data[j+2] << 8) | ((uint32_t)data[j+3]);
    for ( ; i < 64; ++i)
        m[i] = SHA256_SIG1(m[i-2]) + m[i-7] + SHA256_SIG0(m[i-15]) + m[i-16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + kSha256K[i] + m[i];
        t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void Sha256Init(Sha256Ctx* ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void Sha256Update(Sha256Ctx* ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            Sha256Transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void Sha256Final(Sha256Ctx* ctx, uint8_t hash[32]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        Sha256Transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    Sha256Transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (uint8_t)((ctx->state[0] >> (24 - i*8)) & 0xff);
        hash[i + 4]  = (uint8_t)((ctx->state[1] >> (24 - i*8)) & 0xff);
        hash[i + 8]  = (uint8_t)((ctx->state[2] >> (24 - i*8)) & 0xff);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i*8)) & 0xff);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i*8)) & 0xff);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i*8)) & 0xff);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i*8)) & 0xff);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i*8)) & 0xff);
    }
}

// RFC 2104 HMAC, built on the SHA-256 above. `key_len` is always 32 in this
// file's actual usage (content_key), but this is written as the fully
// general construction (the > 64 branch) rather than a shortcut specific to
// that one call site -- a primitive should be correct on its own terms.
static int HmacSha256(const uint8_t* key, size_t key_len,
                      const uint8_t* msg, size_t msg_len,
                      uint8_t out[32]) {
    uint8_t k_ipad[64], k_opad[64], tk[32];
    Sha256Ctx ctx;

    if (key_len > 64) {
        Sha256Init(&ctx);
        Sha256Update(&ctx, key, key_len);
        Sha256Final(&ctx, tk);
        key = tk;
        key_len = 32;
    }

    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < key_len; ++i) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    uint8_t inner[32];
    Sha256Init(&ctx);
    Sha256Update(&ctx, k_ipad, 64);
    Sha256Update(&ctx, msg, msg_len);
    Sha256Final(&ctx, inner);

    Sha256Init(&ctx);
    Sha256Update(&ctx, k_opad, 64);
    Sha256Update(&ctx, inner, 32);
    Sha256Final(&ctx, out);

    SecureZeroLocal(k_ipad, 64);
    SecureZeroLocal(k_opad, 64);
    SecureZeroLocal(inner, 32);
    return 1;
}

static void DeriveContentKey(const uint8_t* handoff_secret, uint8_t out_key[32]) {
    Sha256Ctx ctx;
    Sha256Init(&ctx);
    Sha256Update(&ctx, (const uint8_t*)"QUARK-CORE-CONTENT-KEY", 22);
    Sha256Update(&ctx, handoff_secret, 32);
    Sha256Final(&ctx, out_key);
}

#endif  // !_WIN32

// ─── main ────────────────────────────────────────────────────────────────────
int main(void) {
#if defined(_WIN32)
    HANDLE stdin_h  = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE stdout_h = GetStdHandle(STD_OUTPUT_HANDLE);
#else
    int stdin_h = STDIN_FILENO;
    int stdout_h = STDOUT_FILENO;
#endif

    // Read challenge count from env var (for test speed control).
    int kMaxChallenges = kDefaultChallenges;
    {
#if defined(_WIN32)
        char buf[16] = {0};
        if (GetEnvironmentVariableA("QUARK_SPY_CHALLENGES", buf, sizeof(buf)) > 0) {
            int n = atoi(buf);
            if (n > 0 && n <= 100) kMaxChallenges = n;
        }
#else
        const char* env = getenv("QUARK_SPY_CHALLENGES");
        if (env) {
            int n = atoi(env);
            if (n > 0 && n <= 100) kMaxChallenges = n;
        }
#endif
    }

    // ── Step 1: Read and validate QKH2 initial frame ─────────────────────
    uint8_t frame[136] = {0};
    if (!ReadExact(stdin_h, frame, kInitialFrameSize)) {
        fprintf(stderr, "[handoff_spy] FAIL: could not read %zu bytes\n", kInitialFrameSize);
        return 1;
    }

    if (memcmp(frame, kInitialMagic, 4) != 0) {
        fprintf(stderr, "[handoff_spy] FAIL: bad magic %02x%02x%02x%02x\n",
                frame[0], frame[1], frame[2], frame[3]);
        return 1;
    }
    uint32_t ver = ReadU32LE(frame + 4);
    if (ver != kInitialVersion) {
        fprintf(stderr, "[handoff_spy] FAIL: bad version %u\n", ver);
        return 1;
    }

    const uint8_t* handoff_secret = frame + 8;
    const uint8_t* session_id     = frame + 40;
    const uint8_t* initial_seal   = frame + 72;
    const uint8_t* core_enc_key   = frame + 104;

    fprintf(stderr, "[handoff_spy] PASS: QKH2 initial frame valid (magic=QKH2, version=2, 136 bytes)\n");
    PrintHex("handoff_secret", handoff_secret, 32);
    PrintHex("session_id    ", session_id,     32);
    PrintHex("initial_seal  ", initial_seal,   32);
    PrintHex("core_enc_key  ", core_enc_key,   32);
    fflush(stderr);

    // Derive content_key (same derivation as Java's HandoffFrame.deriveContentKey)
    uint8_t content_key[32] = {0};
    DeriveContentKey(handoff_secret, content_key);
    PrintHex("content_key   ", content_key, 32);
    fflush(stderr);

    // ── Step 2: Challenge-response loop (mirrors QuarkHeartbeat) ─────────
    fprintf(stderr, "[handoff_spy] entering challenge-response loop (max %d cycles)\n", kMaxChallenges);
    fflush(stderr);

    for (int cycle = 0; cycle < kMaxChallenges; ++cycle) {
        uint8_t chal[40] = {0};
        if (!ReadExact(stdin_h, chal, kChallengeFrameSize)) {
            fprintf(stderr, "[handoff_spy] FAIL: could not read challenge frame (cycle %d)\n", cycle);
            SecureZeroLocal(content_key, 32);
            return 1;
        }

        if (memcmp(chal, kChallengeMagic, 4) != 0) {
            fprintf(stderr, "[handoff_spy] FAIL: bad challenge magic cycle %d\n", cycle);
            SecureZeroLocal(content_key, 32);
            return 1;
        }

        uint32_t counter = ReadU32LE(chal + 4);
        const uint8_t* nonce = chal + 8;

        fprintf(stderr, "[handoff_spy] challenge %u received (counter=%u)\n", cycle, counter);
        fflush(stderr);

        // Build HMAC message: "RESP" || session_id || counter (LE u32) || nonce
        uint8_t hmac_msg[4 + 32 + 4 + 32] = {0};
        memcpy(hmac_msg,      "RESP",     4);
        memcpy(hmac_msg + 4,  session_id, 32);
        hmac_msg[36] = (uint8_t)(counter & 0xFF);
        hmac_msg[37] = (uint8_t)((counter >> 8) & 0xFF);
        hmac_msg[38] = (uint8_t)((counter >> 16) & 0xFF);
        hmac_msg[39] = (uint8_t)((counter >> 24) & 0xFF);
        memcpy(hmac_msg + 40, nonce, 32);

        uint8_t response[32] = {0};
        if (!HmacSha256(content_key, 32, hmac_msg, sizeof(hmac_msg), response)) {
            fprintf(stderr, "[handoff_spy] FAIL: HMAC computation failed\n");
            SecureZeroLocal(content_key, 32);
            return 1;
        }

        if (!WriteExact(stdout_h, response, kResponseSize)) {
            fprintf(stderr, "[handoff_spy] FAIL: could not write response\n");
            SecureZeroLocal(content_key, 32);
            SecureZeroLocal(response, 32);
            return 1;
        }
        SecureZeroLocal(response, 32);

        fprintf(stderr, "[handoff_spy] challenge %u response sent\n", cycle);
        fflush(stderr);
    }

    fprintf(stderr, "[handoff_spy] PASS: %d challenge cycles completed\n", kMaxChallenges);
    fflush(stderr);

    SecureZeroLocal(content_key, 32);
    SecureZeroLocal(frame, 136);
    return 0;
}
