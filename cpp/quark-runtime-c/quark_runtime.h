#pragma once
// quark_runtime.h -- C/C++ runtime library for Quark DRM (QKH2 protocol)
//
// Mirrors the Java QuarkHeartbeat + QuarkRuntime contract for native applications.
// The protected C/C++ application is launched by DRM_Wrapper.exe with two pipes:
//   stdin  -- QKH2 initial frame (136 bytes) then challenge frames (40 bytes each)
//   stdout -- 32-byte HMAC responses (one per challenge)
//
// Usage in a protected C/C++ application:
//
//   #include "quark_runtime.h"
//
//   int main() {
//       if (!quark_init()) return 1;          // read 136-byte QKH2 frame from stdin
//       quark_heartbeat_start();              // start background challenge-response thread
//       // ... application code ...
//       long token = quark_checkpoint(0x1001);  // HMAC token; feed into business logic
//   }
//
// Security notes:
//   - quark_init() reads exactly 136 bytes from stdin. Does NOT check for EOF.
//   - quark_heartbeat_start() spawns a Windows thread. Must be called before any
//     blocking operation that would delay the first challenge response.
//   - quark_checkpoint() returns HMAC-SHA256(content_key, "CP"||id||counter) as
//     a 64-bit value. Feed it into real computation -- wrong key corrupts outputs.
//   - On pipe failure, the heartbeat thread calls ExitProcess(-1) immediately.

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// Reads the 136-byte QKH2 initial frame from stdin, validates magic/version,
// derives content_key and core_enc_key, stores them internally.
// Returns 1 on success, 0 on failure (wrong protocol, short read, etc.).
// Must be called once before quark_heartbeat_start() and quark_checkpoint().
int quark_init(void);

// Starts the background challenge-response heartbeat thread (non-blocking).
// This thread reads 40-byte CHAL frames from stdin, responds with 32-byte HMACs
// to stdout, and calls ExitProcess(-1) if the pipe breaks or a wrong response is expected.
// quark_init() must have been called first.
void quark_heartbeat_start(void);

// Returns a 64-bit HMAC-SHA256 token derived from the session content_key and
// the given checkpoint id. Feed into real computations -- returning 0 on wrong key
// corrupts business logic rather than providing a patchable boolean check.
//
// token = HMAC-SHA256(key=content_key, msg="CP"||id(u32-LE)||counter(u32-LE))
int64_t quark_checkpoint(int32_t id);

// Returns the raw core_enc_key (32 bytes) for use by native code that needs to
// decrypt its own encrypted bundle. The pointer is valid for the lifetime of the
// process. Must call quark_init() first.
const uint8_t* quark_core_enc_key(void);

#ifdef __cplusplus
}
#endif
