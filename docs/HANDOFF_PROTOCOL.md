# The Quark Handoff Protocol (v2 — QKH2)

This document describes the QKH2 bi-directional challenge-response protocol
that connects `DRM_Wrapper.exe` (C++) and `quark.jar` (Java). It supersedes
the original one-shot QKH1 frame.

Authoritative implementations:

- `cpp/common/include/quark/handoff.hpp` — C++ frame encoder
- `java/drm-core/.../HandoffFrame.java` — Java decoder (must mirror byte-for-byte)

If you change either, you must change the other in the same commit.

---

## 1. Architecture change from QKH1

**QKH1 (old):** One-shot. DRM_Wrapper wrote 40 bytes, closed the pipe, and
`WaitForSingleObject`. Once the frame was sent, C++ had no further communication
with Java.

**QKH2 (new):** Bi-directional lifetime coupling. Two anonymous pipes:

```
DRM_Wrapper.exe (parent)            quark.jar (child)
─────────────────────────────       ─────────────────────────────
stdin_write ────────────────────►  stdin (Java reads)
                ◄───────────────── stdout (Java writes)
stdout_read
```

`DRM_Wrapper.exe` stays alive for the entire Java session:
- It holds the write end of the stdin pipe (never closed until process exits).
- It holds the read end of the stdout pipe (reads challenge responses).

Java's `QuarkHeartbeat` thread holds the only reader on stdin. If DRM_Wrapper
dies, `ReadFile` on stdin returns `FALSE` → `halt(-1)` immediately.

If Java dies (or doesn't respond within 10 s), DRM_Wrapper calls
`TerminateProcess` → mutual assured destruction enforced by pipe topology,
not by convention.

---

## 2. Frame types

### 2a. QKH2 initial frame (136 bytes, one-time at startup)

```
offset  size  field
------  ----  -----------------------------------------------------------
     0     4  magic          = {'Q','K','H','2'}
     4     4  version        = 2, little-endian u32
     8    32  handoff_secret   (Java derives content_key for challenges)
    40    32  session_id       (random 32 B; context for all challenge MACs)
    72    32  initial_seal     (HMAC-SHA256 proof of full DRM flow; stored by Java)
   104    32  core_enc_key     (stable per license; Java decrypts core.enc with this)
------  ----
   136        kInitialFrameSize
```

After writing the 136-byte frame, the **write end is kept open** — no EOF is
signalled. Java reads exactly 136 bytes and continues.

**Key separation:**
- `content_key = SHA256("QUARK-CORE-CONTENT-KEY" || handoff_secret)` — per-session (rolling anchor), used only for challenge-response HMAC.
- `core_enc_key = SHA256("QUARK-CORE-ENC-KEY" || state_key || SHA256(online_secret) || hwid)` — stable per license (excludes rolling anchor), used to decrypt `core.enc` once at launch.

`core.enc` can therefore be pre-encrypted once at license issuance and reused across all sessions on the same machine.

### 2b. Challenge frame (40 bytes, every ~30 s)

```
offset  size  field
------  ----  -----------------------------------------------------------
     0     4  magic   = {'C','H','A','L'}
     4     4  counter = monotonically increasing u32, little-endian
     8    32  nonce   = 32 fresh random bytes
------  ----
    40        kChallengeFrameSize
```

### 2c. Response (32 bytes, Java stdout → DRM_Wrapper)

```
offset  size  field
------  ----  -----------------------------------------------------------
     0    32  HMAC-SHA256(content_key, "RESP"||session_id||counter||nonce)
------  ----
    32        kResponseSize
```

---

## 3. Key derivation chain

Nothing in the wire format changes the underlying KDF:

```
state_key      = SHA256("QUARK-STATE-KEY"        || len(SECRET) || SECRET || hwid)
online_key     = SHA256("QUARK-ONLINE-KEY"        || len(SECRET) || SECRET || hwid)
handoff_secret = SHA256("QUARK-HANDOFF"           || state_key || new_anchor || hwid || online_secret)
content_key    = SHA256("QUARK-CORE-CONTENT-KEY"  || handoff_secret)
```

**What `kBuildSecret` alone cannot do:** `handoff_secret` requires `online_secret`
(only obtainable by fetching and decrypting the paste.rs blob) AND `new_anchor`
(only known once the user supplies the correct Lamport one-time key). Without both,
`content_key` is a uniformly random 32 bytes — `core.enc` fails AES-GCM auth.

**What the `initial_seal` adds:**

```
initial_seal = HMAC-SHA256(key=content_key,
    msg = "SEAL" || anchor_before || anchor_after || SHA256(online_secret) || hwid)
```

Java verifies this seal on receipt. Correct seal proves:
1. The HMAC key (content_key) was derived from the correct SECRET + HWID.
2. `anchor_before` / `anchor_after` match a real Lamport step.
3. `SHA256(online_secret)` proves paste.rs was live and returned the right blob.
4. HWID matches the sealed machine.

A fake DRM_Wrapper that skips any of these cannot produce a valid `initial_seal`.

---

## 4. Challenge-response: why it cannot be bypassed

Java's `QuarkHeartbeat` thread responds to each challenge with:

```
response = HMAC-SHA256(key=content_key, msg="RESP"||session_id||counter||nonce)
```

**Patching `QuarkHeartbeat` to return without responding:** DRM_Wrapper times
out after 10 s → `TerminateProcess`. Java cannot silence the parent this way.

**Patching `QuarkHeartbeat` to always return a fixed response:** The nonce is
freshly random each challenge → counter + nonce make every expected response
unique. An old response cannot be replayed.

**Injecting a fake content_key:** Responses must be HMAC under the **correct**
content_key. Without content_key, the attacker cannot compute a valid response
and DRM_Wrapper kills the process.

**Extracting content_key from memory:** Possible on the original machine with
a valid license. `content_key` is HWID-bound, so it cannot be transferred to
another machine. It also changes every session (new Lamport step → new
`handoff_secret` → new `content_key`).

---

## 5. Lifetime coupling in code

`drm_wrapper/handoff.hpp`:

```
LaunchJvmWithInitialHandoff(path, args, initial_frame)
  → creates stdin_pipe + stdout_pipe
  → CreateProcess(child stdout = stdout_write, child stdin = stdin_read)
  → closes stdin_read (child-facing end), closes stdout_write
  → writes initial_frame to stdin_write (does NOT close it)
  → returns JvmSession{process, stdin_write, stdout_read}

RunChallengeLoop(session, content_key, session_id)
  → loop:
      WaitForSingleObject(process, 30s)
      if WAIT_OBJECT_0 → process exited normally → return
      generate nonce, WriteFile(challenge) to stdin_write
      ReadResponseWithTimeout(stdout_read, 10s)
      if timeout/error → TerminateProcess → WaitForSingleObject → return
      if HMAC mismatch → TerminateProcess → WaitForSingleObject → return
      counter++
```

`java/drm-core/.../QuarkHeartbeat.java` (to be implemented):

```
QuarkHeartbeat (non-daemon thread):
  read 40 bytes from stdin → validate "CHAL" magic
  if ReadFile fails → Runtime.getRuntime().halt(-1)  ← parent died
  compute HMAC response
  write 32 bytes to stdout
  update last_verified_time
  loop

Watchdog (daemon thread):
  every 35 s: if now() - last_verified_time > 60 s → halt(-1)
```

---

## 6. What quark.jar does with the initial frame

`Bootstrap.main`:

1. Read exactly 136 bytes from stdin. Do **not** read until EOF (pipe stays open).
2. Validate magic `"QKH2"` and version `2`.
3. Derive `content_key = SHA256("QUARK-CORE-CONTENT-KEY" || handoff_secret)`.
4. Start `QuarkHeartbeat` non-daemon thread (passes `content_key` + `session_id`).
   Bootstrap must not read stdin after this point -- QuarkHeartbeat owns it.
5. Zero Bootstrap's copy of `content_key`.
6. Decrypt `core.enc` in memory using `core_enc_key` (AES-256-GCM). Wrong key → GCM auth failure → `System.exit(1)`. No boolean trap (CLAUDE.md rule 3).
7. Zero `core_enc_key`.
8. Load decrypted classes via `InMemoryClassLoader` and invoke `CoreEntryPoint.start`.

**On `initial_seal`:** Java cannot independently re-derive it (it lacks the Lamport
anchor values and hwid). The seal is stored by the frame but not verified inline.
The real tamper-proof guarantee is GCM authentication of `core.enc` under `core_enc_key`.
