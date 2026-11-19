#pragma once
// Build-time embedded SHA-256 of quark.jar -- closes the gap that nothing
// else in this system covers: an attacker can simply replace quark.jar with
// a hostile build that, e.g., writes the handoff secret to disk before
// deriving content_key, and DRM_Wrapper would launch it none the wiser (it
// only ever speaks to "whatever's listening on the other end of the pipe").
//
// This is the cryptographic-interlocking principle (CLAUDE.md) applied one
// hop further: the wrapper now refuses to launch a jar whose hash it doesn't
// recognize, exactly as it refuses to operate with a state.bin it can't
// authenticate. A mismatch is reported as kWrapperJarIntegrityFailed and
// fail-deadlies before any prompt, pipe, or process is created.
//
// *** REGENERATE THIS EVERY TIME quark.jar CHANGES. ***
//   certutil -hashfile quark.jar SHA256      (Windows)
//   shasum -a 256 quark.jar                  (anywhere else, for cross-checking)
// then paste the 32 bytes below, in order.
//
// NOTE: this only binds the *jar*, not the JRE/`javaw.exe` launching it -- a
// substituted JRE is a separate, larger problem (CLAUDE.md already flags
// "bundle your own JRE rather than trust a system-wide `java`" for exactly
// this reason). Pinning the jar's hash is the cheap, high-value half of that;
// pinning an entire JRE's hash is not -- it changes on every JDK update and
// would turn "ship a security patch" into "regenerate and redistribute a
// giant constant", which is exactly the kind of complexity this project's
// "simple-solid" directive says to avoid chasing.

#include "quark/crypto.hpp"

namespace quark::drm_wrapper {

// SHA-256 of quark.jar (Java 8 bytecode build, 2026-06-09 -- rebuilt after the
// HandoffFrame.getCoreEncKey() defensive-copy fix and the Bootstrap
// System.out -> System.err response-pipe isolation fix).
// Regenerate with: shasum -a 256 quark.jar
inline constexpr quark::crypto::Sha256Digest kQuarkJarSha256 = {
    0x54, 0x62, 0x4d, 0xcd, 0x16, 0x7a, 0xe2, 0x56, 0x35, 0x97, 0x47, 0x8f,
    0x4d, 0xd3, 0xb0, 0xbb, 0x60, 0xdb, 0x5a, 0x3a, 0x6c, 0xc5, 0xa1, 0x1d,
    0x05, 0xa5, 0x17, 0xbb, 0xad, 0xfe, 0x3c, 0xfc,
};

}  // namespace quark::drm_wrapper
