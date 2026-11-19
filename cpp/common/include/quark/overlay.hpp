#pragma once
// Exe-ADS witness -- a fourth, independent copy of the Lamport chain
// position, stored as an Alternate Data Stream on DRM_Wrapper.exe itself.
//
// --- Why an ADS on the exe? -------------------------------------------------
// An attacker backing up "state.bin + registry" to enable a rewind attack
// will not think to also copy the ADS attached to DRM_Wrapper.exe, because
// the exe looks like a static compiled binary that never changes -- and NTFS
// Alternate Data Streams are invisible to dir, Explorer, and most backup
// tools unless they explicitly handle them.  Post-obfuscation this channel's
// write/read code is opaque, so even a motivated reverse-engineer has to find
// and understand it before they can neutralize it.
//
// --- Why not PE-overlay (bytes appended to exe tail)? -----------------------
// Windows holds a Section object on the PE's primary data stream while the
// process runs.  Opening that stream for GENERIC_WRITE conflicts with the
// Section object and fails with ERROR_SHARING_VIOLATION.  An ADS (":quark")
// is a separate stream object -- the kernel does NOT include it in the image
// mapping, so it can be opened for write while the process is executing.
//
// --- Properties vs. the ThemeCache ADS channel ------------------------------
// Unlike the ThemeCache ADS (which lives in %APPDATA% and survives exe
// replacement), this stream is tied to the exe file itself: it is created
// with it, travels with it if it is moved (on the same NTFS volume), and is
// destroyed when the file is deleted or replaced by overwrite.  This creates
// a meaningfully different attack surface: wipe one, the other may survive.
//
// --- Sealed format ----------------------------------------------------------
//   Same variable-length frame as the ThemeCache channel:
//   magic "QOVL" (4 B) + version u32 LE (4 B) + iv (12 B) + tag (16 B)
//   + ct_len u32 LE (4 B) + ciphertext (76 B)
//   The AES key comes from quark::token::DeriveOverlayKey (domain-separated
//   from the ThemeCache key -- identical HWID+SECRET inputs, different label).

#include <string>
#include <vector>

#include "quark/registry.hpp"  // reuse Witness, LoadResult -- identical data

namespace quark::overlay {

// Returns the ADS path "exe_path:quark" via GetModuleFileNameA.
// Returns empty string on failure; caller fail-deadlies.
std::string StreamPath();

// Same three-way semantics as quark::registry::Load.
quark::registry::LoadResult Load(const quark::crypto::AesKey& overlay_key,
                                 const std::vector<uint8_t>& hwid_aad,
                                 quark::registry::Witness& out_witness);

// Creates or overwrites the ADS on the running exe.
bool Save(const quark::crypto::AesKey& overlay_key,
          const std::vector<uint8_t>& hwid_aad,
          const quark::registry::Witness& witness);

}  // namespace quark::overlay
