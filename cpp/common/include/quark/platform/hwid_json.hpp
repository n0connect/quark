#pragma once
// JSON transport for quark::platform::Fingerprint -- the cross-platform
// successor to quark::hwid::ToJson/FromJson (Windows-only, cpp/quark_hwid.hpp),
// used by HWID_Extractor to hand a fingerprint from the licensed machine to
// whatever machine mints its license. Tags the JSON with which platform
// backend produced it (IHwidBackend::PlatformName()) so a mismatch (e.g. a
// macOS-collected fingerprint fed into a Windows-built keygen) is rejected
// outright instead of producing a state.bin that can never authenticate.

#include <optional>
#include <string>

#include "quark/platform/hwid_backend.hpp"

namespace quark::platform {

// {"platform": "<platform_name>", "fields": [{"name": "...", "value": "..."}, ...]}
std::string FingerprintToJson(const std::string& platform_name, const Fingerprint& fp);

struct ParsedFingerprint {
    std::string platform_name;
    Fingerprint fingerprint;
};

// Returns nullopt on malformed JSON. Not a general JSON parser -- Quark only
// ever reads files this codebase itself wrote (same posture as
// quark::hwid::FromJson).
std::optional<ParsedFingerprint> FingerprintFromJson(const std::string& json);

}  // namespace quark::platform
