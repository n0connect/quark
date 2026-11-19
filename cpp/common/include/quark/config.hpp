#pragma once
// Minimal flat key=value config file reader. CLAUDE.md rule 2: no path, URL,
// timeout, or feature toggle belongs inline in source unless it is
// cryptographically load-bearing enough that hardcoding is the *safer*
// choice (e.g. a KDF domain-separation string) -- a JVM launch path, a
// state.bin location, or a challenge interval is none of those things, so it
// belongs here instead of a `constexpr` in an orchestrator's main.cpp.
//
// Deliberately not JSON/YAML/TOML: one key per line, `key = value`, `#`
// comments, blank lines ignored. This is every tunable Quark's orchestrators
// currently need; pulling in a parser for a format capable of nesting would
// be solving a problem this project doesn't have (CLAUDE.md rule 3).

#include <optional>
#include <string>
#include <unordered_map>

namespace quark::config {

class Config {
public:
    // Reads `path`. Returns nullopt if the file cannot be opened -- callers
    // typically fail-deadly on this the same way a missing state.bin does,
    // since a missing config file means the program has no idea what to run.
    static std::optional<Config> Load(const std::string& path);

    // Returns the value for `key`, or `fallback` if the key is absent. There
    // is no "key present but fail if missing" variant -- every call site is
    // expected to supply a sane default, keeping this a pure convenience
    // reader rather than a schema-validating one.
    std::string GetOr(const std::string& key, const std::string& fallback) const;
    int GetIntOr(const std::string& key, int fallback) const;

private:
    std::unordered_map<std::string, std::string> values_;
};

}  // namespace quark::config
