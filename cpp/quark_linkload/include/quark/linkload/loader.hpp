#pragma once
// Runtime (customer machine): given the sealed bytes of a developer's own,
// completely normally compiled binary -- a whole executable or dylib, not
// a curated symbol -- sealed via quark::payload::Seal at packaging time,
// and the content_key a real HWID+Lamport+witness flow already produced,
// decrypts, loads, and hands back real, callable symbols. Never decodes an
// instruction or a relocation record itself; dyld does that exactly as it
// would for any other Mach-O image it loads.
//
// Honest scope: dlopen() on Darwin requires a real, filesystem-backed path
// (see README.md's "On-disk exposure window" -- shm_open-backed fds are
// not reopenable via /dev/fd on this OS, confirmed for real). The
// decrypted bytes touch disk for the few microseconds between write() and
// the unlink() this module issues immediately after dlopen() returns --
// this is a real, honest exposure window, not zero.

#include <optional>
#include <string>
#include <vector>

#include "quark/crypto.hpp"

namespace quark::linkload {

class ProtectedModule {
public:
    // Unseals `sealed` with `content_key`, writes the plaintext binary
    // bytes to a fresh, randomly-named file inside `temp_dir`, dlopen()s
    // it, and unlinks the file immediately afterward regardless of outcome
    // (POSIX unlink-while-open semantics keep an already-successful
    // dlopen's mapping valid -- verified for real, see README.md). Returns
    // std::nullopt on any failure (wrong content_key, tampering, dlopen
    // failure) -- deliberately no partial/degraded state to inspect.
    static std::optional<ProtectedModule> Load(const std::vector<uint8_t>& sealed,
                                                const crypto::AesKey& content_key,
                                                const std::string& temp_dir);

    ~ProtectedModule();
    ProtectedModule(ProtectedModule&& other) noexcept;
    ProtectedModule& operator=(ProtectedModule&& other) noexcept;
    ProtectedModule(const ProtectedModule&) = delete;
    ProtectedModule& operator=(const ProtectedModule&) = delete;

    // dlsym() wrapper -- nullptr if `symbol_name` isn't found. For a
    // sealed executable, "main" finds the program's own real entry point
    // (see tests/quark_linkload_hwid_test.cpp); for a sealed dylib, any
    // exported symbol's name works exactly as it would with a normal
    // dlopen() of that dylib.
    void* Symbol(const std::string& symbol_name) const;

private:
    explicit ProtectedModule(void* handle);
    void* handle_ = nullptr;
};

}  // namespace quark::linkload
