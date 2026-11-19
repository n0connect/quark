#include "quark/linkload/loader.hpp"

#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#include "quark/payload.hpp"

namespace quark::linkload {

namespace {

std::string UniqueTempPath(const std::string& temp_dir) {
    auto suffix = crypto::RandomBytes(16);
    static const char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(32);
    for (uint8_t b : suffix) {
        hex.push_back(kHex[b >> 4]);
        hex.push_back(kHex[b & 0x0F]);
    }

    // No fixed extension: the sealed content may be a whole executable or
    // a dylib -- dlopen() decides how to load it from the real Mach-O
    // header, not the filename.
    std::string path = temp_dir;
    if (!path.empty() && path.back() != '/') path.push_back('/');
    path += "quark_linkload_" + hex;
    return path;
}

// Writes with the target mode set at creation time (O_CREAT's mode arg),
// rather than a separate later chmod() call, to avoid a window where the
// file briefly exists at the default umask-derived permissions.
bool WriteFileWithMode(const std::string& path, const std::vector<uint8_t>& bytes, mode_t mode) {
    int fd = open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd < 0) return false;

    size_t written = 0;
    while (written < bytes.size()) {
        ssize_t n = write(fd, bytes.data() + written, bytes.size() - written);
        if (n <= 0) {
            close(fd);
            return false;
        }
        written += static_cast<size_t>(n);
    }
    close(fd);
    return true;
}

}  // namespace

std::optional<ProtectedModule> ProtectedModule::Load(const std::vector<uint8_t>& sealed,
                                                       const crypto::AesKey& content_key,
                                                       const std::string& temp_dir) {
    auto plain = payload::Unseal(content_key, sealed);
    if (!plain) return std::nullopt;

    const std::string path = UniqueTempPath(temp_dir);
    if (!WriteFileWithMode(path, *plain, 0755)) return std::nullopt;

    void* handle = dlopen(path.c_str(), RTLD_NOW);
    // The on-disk file is only needed for dlopen() to resolve the path --
    // once the mapping exists, POSIX unlink-while-open semantics keep it
    // valid (verified for real; see README.md). Unlinking immediately,
    // whether dlopen succeeded or not, minimizes the on-disk exposure
    // window to the time between write() and this line.
    unlink(path.c_str());

    if (!handle) return std::nullopt;
    return ProtectedModule(handle);
}

ProtectedModule::ProtectedModule(void* handle) : handle_(handle) {}

ProtectedModule::~ProtectedModule() {
    if (handle_) dlclose(handle_);
}

ProtectedModule::ProtectedModule(ProtectedModule&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
}

ProtectedModule& ProtectedModule::operator=(ProtectedModule&& other) noexcept {
    if (this != &other) {
        if (handle_) dlclose(handle_);
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

void* ProtectedModule::Symbol(const std::string& symbol_name) const {
    if (!handle_) return nullptr;
    return dlsym(handle_, symbol_name.c_str());
}

}  // namespace quark::linkload
