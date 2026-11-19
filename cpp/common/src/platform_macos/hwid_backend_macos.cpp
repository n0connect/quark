#include "quark/platform/macos/hwid_backend_macos.hpp"

#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>

#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>
#include <IOKit/IOKitLib.h>

#include <algorithm>
#include <cstring>
#include <sstream>

namespace quark::platform::macos {

namespace {

std::string ToHex(const uint8_t* data, size_t len) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

// sysctlbyname wrapper for string-valued sysctls (e.g. machdep.cpu.brand_string, hw.model).
std::optional<std::string> SysctlString(const char* name) {
    size_t size = 0;
    if (sysctlbyname(name, nullptr, &size, nullptr, 0) != 0 || size == 0) return std::nullopt;
    std::string value(size, '\0');
    if (sysctlbyname(name, value.data(), &size, nullptr, 0) != 0) return std::nullopt;
    // sysctlbyname's reported size includes the trailing NUL for C-string sysctls.
    if (!value.empty() && value.back() == '\0') value.pop_back();
    return value;
}

template <typename T>
std::optional<T> SysctlValue(const char* name) {
    T value{};
    size_t size = sizeof(value);
    if (sysctlbyname(name, &value, &size, nullptr, 0) != 0 || size != sizeof(value)) return std::nullopt;
    return value;
}

// IOPlatformUUID / IOPlatformSerialNumber / target-sub-type all live on the
// IOPlatformExpertDevice service node -- the same node
// `ioreg -rd1 -c IOPlatformExpertDevice` reads, and what
// `system_profiler SPHardwareDataType` shells out to under the hood. Read
// directly via IOKit rather than shelling out, matching this project's
// existing "raw API over higher-level tooling" posture (CLAUDE.md's HWID
// table).
//
// Handles both property shapes actually seen on this node: CFString
// (Intel-era keys like "board-id") and CFData (Apple Silicon's device-tree-
// derived keys like "target-sub-type", which ioreg renders as `<"J614sAP">`
// -- the angle brackets mean OSData, not OSString, even when the bytes
// happen to be printable ASCII). CFData is hex-encoded verbatim rather than
// guessed at as text: some of these properties are fixed-size, NUL-padded
// byte buffers, and hex-encoding the raw bytes is simple, deterministic, and
// still avalanches exactly like every other field if a single byte differs.
std::optional<std::string> ReadPlatformExpertProperty(CFStringRef key) {
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault,
                                                        IOServiceMatching("IOPlatformExpertDevice"));
    if (service == IO_OBJECT_NULL) return std::nullopt;

    CFTypeRef value = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
    IOObjectRelease(service);
    if (value == nullptr) return std::nullopt;

    std::optional<std::string> result;
    if (CFGetTypeID(value) == CFStringGetTypeID()) {
        auto* str = static_cast<CFStringRef>(value);
        char buf[256] = {0};
        if (CFStringGetCString(str, buf, sizeof(buf), kCFStringEncodingUTF8)) {
            result = std::string(buf);
        }
    } else if (CFGetTypeID(value) == CFDataGetTypeID()) {
        auto* data = static_cast<CFDataRef>(value);
        const auto* bytes = CFDataGetBytePtr(data);
        auto len = static_cast<size_t>(CFDataGetLength(data));
        if (bytes != nullptr && len > 0) {
            result = ToHex(bytes, len);
        }
    }
    CFRelease(value);
    return result;
}

// The boot volume's BSD device name (e.g. "disk3s1s1"), read via statfs("/")
// rather than shelling out to `diskutil` -- f_mntfromname is exactly what
// `mount` itself reports, no parsing of human-readable tool output involved.
std::optional<std::string> BootVolumeBsdName() {
    struct statfs fs {};
    if (statfs("/", &fs) != 0) return std::nullopt;
    std::string dev(fs.f_mntfromname);
    constexpr std::string_view kDevPrefix = "/dev/";
    if (dev.rfind(kDevPrefix, 0) != 0) return std::nullopt;
    return dev.substr(kDevPrefix.size());
}

struct DiskUuids {
    std::string volume_uuid;  // ~ Windows system_volume_serial (the filesystem instance)
    std::string media_uuid;   // ~ Windows system_disk_serial (the physical/container store)
};

std::optional<DiskUuids> ReadBootDiskUuids() {
    auto bsd_name = BootVolumeBsdName();
    if (!bsd_name) return std::nullopt;

    DASessionRef session = DASessionCreate(kCFAllocatorDefault);
    if (session == nullptr) return std::nullopt;

    DADiskRef disk = DADiskCreateFromBSDName(kCFAllocatorDefault, session, bsd_name->c_str());
    if (disk == nullptr) {
        CFRelease(session);
        return std::nullopt;
    }

    CFDictionaryRef description = DADiskCopyDescription(disk);
    CFRelease(disk);
    CFRelease(session);
    if (description == nullptr) return std::nullopt;

    auto uuid_to_string = [](CFTypeRef ref) -> std::string {
        if (ref == nullptr || CFGetTypeID(ref) != CFUUIDGetTypeID()) return {};
        CFStringRef str = CFUUIDCreateString(kCFAllocatorDefault, static_cast<CFUUIDRef>(ref));
        if (str == nullptr) return {};
        char buf[64] = {0};
        std::string out;
        if (CFStringGetCString(str, buf, sizeof(buf), kCFStringEncodingUTF8)) out = buf;
        CFRelease(str);
        return out;
    };

    DiskUuids out;
    out.volume_uuid = uuid_to_string(CFDictionaryGetValue(description, kDADiskDescriptionVolumeUUIDKey));
    out.media_uuid = uuid_to_string(CFDictionaryGetValue(description, kDADiskDescriptionMediaUUIDKey));
    CFRelease(description);

    if (out.volume_uuid.empty() || out.media_uuid.empty()) return std::nullopt;
    return out;
}

// Is this interface one we should skip? Well-known virtual/utility
// interfaces (utun*, awdl*, llw*, bridge*, lo*) come and go with VPNs/AWDL/
// Internet Sharing and aren't a stable per-machine identifier, the same
// reasoning the Windows backend applies via its virtual-OUI table.
bool IsVirtualInterfaceName(std::string_view name) {
    return name.rfind("utun", 0) == 0 || name.rfind("awdl", 0) == 0 || name.rfind("llw", 0) == 0 ||
           name.rfind("bridge", 0) == 0 || name.rfind("lo", 0) == 0;
}

// Every non-virtual interface's MAC, sorted and joined -- stronger than
// "first NIC only": a machine with both Wi-Fi and Ethernet controllers must
// match on both, and the field changes if either adapter is removed/replaced,
// not just whichever one getifaddrs happens to enumerate first.
std::optional<std::string> ReadAllMacAddresses() {
    struct ifaddrs* addrs = nullptr;
    if (getifaddrs(&addrs) != 0) return std::nullopt;

    std::vector<std::string> macs;
    for (auto* a = addrs; a != nullptr; a = a->ifa_next) {
        if (a->ifa_addr == nullptr || a->ifa_addr->sa_family != AF_LINK) continue;
        if (a->ifa_flags & IFF_LOOPBACK) continue;
        if (IsVirtualInterfaceName(a->ifa_name)) continue;

        auto* sdl = reinterpret_cast<struct sockaddr_dl*>(a->ifa_addr);
        if (sdl->sdl_alen != 6) continue;

        const auto* mac = reinterpret_cast<const uint8_t*>(LLADDR(sdl));
        macs.push_back(ToHex(mac, 6));
    }
    freeifaddrs(addrs);

    if (macs.empty()) return std::nullopt;
    std::sort(macs.begin(), macs.end());
    macs.erase(std::unique(macs.begin(), macs.end()), macs.end());  // some interfaces share a MAC (e.g. Wi-Fi/AWDL alias)

    std::string joined;
    for (size_t i = 0; i < macs.size(); ++i) {
        if (i != 0) joined.push_back(';');
        joined += macs[i];
    }
    return joined;
}

}  // namespace

std::optional<Fingerprint> MacHwidBackend::Collect() const {
    auto cpu_brand = SysctlString("machdep.cpu.brand_string");
    auto hw_model = SysctlString("hw.model");
    auto logical_cpu = SysctlValue<int32_t>("hw.logicalcpu");
    auto memsize = SysctlValue<uint64_t>("hw.memsize");
    // hw.cpufamily/cputype/cpusubtype are numeric CPU-family codes Apple
    // assigns per microarchitecture (e.g. a specific value per Apple Silicon
    // generation) -- present on both Intel and Apple Silicon Macs, and a
    // fact independent of the free-text brand string above.
    auto cpu_family = SysctlValue<int32_t>("hw.cpufamily");
    auto cpu_type = SysctlValue<int32_t>("hw.cputype");
    auto cpu_subtype = SysctlValue<int32_t>("hw.cpusubtype");
    auto platform_uuid = ReadPlatformExpertProperty(CFSTR("IOPlatformUUID"));
    auto platform_serial = ReadPlatformExpertProperty(CFSTR("IOPlatformSerialNumber"));
    // A hardware model code distinct from hw.model's human-readable string
    // (e.g. "Mac14,2") -- Intel Macs expose this as the CFString "board-id"
    // (e.g. "Mac-A5C67F76ED83108C"); Apple Silicon Macs don't have that key
    // at all and instead expose an OSData "target-sub-type" on the same
    // IOPlatformExpertDevice node (verified via `ioreg -rd1 -c
    // IOPlatformExpertDevice` -- ioreg renders it as `<"J614sAP">`, but the
    // angle brackets mean it's data, not a string). Try both, in that order.
    auto board_id = ReadPlatformExpertProperty(CFSTR("board-id"));
    if (!board_id) board_id = ReadPlatformExpertProperty(CFSTR("target-sub-type"));
    auto disk_uuids = ReadBootDiskUuids();
    auto all_macs = ReadAllMacAddresses();

    if (!cpu_brand || !hw_model || !logical_cpu || !memsize || !cpu_family || !cpu_type ||
        !cpu_subtype || !platform_uuid || !platform_serial || !board_id || !disk_uuids || !all_macs) {
        return std::nullopt;  // partial fingerprint rejected outright -- see header rationale
    }

    Fingerprint fp;
    fp.fields.push_back({"cpu_brand", *cpu_brand});
    fp.fields.push_back({"cpu_logical_cores", std::to_string(*logical_cpu)});
    fp.fields.push_back({"cpu_family_ids", std::to_string(*cpu_family) + "|" + std::to_string(*cpu_type) +
                                                "|" + std::to_string(*cpu_subtype)});
    fp.fields.push_back({"hw_model", *hw_model});
    fp.fields.push_back({"board_id", *board_id});
    fp.fields.push_back({"platform_uuid", *platform_uuid});
    fp.fields.push_back({"platform_serial", *platform_serial});
    fp.fields.push_back({"physical_memory_bytes", std::to_string(*memsize)});
    fp.fields.push_back({"boot_volume_uuid", disk_uuids->volume_uuid});
    fp.fields.push_back({"boot_media_uuid", disk_uuids->media_uuid});
    fp.fields.push_back({"mac_addresses", *all_macs});
    return fp;
}

}  // namespace quark::platform::macos
