#include "quark/platform/linux/hwid_backend_linux.hpp"

#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_packet.h>

#include <algorithm>
#include <fstream>
#include <sstream>

namespace quark::platform::linux_ {

namespace {

std::string Trim(const std::string& s) {
    size_t begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

std::optional<std::string> ReadWholeFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    if (f.bad()) return std::nullopt;
    return Trim(ss.str());
}

// /etc/machine-id (systemd, present on essentially every modern distro after
// first boot) with the historical /var/lib/dbus/machine-id fallback systemd
// itself documents (machine-id(5)) for pre-systemd or dbus-only systems.
std::optional<std::string> ReadMachineId() {
    if (auto id = ReadWholeFile("/etc/machine-id"); id && !id->empty()) return id;
    if (auto id = ReadWholeFile("/var/lib/dbus/machine-id"); id && !id->empty()) return id;
    return std::nullopt;
}

// World-readable-by-default DMI fields only -- see header for why
// product_uuid/board_serial/product_serial (root-only, mode 0400) are
// deliberately not read here.
struct DmiFacts {
    std::string board;    // vendor|name|version
    std::string bios;     // vendor|version|date
    std::string product;  // name|version
    std::string chassis;  // vendor|type
};

std::optional<DmiFacts> ReadDmiFacts() {
    constexpr const char* kDmiDir = "/sys/class/dmi/id/";
    auto read_field = [&](const char* name) -> std::string {
        auto value = ReadWholeFile(std::string(kDmiDir) + name);
        return value.value_or(std::string());
    };

    // Absence of the directory entirely (no DMI table -- bare-metal ARM,
    // some containers/VMs) is fail-deadly, not "fall back to empty": see
    // header rationale on scope (x86_64 / UEFI-booted Linux only).
    std::ifstream probe(std::string(kDmiDir) + "board_vendor");
    if (!probe) return std::nullopt;

    DmiFacts facts;
    facts.board = read_field("board_vendor") + "|" + read_field("board_name") + "|" +
                  read_field("board_version");
    facts.bios = read_field("bios_vendor") + "|" + read_field("bios_version") + "|" +
                 read_field("bios_date");
    facts.product = read_field("product_name") + "|" + read_field("product_version");
    facts.chassis = read_field("chassis_vendor") + "|" + read_field("chassis_type");
    return facts;
}

// Total installed RAM, from /proc/meminfo's "MemTotal:" line (kB). A coarse
// analogue of Windows' per-DIMM ram_fingerprint -- Linux exposes no
// unprivileged per-slot SPD/serial data (that's `dmidecode --type 17`,
// root-only for the same reason product_uuid is), so this is what's
// actually available: still a real, independent fact that changes if RAM is
// added or removed, just not down to individual-stick granularity.
std::optional<uint64_t> ReadTotalMemoryKb() {
    std::ifstream f("/proc/meminfo");
    if (!f) return std::nullopt;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("MemTotal:", 0) == 0) {
            std::istringstream iss(line.substr(9));
            uint64_t kb = 0;
            if (iss >> kb) return kb;
            return std::nullopt;
        }
    }
    return std::nullopt;
}

// Storage topology fingerprint: every non-virtual block device's model +
// size, sorted. Not a real per-drive *serial* (that generally needs
// CAP_SYS_RAWIO / root via SG_IO, the Linux analogue of why product_uuid is
// skipped -- see header), but "what disks of what size and model are
// attached" is still a real, world-readable fact from /sys/block that
// changes if a drive is added, removed, or swapped for a different model.
std::optional<std::string> ReadBlockDeviceTopology() {
    DIR* dir = opendir("/sys/block");
    if (dir == nullptr) return std::nullopt;

    std::vector<std::string> devices;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name(entry->d_name);
        if (name == "." || name == "..") continue;
        // Skip virtual/pseudo block devices: loopback, ramdisk, zram,
        // device-mapper (already backed by a real device counted separately).
        if (name.rfind("loop", 0) == 0 || name.rfind("ram", 0) == 0 ||
            name.rfind("zram", 0) == 0 || name.rfind("dm-", 0) == 0) {
            continue;
        }

        std::string base = "/sys/block/" + name + "/";
        auto size = ReadWholeFile(base + "size");
        if (!size || size->empty()) continue;  // no size -- not a real block device
        auto model = ReadWholeFile(base + "device/model");  // often absent for virtio/NVMe namespaces; empty is fine

        std::ostringstream oss;
        oss << name << '|' << (model ? *model : std::string()) << '|' << *size;
        devices.push_back(oss.str());
    }
    closedir(dir);

    if (devices.empty()) return std::nullopt;
    std::sort(devices.begin(), devices.end());

    std::string joined;
    for (size_t i = 0; i < devices.size(); ++i) {
        if (i != 0) joined.push_back(';');
        joined += devices[i];
    }
    return joined;
}

// /proc/cpuinfo covers both the x86 field names (vendor_id, model name) and
// the ARM ones (CPU implementer, CPU part, CPU architecture) -- whichever
// this kernel actually reports. Logical core count is simply the number of
// "processor\t:" lines, architecture-independent.
struct CpuFacts {
    std::string identity;
    uint32_t logical_cores = 0;
};

std::optional<CpuFacts> ReadCpuFacts() {
    std::ifstream f("/proc/cpuinfo");
    if (!f) return std::nullopt;

    std::string vendor_id, model_name, implementer, part, architecture;
    uint32_t processor_count = 0;
    std::string line;
    while (std::getline(f, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = Trim(line.substr(0, colon));
        std::string value = Trim(line.substr(colon + 1));
        if (key == "processor") {
            ++processor_count;
        } else if (key == "vendor_id" && vendor_id.empty()) {
            vendor_id = value;
        } else if (key == "model name" && model_name.empty()) {
            model_name = value;
        } else if (key == "CPU implementer" && implementer.empty()) {
            implementer = value;
        } else if (key == "CPU part" && part.empty()) {
            part = value;
        } else if (key == "CPU architecture" && architecture.empty()) {
            architecture = value;
        }
    }
    if (processor_count == 0) return std::nullopt;

    CpuFacts facts;
    facts.logical_cores = processor_count;
    if (!vendor_id.empty() || !model_name.empty()) {
        facts.identity = vendor_id + "|" + model_name;  // x86
    } else if (!implementer.empty() || !part.empty()) {
        facts.identity = implementer + "|" + part + "|" + architecture;  // ARM
    } else {
        return std::nullopt;  // neither field family present -- unknown layout
    }
    return facts;
}

// The block device UUID backing "/" -- resolved via /proc/self/mountinfo
// (world-readable) plus /dev/disk/by-uuid (world-listable symlinks udev
// creates on every real install) rather than shelling out to `blkid`/
// `lsblk`, matching this project's "raw source over tool output" posture.
std::optional<std::string> ReadRootDeviceUuid() {
    std::ifstream mountinfo("/proc/self/mountinfo");
    if (!mountinfo) return std::nullopt;

    std::string target_device;
    std::string line;
    while (std::getline(mountinfo, line)) {
        std::istringstream iss(line);
        std::vector<std::string> fields;
        std::string field;
        while (iss >> field) fields.push_back(field);
        // mountinfo columns: ... mount_point ... - fs_type source ...
        // find " - " separator, then mount_point is column 4 (0-indexed).
        size_t dash = 0;
        for (; dash < fields.size(); ++dash) {
            if (fields[dash] == "-") break;
        }
        if (dash == fields.size() || dash + 2 >= fields.size()) continue;
        const std::string& mount_point = fields[4];
        const std::string& source = fields[dash + 2];
        if (mount_point == "/") {
            target_device = source;
            break;
        }
    }
    if (target_device.empty() || target_device[0] != '/') return std::nullopt;  // not a real block device (e.g. overlay)

    DIR* dir = opendir("/dev/disk/by-uuid");
    if (dir == nullptr) return std::nullopt;

    std::optional<std::string> result;
    char resolved_target[PATH_MAX];
    char resolved_link[PATH_MAX];
    if (realpath(target_device.c_str(), resolved_target) == nullptr) {
        closedir(dir);
        return std::nullopt;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name(entry->d_name);
        if (name == "." || name == "..") continue;
        std::string link_path = "/dev/disk/by-uuid/" + name;
        if (realpath(link_path.c_str(), resolved_link) == nullptr) continue;
        if (std::string(resolved_link) == std::string(resolved_target)) {
            result = name;
            break;
        }
    }
    closedir(dir);
    return result;
}

bool IsVirtualInterfaceName(std::string_view name) {
    return name.rfind("veth", 0) == 0 || name.rfind("docker", 0) == 0 || name.rfind("br-", 0) == 0 ||
           name.rfind("virbr", 0) == 0 || name.rfind("tun", 0) == 0 || name.rfind("tap", 0) == 0 ||
           name.rfind("lo", 0) == 0;
}

std::string FormatMac(const uint8_t* bytes) {
    static const char* kHex = "0123456789ABCDEF";
    std::string mac;
    mac.reserve(12);
    for (int i = 0; i < 6; ++i) {
        mac.push_back(kHex[bytes[i] >> 4]);
        mac.push_back(kHex[bytes[i] & 0x0F]);
    }
    return mac;
}

// Every non-virtual interface's MAC, sorted and joined -- stronger than
// "first NIC only": a machine with both Wi-Fi and wired Ethernet must match
// on both, and the field changes if either adapter is removed/replaced.
std::optional<std::string> ReadAllMacAddresses() {
    struct ifaddrs* addrs = nullptr;
    if (getifaddrs(&addrs) != 0) return std::nullopt;

    std::vector<std::string> macs;
    for (auto* a = addrs; a != nullptr; a = a->ifa_next) {
        if (a->ifa_addr == nullptr || a->ifa_addr->sa_family != AF_PACKET) continue;
        if (a->ifa_flags & IFF_LOOPBACK) continue;
        if (IsVirtualInterfaceName(a->ifa_name)) continue;

        auto* ll = reinterpret_cast<struct sockaddr_ll*>(a->ifa_addr);
        if (ll->sll_halen != 6) continue;

        macs.push_back(FormatMac(ll->sll_addr));
    }
    freeifaddrs(addrs);

    if (macs.empty()) return std::nullopt;
    std::sort(macs.begin(), macs.end());
    macs.erase(std::unique(macs.begin(), macs.end()), macs.end());

    std::string joined;
    for (size_t i = 0; i < macs.size(); ++i) {
        if (i != 0) joined.push_back(';');
        joined += macs[i];
    }
    return joined;
}

}  // namespace

std::optional<Fingerprint> LinuxHwidBackend::Collect() const {
    auto cpu = ReadCpuFacts();
    auto machine_id = ReadMachineId();
    auto dmi = ReadDmiFacts();
    auto total_memory_kb = ReadTotalMemoryKb();
    auto root_uuid = ReadRootDeviceUuid();
    auto block_topology = ReadBlockDeviceTopology();
    auto all_macs = ReadAllMacAddresses();

    if (!cpu || !machine_id || !dmi || !total_memory_kb || !root_uuid || !block_topology || !all_macs) {
        return std::nullopt;  // partial fingerprint rejected outright -- see header rationale
    }

    Fingerprint fp;
    fp.fields.push_back({"cpu_identity", cpu->identity});
    fp.fields.push_back({"cpu_logical_cores", std::to_string(cpu->logical_cores)});
    fp.fields.push_back({"machine_id", *machine_id});
    fp.fields.push_back({"dmi_board", dmi->board});
    fp.fields.push_back({"dmi_bios", dmi->bios});
    fp.fields.push_back({"dmi_product", dmi->product});
    fp.fields.push_back({"dmi_chassis", dmi->chassis});
    fp.fields.push_back({"total_memory_kb", std::to_string(*total_memory_kb)});
    fp.fields.push_back({"root_device_uuid", *root_uuid});
    fp.fields.push_back({"block_device_topology", *block_topology});
    fp.fields.push_back({"mac_addresses", *all_macs});
    return fp;
}

}  // namespace quark::platform::linux_
