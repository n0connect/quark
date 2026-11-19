#include "quark/hwid.hpp"

// Windows-only low-level collection. Deliberately avoids high-level "identity"
// APIs (WMI, etc.) in favor of raw CPUID / SMBIOS / storage / registry reads --
// these are the same tables tools like dmidecode and CrystalDiskInfo read
// directly, and are far more resistant to hooking/virtualization than WMI's
// provider layer.

#include <intrin.h>

// <iphlpapi.h> needs <winsock2.h>'s types; <windows.h> alone would otherwise
// drag in the legacy <winsock.h> first and its include guard (_WINSOCKAPI_)
// would silently suppress everything <iphlpapi.h> (and <winsock2.h>) declare
// -- GetAdaptersAddresses & friends would simply vanish, not error, if these
// three lines were reordered. WIN32_LEAN_AND_MEAN is what stops <windows.h>
// from pulling in <winsock.h> in the first place.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <winioctl.h>

// DXGI: raw PCI vendor/device/subsystem/revision IDs for every GPU adapter,
// via IDXGIFactory1 -- the same low-level enumeration `dxdiag` uses, not
// WMI's Win32_VideoController (which normalizes/caches driver-reported
// strings rather than raw silicon IDs).
#include <dxgi.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "dxgi.lib")

namespace quark::hwid {

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

std::string Trim(const std::string& s) {
    size_t begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

// ===========================================================================
// CPU identity: vendor string + family/model/stepping (leaf 0/1) plus the
// full marketing brand string (leaves 0x80000002-4) and logical core count.
// Three independent CPUID facts rather than one -- a spoofed vendor string
// alone no longer reproduces the fingerprint.
// ===========================================================================

std::optional<std::string> ReadCpuVendorSignature() {
    std::array<int, 4> leaf0{};
    std::array<int, 4> leaf1{};
    __cpuid(leaf0.data(), 0);
    __cpuid(leaf1.data(), 1);

    char vendor[13] = {0};
    std::memcpy(vendor + 0, &leaf0[1], 4);
    std::memcpy(vendor + 4, &leaf0[3], 4);
    std::memcpy(vendor + 8, &leaf0[2], 4);

    uint32_t signature = static_cast<uint32_t>(leaf1[0]);  // EAX of leaf 1
    std::ostringstream oss;
    oss << vendor << ":" << ToHex(reinterpret_cast<uint8_t*>(&signature), sizeof(signature));
    return oss.str();
}

std::optional<std::string> ReadCpuBrand() {
    std::array<int, 4> ext{};
    __cpuid(ext.data(), 0x80000000);
    if (static_cast<uint32_t>(ext[0]) < 0x80000004) return std::nullopt;  // brand string unsupported

    char brand[49] = {0};
    for (int i = 0; i < 3; ++i) {
        __cpuid(ext.data(), 0x80000002 + i);
        std::memcpy(brand + i * 16, ext.data(), sizeof(ext));
    }
    return Trim(std::string(brand));
}

std::optional<uint32_t> ReadCpuLogicalCores() {
    std::array<int, 4> leaf1{};
    __cpuid(leaf1.data(), 1);
    if (!(leaf1[3] & (1 << 28))) {
        // HTT bit clear -- EBX[23:16] is not meaningful; one logical core.
        return 1u;
    }
    return (static_cast<uint32_t>(leaf1[1]) >> 16) & 0xFF;
}

// ===========================================================================
// SMBIOS: System UUID (Type 1), Base Board (Type 2), BIOS (Type 0), and
// per-slot Memory Device (Type 17) -- read via GetSystemFirmwareTable(RSMB),
// the same raw firmware table dmidecode parses; no WMI indirection.
// ===========================================================================

struct RawSmbiosData {
    BYTE used20CallingMethod;
    BYTE smbiosMajorVersion;
    BYTE smbiosMinorVersion;
    BYTE dmiRevision;
    DWORD length;
    BYTE smbiosTableData[1];
};

struct SmbiosHeader {
    BYTE type;
    BYTE length;
    WORD handle;
};

#pragma pack(push, 1)
struct SmbiosType0 {  // BIOS Information
    SmbiosHeader hdr;
    BYTE vendor;
    BYTE version;
    WORD starting_address_segment;
    BYTE release_date;
    // ... (rom size, characteristics, etc. follow; not needed)
};

struct SmbiosType1 {  // System Information
    SmbiosHeader hdr;
    BYTE manufacturer;
    BYTE product_name;
    BYTE version;
    BYTE serial_number;
    BYTE uuid[16];
    BYTE wake_up_type;
};

struct SmbiosType2 {  // Base Board Information
    SmbiosHeader hdr;
    BYTE manufacturer;
    BYTE product;
    BYTE version;
    BYTE serial_number;
    // ... (asset tag, feature flags, etc. follow; not needed)
};

struct SmbiosType3 {  // Chassis Information
    SmbiosHeader hdr;
    BYTE manufacturer;
    BYTE type;
    BYTE version;
    BYTE serial_number;
    BYTE asset_tag;
    // ... (boot-up state, power/thermal state, height, etc. follow; not needed)
};

struct SmbiosType4 {  // Processor Information -- firmware-reported strings,
                      // independent of the CPUID leaves ReadCpuBrand() reads
                      // (a different subsystem entirely: this comes from the
                      // motherboard firmware's table, not the silicon itself).
    SmbiosHeader hdr;
    BYTE socket_designation;
    BYTE processor_type;
    BYTE processor_family;
    BYTE manufacturer;
    BYTE processor_id[8];
    BYTE version;
    BYTE voltage;
    WORD external_clock;
    WORD max_speed;
    WORD current_speed;
    BYTE status;
    BYTE processor_upgrade;
    WORD l1_cache_handle;
    WORD l2_cache_handle;
    WORD l3_cache_handle;
    BYTE serial_number;
    BYTE asset_tag;
    BYTE part_number;
    // ... (core count, thread count, characteristics follow in newer
    // versions; not needed -- everything we want is in this fixed prefix.)
};

struct SmbiosType17Prefix {  // Memory Device -- fixed-offset prefix, version-stable
    SmbiosHeader hdr;
    WORD physical_memory_array_handle;
    WORD memory_error_information_handle;
    WORD total_width;
    WORD data_width;
    WORD size;
    BYTE form_factor;
    BYTE device_set;
    BYTE device_locator;
    BYTE bank_locator;
    BYTE memory_type;
    WORD type_detail;
    WORD speed;
    BYTE manufacturer;
    BYTE serial_number;
    BYTE asset_tag;
    BYTE part_number;
    // ... (rank, extended size, configured speeds follow in newer versions;
    // not needed -- everything we want is in this fixed prefix.)
};
#pragma pack(pop)

// Walks the formatted-section table; `visit` is called with
// (header, struct-start, string-table-start, string-table-end). Returning
// false from `visit` stops the walk early (unused here, kept for clarity).
template <typename Visitor>
void WalkSmbiosStructures(const BYTE* data, DWORD length, Visitor visit) {
    const BYTE* p = data;
    const BYTE* end = data + length;
    while (p + sizeof(SmbiosHeader) <= end) {
        const auto* hdr = reinterpret_cast<const SmbiosHeader*>(p);
        if (hdr->length < sizeof(SmbiosHeader)) break;

        const BYTE* struct_end = p + hdr->length;
        if (struct_end > end) break;

        const BYTE* str_table = struct_end;
        const BYTE* q = str_table;
        while (q + 1 < end && !(q[0] == 0 && q[1] == 0)) ++q;
        const BYTE* str_table_end = (q + 1 < end) ? q + 2 : end;

        if (!visit(*hdr, p, str_table, str_table_end)) return;

        p = str_table_end;
    }
}

std::string SmbiosString(const BYTE* str_table, const BYTE* table_end, BYTE index) {
    if (index == 0) return {};
    const BYTE* p = str_table;
    BYTE current = 1;
    while (p < table_end && current < index) {
        while (p < table_end && *p != 0) ++p;
        if (p < table_end) ++p;
        ++current;
    }
    if (p >= table_end) return {};
    const char* s = reinterpret_cast<const char*>(p);
    return Trim(std::string(s, strnlen(s, static_cast<size_t>(table_end - p))));
}

struct SmbiosFacts {
    std::string board_uuid;
    std::string board_manufacturer;
    std::string bios_identity;
    std::string chassis_identity;
    std::string processor_identity;
    std::vector<std::string> ram_slots;  // one rendered string per populated slot, in handle order
};

std::optional<SmbiosFacts> ReadSmbiosFacts() {
    DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (size == 0) return std::nullopt;

    std::vector<BYTE> buffer(size);
    if (GetSystemFirmwareTable('RSMB', 0, buffer.data(), size) != size) return std::nullopt;

    const auto* raw = reinterpret_cast<const RawSmbiosData*>(buffer.data());
    const BYTE* table = raw->smbiosTableData;
    DWORD table_len = raw->length;
    if (table + table_len > buffer.data() + buffer.size()) return std::nullopt;

    SmbiosFacts facts;
    bool found_uuid = false, found_board = false, found_bios = false;
    bool found_chassis = false, found_processor = false;
    // (locator, rendered) pairs, sorted by locator before joining -- makes the
    // canonical form independent of the order the firmware happens to list slots in.
    std::vector<std::pair<std::string, std::string>> ram_entries;

    WalkSmbiosStructures(table, table_len,
        [&](const SmbiosHeader& hdr, const BYTE* s, const BYTE* strs, const BYTE* strs_end) -> bool {
            if (hdr.type == 0 && hdr.length >= sizeof(SmbiosType0)) {
                const auto* t0 = reinterpret_cast<const SmbiosType0*>(s);
                std::ostringstream oss;
                oss << SmbiosString(strs, strs_end, t0->vendor) << '|'
                    << SmbiosString(strs, strs_end, t0->version) << '|'
                    << SmbiosString(strs, strs_end, t0->release_date);
                facts.bios_identity = oss.str();
                found_bios = true;
            } else if (hdr.type == 1 && hdr.length >= sizeof(SmbiosType1)) {
                const auto* t1 = reinterpret_cast<const SmbiosType1*>(s);
                facts.board_uuid = ToHex(t1->uuid, sizeof(t1->uuid));
                found_uuid = true;
            } else if (hdr.type == 2 && hdr.length >= sizeof(SmbiosType2)) {
                const auto* t2 = reinterpret_cast<const SmbiosType2*>(s);
                std::ostringstream oss;
                oss << SmbiosString(strs, strs_end, t2->manufacturer) << '|'
                    << SmbiosString(strs, strs_end, t2->product) << '|'
                    << SmbiosString(strs, strs_end, t2->version) << '|'
                    << SmbiosString(strs, strs_end, t2->serial_number);
                facts.board_manufacturer = oss.str();
                found_board = true;
            } else if (hdr.type == 3 && hdr.length >= sizeof(SmbiosType3)) {
                const auto* t3 = reinterpret_cast<const SmbiosType3*>(s);
                std::ostringstream oss;
                oss << SmbiosString(strs, strs_end, t3->manufacturer) << '|'
                    << static_cast<unsigned>(t3->type) << '|'
                    << SmbiosString(strs, strs_end, t3->serial_number) << '|'
                    << SmbiosString(strs, strs_end, t3->asset_tag);
                facts.chassis_identity = oss.str();
                found_chassis = true;
            } else if (hdr.type == 4 && hdr.length >= sizeof(SmbiosType4)) {
                const auto* t4 = reinterpret_cast<const SmbiosType4*>(s);
                std::ostringstream oss;
                oss << SmbiosString(strs, strs_end, t4->socket_designation) << '|'
                    << SmbiosString(strs, strs_end, t4->manufacturer) << '|'
                    << SmbiosString(strs, strs_end, t4->version) << '|'
                    << SmbiosString(strs, strs_end, t4->serial_number) << '|'
                    << SmbiosString(strs, strs_end, t4->asset_tag);
                facts.processor_identity = oss.str();
                found_processor = true;
            } else if (hdr.type == 17 && hdr.length >= sizeof(SmbiosType17Prefix)) {
                const auto* t17 = reinterpret_cast<const SmbiosType17Prefix*>(s);
                if (t17->size != 0) {  // populated slot only
                    std::string locator = SmbiosString(strs, strs_end, t17->device_locator);
                    std::ostringstream oss;
                    oss << locator << '|'
                        << SmbiosString(strs, strs_end, t17->manufacturer) << '|'
                        << SmbiosString(strs, strs_end, t17->part_number) << '|'
                        << SmbiosString(strs, strs_end, t17->serial_number) << '|'
                        << t17->size << '|' << t17->speed;
                    ram_entries.emplace_back(std::move(locator), oss.str());
                }
            }
            return true;
        });

    if (!found_uuid || !found_board || !found_bios || !found_chassis || !found_processor) return std::nullopt;

    std::sort(ram_entries.begin(), ram_entries.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    for (auto& [locator, rendered] : ram_entries) facts.ram_slots.push_back(std::move(rendered));

    return facts;
}

// ===========================================================================
// Storage: serial of the physical disk Windows booted from, plus the system
// volume's serial number. Two independent identifiers from one subsystem --
// re-imaging a disk changes the volume serial; swapping the physical drive
// changes the device serial; cloning defeats neither alone.
// ===========================================================================

// Shared by ReadSystemDiskSerial (boot disk only) and ReadAllDiskSerials
// (every attached physical drive) -- same IOCTL_STORAGE_QUERY_PROPERTY call,
// factored out so the two callers can't silently drift in how they parse
// the STORAGE_DEVICE_DESCRIPTOR.
std::optional<std::string> ReadPhysicalDriveSerial(DWORD disk_number) {
    wchar_t physical_path[64] = {0};
    swprintf_s(physical_path, L"\\\\.\\PhysicalDrive%lu", disk_number);

    HANDLE disk = CreateFileW(physical_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (disk == INVALID_HANDLE_VALUE) return std::nullopt;

    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    std::vector<BYTE> out_buf(1024);
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(disk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                              out_buf.data(), static_cast<DWORD>(out_buf.size()), &bytes, nullptr);
    CloseHandle(disk);
    if (!ok || bytes < sizeof(STORAGE_DEVICE_DESCRIPTOR)) return std::nullopt;

    const auto* desc = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(out_buf.data());
    if (desc->SerialNumberOffset == 0 || desc->SerialNumberOffset >= bytes) return std::nullopt;

    const char* serial = reinterpret_cast<const char*>(out_buf.data()) + desc->SerialNumberOffset;
    std::string result = Trim(std::string(serial, strnlen(serial, bytes - desc->SerialNumberOffset)));
    if (result.empty()) return std::nullopt;
    return result;
}

std::optional<std::string> ReadSystemDiskSerial() {
    wchar_t windows_dir[MAX_PATH] = {0};
    if (GetWindowsDirectoryW(windows_dir, MAX_PATH) == 0) return std::nullopt;

    wchar_t volume_path[MAX_PATH] = {0};
    if (!GetVolumePathNameW(windows_dir, volume_path, MAX_PATH)) return std::nullopt;

    wchar_t volume_name[] = L"\\\\.\\C:";
    volume_name[4] = volume_path[0];

    HANDLE vol = CreateFileW(volume_name, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_EXISTING, 0, nullptr);
    if (vol == INVALID_HANDLE_VALUE) return std::nullopt;

    // Fixed-size struct -- only `Extents[0]` is read. Correct for the
    // overwhelmingly common case (system volume backed by a single physical
    // disk); a volume spanning multiple disks would report only the first.
    // That's an acceptable simplification here: the goal is a stable
    // per-machine identifier, not an exhaustive storage topology dump (that's
    // what ReadAllDiskSerials below is for), and the boot disk practically
    // never changes independent of the others.
    VOLUME_DISK_EXTENTS extents{};
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(vol, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0,
                              &extents, sizeof(extents), &bytes, nullptr);
    CloseHandle(vol);
    if (!ok || extents.NumberOfDiskExtents == 0) return std::nullopt;

    return ReadPhysicalDriveSerial(extents.Extents[0].DiskNumber);
}

// Every attached physical drive's serial, not just the boot one -- adding,
// removing, or swapping ANY drive changes this field. `\\.\PhysicalDriveN`
// enumerates densely from 0, so probing sequentially until the first
// CreateFileW failure is the standard way to walk them (same technique
// diskpart/CrystalDiskInfo use); 64 is far beyond any real desktop/server
// drive bay count, just a sane upper bound against a runaway loop.
std::optional<std::string> ReadAllDiskSerials() {
    constexpr DWORD kMaxDrivesToProbe = 64;
    std::vector<std::string> serials;

    for (DWORD i = 0; i < kMaxDrivesToProbe; ++i) {
        wchar_t probe_path[64] = {0};
        swprintf_s(probe_path, L"\\\\.\\PhysicalDrive%lu", i);
        HANDLE probe = CreateFileW(probe_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                   OPEN_EXISTING, 0, nullptr);
        if (probe == INVALID_HANDLE_VALUE) break;  // no more drives at or past this index
        CloseHandle(probe);

        if (auto serial = ReadPhysicalDriveSerial(i)) {
            serials.push_back(*serial);
        }
    }

    if (serials.empty()) return std::nullopt;
    std::sort(serials.begin(), serials.end());

    std::string joined;
    for (size_t i = 0; i < serials.size(); ++i) {
        if (i != 0) joined.push_back(';');
        joined += serials[i];
    }
    return joined;
}

std::optional<std::string> ReadSystemVolumeSerial() {
    wchar_t windows_dir[MAX_PATH] = {0};
    if (GetWindowsDirectoryW(windows_dir, MAX_PATH) == 0) return std::nullopt;

    wchar_t volume_path[MAX_PATH] = {0};
    if (!GetVolumePathNameW(windows_dir, volume_path, MAX_PATH)) return std::nullopt;

    DWORD serial = 0;
    if (!GetVolumeInformationW(volume_path, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        return std::nullopt;
    }
    return ToHex(reinterpret_cast<uint8_t*>(&serial), sizeof(serial));
}

// ===========================================================================
// Network: first non-virtual NIC's permanent (burned-in) MAC address.
// ===========================================================================

std::optional<std::string> ReadPrimaryMac() {
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                        GAA_FLAG_SKIP_DNS_SERVER,
                         nullptr, nullptr, &size);
    if (size == 0) return std::nullopt;

    std::vector<BYTE> buffer(size);
    auto* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC,
                             GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                             nullptr, addresses, &size) != NO_ERROR) {
        return std::nullopt;
    }

    static const uint8_t kVirtualOuis[][3] = {
        {0x00, 0x05, 0x69},  // VMware
        {0x00, 0x0C, 0x29},  // VMware
        {0x00, 0x1C, 0x14},  // VMware
        {0x00, 0x50, 0x56},  // VMware
        {0x08, 0x00, 0x27},  // VirtualBox
        {0x00, 0x15, 0x5D},  // Hyper-V
    };

    for (auto* a = addresses; a != nullptr; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (a->PhysicalAddressLength != 6) continue;

        bool is_virtual = false;
        for (const auto& oui : kVirtualOuis) {
            if (std::memcmp(a->PhysicalAddress, oui, 3) == 0) {
                is_virtual = true;
                break;
            }
        }
        if (is_virtual) continue;

        return ToHex(a->PhysicalAddress, a->PhysicalAddressLength);
    }
    return std::nullopt;
}

// ===========================================================================
// Graphics: raw PCI vendor/device/subsystem/revision IDs for every GPU
// adapter, via IDXGIFactory1 -- not WMI's Win32_VideoController, which
// reports driver-normalized strings rather than the silicon's own PCI IDs.
// Sorted so the canonical form doesn't depend on DXGI's enumeration order.
// ===========================================================================

std::optional<std::string> ReadGpuFingerprint() {
    IDXGIFactory1* factory = nullptr;
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), reinterpret_cast<void**>(&factory))) ||
        factory == nullptr) {
        return std::nullopt;
    }

    std::vector<std::string> adapters;
    IDXGIAdapter1* adapter = nullptr;
    for (UINT i = 0; factory->EnumAdapters1(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
        DXGI_ADAPTER_DESC1 desc{};
        if (SUCCEEDED(adapter->GetDesc1(&desc))) {
            // Skip Microsoft's software rasterizer ("Microsoft Basic Render
            // Driver") -- not a physical GPU, and its IDs are the same on
            // every Windows install, contributing zero entropy while adding
            // a false sense of an extra independent source.
            if (!(desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE)) {
                std::ostringstream oss;
                oss << ToHex(reinterpret_cast<uint8_t*>(&desc.VendorId), sizeof(desc.VendorId)) << '|'
                    << ToHex(reinterpret_cast<uint8_t*>(&desc.DeviceId), sizeof(desc.DeviceId)) << '|'
                    << ToHex(reinterpret_cast<uint8_t*>(&desc.SubSysId), sizeof(desc.SubSysId)) << '|'
                    << ToHex(reinterpret_cast<uint8_t*>(&desc.Revision), sizeof(desc.Revision));
                adapters.push_back(oss.str());
            }
        }
        adapter->Release();
        adapter = nullptr;
    }
    factory->Release();

    if (adapters.empty()) return std::nullopt;
    std::sort(adapters.begin(), adapters.end());

    std::string joined;
    for (size_t i = 0; i < adapters.size(); ++i) {
        if (i != 0) joined.push_back(';');
        joined += adapters[i];
    }
    return joined;
}

// ===========================================================================
// OS install identity: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid, and
// a second, independently-generated identifier from a completely different
// registry subtree (HKLM\...\Windows NT\CurrentVersion\ProductId). Both are
// per-install and both are regenerated on a clean OS reinstall (intentionally
// treated as "different machine" for licensing purposes, same policy as
// before) -- two separately-maintained values rather than one means an
// attacker patching/restoring one doesn't automatically fix the other.
// ===========================================================================

std::optional<std::string> ReadMachineGuid() {
    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0,
                      KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    char buf[64] = {0};
    DWORD buf_size = sizeof(buf);
    DWORD type = 0;
    LONG rc = RegQueryValueExA(key, "MachineGuid", nullptr, &type,
                               reinterpret_cast<LPBYTE>(buf), &buf_size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_SZ) return std::nullopt;
    return std::string(buf, strnlen(buf, sizeof(buf)));
}

std::optional<std::string> ReadWindowsProductId() {
    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
                      KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    char buf[64] = {0};
    DWORD buf_size = sizeof(buf);
    DWORD type = 0;
    LONG rc = RegQueryValueExA(key, "ProductId", nullptr, &type,
                               reinterpret_cast<LPBYTE>(buf), &buf_size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_SZ) return std::nullopt;
    return std::string(buf, strnlen(buf, sizeof(buf)));
}

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

}  // namespace

std::optional<Components> Collect() {
    auto cpu_vendor_sig = ReadCpuVendorSignature();
    auto cpu_brand = ReadCpuBrand();
    auto cpu_cores = ReadCpuLogicalCores();
    auto smbios = ReadSmbiosFacts();
    auto disk_serial = ReadSystemDiskSerial();
    auto volume_serial = ReadSystemVolumeSerial();
    auto all_disk_serials = ReadAllDiskSerials();
    auto gpu = ReadGpuFingerprint();
    auto mac = ReadPrimaryMac();
    auto guid = ReadMachineGuid();
    auto product_id = ReadWindowsProductId();

    // Partial fingerprints are deliberately rejected -- see header comment.
    if (!cpu_vendor_sig || !cpu_brand || !cpu_cores || !smbios || !disk_serial ||
        !volume_serial || !all_disk_serials || !gpu || !mac || !guid || !product_id) {
        return std::nullopt;
    }
    if (smbios->ram_slots.empty()) return std::nullopt;  // no populated DIMMs read -- treat as anomaly

    Components c;
    c.cpu_vendor_signature = *cpu_vendor_sig;
    c.cpu_brand = *cpu_brand;
    c.cpu_logical_cores = *cpu_cores;
    c.board_uuid = smbios->board_uuid;
    c.board_manufacturer = smbios->board_manufacturer;
    c.bios_identity = smbios->bios_identity;
    c.chassis_identity = smbios->chassis_identity;
    c.processor_identity = smbios->processor_identity;

    std::ostringstream ram;
    for (size_t i = 0; i < smbios->ram_slots.size(); ++i) {
        if (i != 0) ram << ';';
        ram << smbios->ram_slots[i];
    }
    c.ram_fingerprint = ram.str();

    c.system_disk_serial = *disk_serial;
    c.system_volume_serial = *volume_serial;
    c.all_disk_serials = *all_disk_serials;
    c.gpu_fingerprint = *gpu;
    c.mac_address = *mac;
    c.machine_guid = *guid;
    c.windows_product_id = *product_id;
    return c;
}

namespace {

// Returns the i-th field of `c` in kFieldOrder, rendered as a string.
// Centralizing this means CanonicalBytes/ToJson/FromJson can never silently
// disagree about field order or rendering.
std::vector<std::string> FieldValues(const Components& c) {
    return {
        c.cpu_vendor_signature,
        c.cpu_brand,
        std::to_string(c.cpu_logical_cores),
        c.board_uuid,
        c.board_manufacturer,
        c.bios_identity,
        c.chassis_identity,
        c.processor_identity,
        c.ram_fingerprint,
        c.system_disk_serial,
        c.system_volume_serial,
        c.all_disk_serials,
        c.gpu_fingerprint,
        c.mac_address,
        c.machine_guid,
        c.windows_product_id,
    };
}

}  // namespace

std::vector<uint8_t> CanonicalBytes(const Components& c) {
    std::string joined;
    for (const auto& v : FieldValues(c)) {
        if (!joined.empty()) joined.push_back('\x1F');
        joined += v;
    }
    return std::vector<uint8_t>(joined.begin(), joined.end());
}

std::string ToJson(const Components& c) {
    auto values = FieldValues(c);
    std::ostringstream oss;
    oss << "{\n";
    for (size_t i = 0; i < values.size(); ++i) {
        oss << "  \"" << kFieldOrder[i] << "\": \"" << JsonEscape(values[i]) << "\"";
        if (i + 1 != values.size()) oss << ',';
        oss << '\n';
    }
    oss << "}\n";
    return oss.str();
}

namespace {

// Minimal hand-rolled flat-object string-field parser -- sufficient for the
// fixed-shape document `ToJson` produces. Not a general JSON parser:
// Dev_Keygen only ever reads files this codebase wrote.
std::optional<std::string> FindStringField(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return std::nullopt;
    pos = json.find('"', pos);
    if (pos == std::string::npos) return std::nullopt;
    ++pos;
    std::string out;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) ++pos;
        out.push_back(json[pos]);
        ++pos;
    }
    if (pos >= json.size()) return std::nullopt;
    return out;
}

}  // namespace

std::optional<Components> FromJson(const std::string& json) {
    auto get = [&](const char* key) { return FindStringField(json, key); };

    auto cpu_vendor_sig = get("cpu_vendor_signature");
    auto cpu_brand = get("cpu_brand");
    auto cpu_cores_str = get("cpu_logical_cores");
    auto board_uuid = get("board_uuid");
    auto board_manufacturer = get("board_manufacturer");
    auto bios_identity = get("bios_identity");
    auto chassis_identity = get("chassis_identity");
    auto processor_identity = get("processor_identity");
    auto ram = get("ram_fingerprint");
    auto disk_serial = get("system_disk_serial");
    auto volume_serial = get("system_volume_serial");
    auto all_disk_serials = get("all_disk_serials");
    auto gpu_fingerprint = get("gpu_fingerprint");
    auto mac = get("mac_address");
    auto guid = get("machine_guid");
    auto product_id = get("windows_product_id");

    if (!cpu_vendor_sig || !cpu_brand || !cpu_cores_str || !board_uuid || !board_manufacturer ||
        !bios_identity || !chassis_identity || !processor_identity || !ram || !disk_serial ||
        !volume_serial || !all_disk_serials || !gpu_fingerprint || !mac || !guid || !product_id) {
        return std::nullopt;
    }

    Components c;
    c.cpu_vendor_signature = *cpu_vendor_sig;
    c.cpu_brand = *cpu_brand;
    c.cpu_logical_cores = static_cast<uint32_t>(std::strtoul(cpu_cores_str->c_str(), nullptr, 10));
    c.board_uuid = *board_uuid;
    c.board_manufacturer = *board_manufacturer;
    c.bios_identity = *bios_identity;
    c.chassis_identity = *chassis_identity;
    c.processor_identity = *processor_identity;
    c.ram_fingerprint = *ram;
    c.system_disk_serial = *disk_serial;
    c.system_volume_serial = *volume_serial;
    c.all_disk_serials = *all_disk_serials;
    c.gpu_fingerprint = *gpu_fingerprint;
    c.mac_address = *mac;
    c.machine_guid = *guid;
    c.windows_product_id = *product_id;
    return c;
}

}  // namespace quark::hwid
