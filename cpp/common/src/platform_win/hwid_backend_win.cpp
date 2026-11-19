#include "quark/platform/windows/hwid_backend_win.hpp"

#include "quark/hwid.hpp"

namespace quark::platform::win {

std::optional<Fingerprint> WindowsHwidBackend::Collect() const {
    auto components = quark::hwid::Collect();
    if (!components) return std::nullopt;

    Fingerprint fp;
    fp.fields.reserve(std::size(quark::hwid::kFieldOrder));

    // Field order and values must match quark::hwid::CanonicalBytes exactly
    // (see hwid_backend.hpp) -- this is a representation change only, not a
    // cryptographic one. Kept as an explicit, ordered list rather than
    // reusing quark::hwid's internal FieldValues() helper (unexported, and
    // duplicating eleven lines here is more honest than reaching into
    // hwid.cpp's anonymous namespace).
    fp.fields.push_back({"cpu_vendor_signature", components->cpu_vendor_signature});
    fp.fields.push_back({"cpu_brand", components->cpu_brand});
    fp.fields.push_back({"cpu_logical_cores", std::to_string(components->cpu_logical_cores)});
    fp.fields.push_back({"board_uuid", components->board_uuid});
    fp.fields.push_back({"board_manufacturer", components->board_manufacturer});
    fp.fields.push_back({"bios_identity", components->bios_identity});
    fp.fields.push_back({"chassis_identity", components->chassis_identity});
    fp.fields.push_back({"processor_identity", components->processor_identity});
    fp.fields.push_back({"ram_fingerprint", components->ram_fingerprint});
    fp.fields.push_back({"system_disk_serial", components->system_disk_serial});
    fp.fields.push_back({"system_volume_serial", components->system_volume_serial});
    fp.fields.push_back({"all_disk_serials", components->all_disk_serials});
    fp.fields.push_back({"gpu_fingerprint", components->gpu_fingerprint});
    fp.fields.push_back({"mac_address", components->mac_address});
    fp.fields.push_back({"machine_guid", components->machine_guid});
    fp.fields.push_back({"windows_product_id", components->windows_product_id});

    return fp;
}

}  // namespace quark::platform::win
