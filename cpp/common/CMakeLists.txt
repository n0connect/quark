# quark_core: the platform-agnostic cryptographic/licensing logic -- AEAD
# wrappers, KDF (quark::token), the Lamport chain, the state.bin codec, the
# QKH2 handoff frame codec, and the numbered error registry. None of these
# files touch a Win32 API; they only depend on mbedTLS and the standard
# library. This is what lets the actual crypto logic be written, built, and
# unit-tested directly on macOS/Linux -- no Windows VM required for this half
# of the codebase. See CLAUDE.md and the top-level CMakeLists.txt comment for
# the platform-split rationale.
add_library(quark_core STATIC
    src/config.cpp
    src/crypto.cpp
    src/error.cpp
    src/handoff.cpp
    src/lamport.cpp
    src/online_crypto.cpp
    src/online_http.cpp
    src/orchestrator.cpp
    src/payload_codec.cpp
    src/platform_file_witness_store.cpp
    src/platform_hwid.cpp
    src/platform_hwid_json.cpp
    src/state.cpp
    src/token.cpp
    src/witness_codec.cpp
)

target_include_directories(quark_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(quark_core PUBLIC
    mbedtls
    mbedx509
    mbedcrypto
)

add_subdirectory(tests)

if(WIN32)
    # quark_platform_win: everything that reads or writes an OS-level
    # capability that only exists on Windows -- SMBIOS/HWID, the registry,
    # NTFS ADS, the PE overlay, and the IHwidBackend/IWitnessStore adapters
    # that expose all of the above through quark::platform's cross-platform
    # contract (see quark/platform/*.hpp). The paste.rs online-witness client
    # (quark::online) is now portable and lives entirely in quark_core
    # (online_crypto.cpp/online_http.cpp) -- it needs no Windows-specific code.
    # This is deliberately a separate target from quark_core: the split is
    # the actual boundary between "logic that could run anywhere" and
    # "capability that is Windows by definition", not just a build convenience.
    add_library(quark_platform_win STATIC
        src/ads.cpp
        src/hwid.cpp
        src/overlay.cpp
        src/registry.cpp
        src/platform_win/hwid_backend_win.cpp
        src/platform_win/process_lock_win.cpp
        src/platform_win/witness_stores_win.cpp
    )

    target_include_directories(quark_platform_win PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    target_link_libraries(quark_platform_win PUBLIC
        quark_core
        iphlpapi
        advapi32
    )

    # quark_common: kept as the combined name every executable already links
    # against (Dev_Keygen, DRM_Wrapper, HWID_Extractor, paste_test,
    # handoff_spy) -- an INTERFACE target so none of their CMakeLists.txt
    # files need to change.
    add_library(quark_common INTERFACE)
    target_link_libraries(quark_common INTERFACE quark_core quark_platform_win)
endif()

if(APPLE)
    # quark_platform_macos: the macOS IHwidBackend/IWitnessStore
    # implementations -- sysctl/IOKit/DiskArbitration for HWID, xattrs for
    # the two ADS-equivalent witness channels (the third channel, the
    # config-directory file, is quark_core's portable FileWitnessStore --
    # no macOS-specific code needed for it). See quark/platform/macos/*.hpp
    # for the per-field and per-channel rationale.
    add_library(quark_platform_macos STATIC
        src/platform_macos/anti_debug_macos.cpp
        src/platform_macos/hwid_backend_macos.cpp
        src/platform_macos/xattr_witness_store.cpp
        src/platform_posix/process_handoff.cpp
        src/platform_posix/process_lock_posix.cpp
    )

    target_include_directories(quark_platform_macos PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    target_link_libraries(quark_platform_macos PUBLIC
        quark_core
        "-framework CoreFoundation"
        "-framework IOKit"
        "-framework DiskArbitration"
    )

    # quark_common: kept as the combined name every executable already links
    # against, same convention as the Windows quark_common INTERFACE target
    # above -- lets HWID_Extractor/handoff_spy/quark-runtime-c and (later)
    # Dev_Keygen/DRM_Wrapper/paste_test link one name regardless of OS.
    add_library(quark_common INTERFACE)
    target_link_libraries(quark_common INTERFACE quark_core quark_platform_macos)
endif()

if(UNIX AND NOT APPLE)
    # quark_platform_linux: the Linux IHwidBackend/IWitnessStore
    # implementations -- /proc + /sys/class/dmi for HWID, "user."-namespaced
    # xattrs for the two ADS-equivalent witness channels (the third channel,
    # the config-directory file, is quark_core's portable FileWitnessStore --
    # no Linux-specific code needed for it). See
    # quark/platform/linux/*.hpp for the per-field and per-channel rationale,
    # including why root-only DMI fields (product_uuid, board_serial) are
    # deliberately not read.
    add_library(quark_platform_linux STATIC
        src/platform_linux/anti_debug_linux.cpp
        src/platform_linux/hwid_backend_linux.cpp
        src/platform_linux/xattr_witness_store.cpp
        src/platform_posix/process_handoff.cpp
        src/platform_posix/process_lock_posix.cpp
    )

    target_include_directories(quark_platform_linux PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    target_link_libraries(quark_platform_linux PUBLIC
        quark_core
    )

    add_library(quark_common INTERFACE)
    target_link_libraries(quark_common INTERFACE quark_core quark_platform_linux)
endif()
