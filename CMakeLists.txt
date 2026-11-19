cmake_minimum_required(VERSION 3.21)
# C is enabled alongside CXX for cpp/quark_c_api's tests -- plain C
# translation units that exercise the public C ABI exactly as an external
# Go/Python/Java binding would, not through any C++ header.
project(Quark C CXX)

# --- Platform split -----------------------------------------------------
# quark_core (cpp/common's crypto/token/lamport/state/handoff/error +
# quark::platform's interfaces) is plain C++17 + mbedTLS -- no Win32/POSIX
# API calls anywhere in it. It configures and builds on any OS, which is what
# lets the actual cryptographic/licensing logic be developed and genuinely,
# non-mocked tested (CLAUDE.md engineering rule 1) directly on macOS or Linux
# without round-tripping through a Windows VM for every change.
#
# Everything that touches a capability that only exists on Windows today --
# SMBIOS/HWID, the registry, NTFS ADS, WinHTTP, CreateProcess pipes, PEB
# reads -- lives in quark_platform_win and the Windows-only executables, and
# is only configured when building on Windows with MSVC (the /MT static
# runtime this project requires only exists in that toolchain). Linux and
# macOS platform layers are planned (see docs/PLAN.md) and will each get
# their own quark_platform_<os> target guarded the same way, implementing
# the same quark::platform::IHwidBackend / IWitnessStore contracts.
#
# Cross-compilation (e.g. clang-cl/llvm-mingw from macOS) is deliberately not
# used to bridge this gap: a cross-compiled .exe still can't be *run or
# tested* on the host that built it, which is exactly the kind of unverified
# artifact CLAUDE.md rule 1 forbids trusting. See CLAUDE.md "Cross-platform
# build & test strategy" for the reasoning and the CI-matrix alternative.
if(WIN32 AND NOT MSVC)
    message(FATAL_ERROR "Quark's Windows platform layer requires MSVC -- the architecture spec mandates the /MT static runtime.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Enabled once, here, so `ctest` run from any sandbox/build-<os> directory
# discovers every add_test() registered by subdirectories below (previously
# each tests/CMakeLists.txt called enable_testing() itself, which registers
# tests with CTest but never wires the top-level build directory to look for
# them -- ctest silently reported "No tests were found" from the root).
enable_testing()

if(MSVC)
    # Force the static multithreaded runtime (/MT, /MTd) on every target, in
    # every configuration -- this is what makes "zero external DLL
    # dependencies" possible for the Windows platform layer and executables.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# --- mbedTLS (vendored, static) ----------------------------------------------
# Pulled at configure time and built as part of this tree -- "statically gömülü"
# per the spec, with no prebuilt binaries checked in. Pin to a specific tag so
# builds are reproducible; bump deliberately, not via a floating branch.
#
# Declared and made available *before* our own /W4 /WX below: add_compile_options
# is a directory property that every add_subdirectory()'d target -- including
# this FetchContent-populated one -- inherits from the point it's added onward.
# mbedTLS's own headers (e.g. crypto_struct.h's intentional zero-sized array)
# trip /W4's C4200 in code we don't own and can't fix upstream from here; our
# /WX must not turn that into a build break. Ordering it this way keeps the
# strict flags scoped to only the code this project actually authors.
include(FetchContent)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_AS_SUBPROJECT ON CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
if(MSVC)
    set(MSVC_STATIC_RUNTIME ON CACHE BOOL "" FORCE)
endif()
# mbedTLS's own CMakeLists enables -Werror (MBEDTLS_FATAL_WARNINGS, default
# ON) for its own build, independent of any flags this project sets. Newer
# Apple Clang (observed: AppleClang 21) added -Wunterminated-string-init
# -ialization as an on-by-default diagnostic that mbedTLS 3.6.2's
# ssl_tls13_keys.c intentionally trips (fixed-size, deliberately-truncated
# label arrays) -- turning mbedTLS's own upstream code into a build break on
# a compiler version it predates. Same class of problem as the MSVC /W4 /WX
# note above (code we don't own tripping strict flags we don't control from
# upstream's side this time, not ours) and the same fix: don't let a vendored
# dependency's warnings-as-errors posture decide whether *our* build succeeds.
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.2
    GIT_SUBMODULES_RECURSE FALSE
)
FetchContent_MakeAvailable(mbedtls)

if(MSVC)
    add_compile_options(
        /W4
        /WX        # warnings are errors -- this codebase should compile clean
        /permissive-
        /utf-8
    )
    # Prevent <windows.h> from defining min/max macros that clash with
    # std::max initializer-list overloads. NOMINMAX is the canonical Windows
    # guard for this.
    add_compile_definitions(NOMINMAX)
else()
    # Same "compile clean or fail" posture as the MSVC branch above, via the
    # GCC/Clang equivalents -- quark_core must hold to this bar on every OS,
    # not just Windows (CLAUDE.md engineering rule 3).
    add_compile_options(
        -Wall
        -Wextra
        -Werror
    )
endif()

# quark_core (+ its real, non-mocked tests) builds and runs on every OS --
# this is the one subdirectory that is never gated behind WIN32.
add_subdirectory(cpp/common)

# quark_c: the public C ABI over quark_core (see cpp/quark_c_api/README and
# include/quark_c_api.h) -- also never gated behind WIN32. It links whichever
# quark_platform_<os> target this OS already built above, so it builds
# everywhere quark_core plus that OS's platform layer builds.
add_subdirectory(cpp/quark_c_api)

# quark_codecipher: reversible AES-256-CTR instruction-level scramble +
# real-machine-code reconstruction (see cpp/quark_codecipher/README.md).
# Superseded the earlier bytecode-VM approach (quark_vm/quark_vmasm,
# removed) -- this operates on the program's own real instructions, no new
# ISA. macOS-only today (its Materialize step uses MAP_JIT); gated
# accordingly until Linux/Windows equivalents are verified for real.
if(APPLE)
    add_subdirectory(cpp/quark_codecipher)
endif()

# quark_linkload: packaging-time symbol->dylib extraction via the real
# system linker + runtime Seal/Unseal+dlopen loading (see
# cpp/quark_linkload/README.md). dyld resolves every external reference
# the extracted code makes -- this module never decodes an instruction or a
# relocation record itself. macOS-only today; gated accordingly.
if(APPLE)
    add_subdirectory(cpp/quark_linkload)
endif()

# HWID_Extractor, handoff_spy, and quark-runtime-c are cross-platform (see
# docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md Phase A)
# -- never gated behind WIN32.
add_subdirectory(cpp/hwid_extractor)
add_subdirectory(cpp/handoff_spy)
add_subdirectory(cpp/quark-runtime-c)

# Dev_Keygen and paste_test are cross-platform as of Phase B of
# docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md.
add_subdirectory(cpp/dev_keygen)
add_subdirectory(cpp/paste_test)

# DRM_Wrapper is cross-platform as of Phase C of
# docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md.
add_subdirectory(cpp/drm_wrapper)
