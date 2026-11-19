# quark_linkload: whole-binary Seal/Unseal + dlopen loading. Packaging is
# "read the developer's own, completely normally compiled binary's bytes,
# quark::payload::Seal them" -- no symbol search, no linker re-invocation;
# see README.md for why an earlier symbol-extraction design was replaced by
# this one (extracting a single symbol left the ORIGINAL binary still
# shipping that same code in plaintext, so it never actually protected
# anything). ProtectedModule (loader.cpp) is this module's entire runtime
# surface: Unseal -> write -> dlopen -> dlsym -> unlink. macOS-only today
# (dlopen-of-a-plain-Mach-O is written against Darwin) -- gated by the
# top-level CMakeLists' `if(APPLE)`, same as quark_codecipher.
add_library(quark_linkload STATIC
    src/loader.cpp
)

target_include_directories(quark_linkload PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(quark_linkload PUBLIC quark_core)

add_subdirectory(tests)
