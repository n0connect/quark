# Real fixture functions, compiled into a real dylib at build time (not a
# throwaway sandbox script) -- CLAUDE.md rule 1: every test here dlopen()s
# genuine, compiler-generated ARM64 machine code, never hand-written bytes.
add_library(quark_codecipher_fixtures SHARED
    fixtures/tiny_func.c
    fixtures/branchy_func.c
    fixtures/dep_func.c
    fixtures/backward_call.c
)
set_target_properties(quark_codecipher_fixtures PROPERTIES
    OUTPUT_NAME "quark_codecipher_fixtures"
)

# A real, complex, unmodified consumer of quark_platform_macos -- links the
# actual MacHwidBackend::Collect() (sysctlbyname/IOKit/DiskArbitration/
# CoreFoundation, ~710 real ARM64 instructions) into its own dylib via a
# thin extern "C" wrapper that forces the linker to keep it.
add_library(quark_codecipher_hwid_fixture SHARED
    fixtures/hwid_wrapper.cpp
)
target_link_libraries(quark_codecipher_hwid_fixture PRIVATE quark_platform_macos)
set_target_properties(quark_codecipher_hwid_fixture PROPERTIES
    OUTPUT_NAME "quark_codecipher_hwid_fixture"
)

add_executable(quark_codecipher_test quark_codecipher_test.cpp)
target_link_libraries(quark_codecipher_test PRIVATE quark_codecipher)
target_compile_definitions(quark_codecipher_test PRIVATE
    FIXTURES_DYLIB_PATH="$<TARGET_FILE:quark_codecipher_fixtures>"
)
add_dependencies(quark_codecipher_test quark_codecipher_fixtures)
add_test(NAME quark_codecipher_test COMMAND quark_codecipher_test)

add_executable(quark_codecipher_pipeline_test quark_codecipher_pipeline_test.cpp)
target_link_libraries(quark_codecipher_pipeline_test PRIVATE quark_codecipher quark_core)
target_compile_definitions(quark_codecipher_pipeline_test PRIVATE
    FIXTURES_DYLIB_PATH="$<TARGET_FILE:quark_codecipher_fixtures>"
)
add_dependencies(quark_codecipher_pipeline_test quark_codecipher_fixtures)
add_test(NAME quark_codecipher_pipeline_test COMMAND quark_codecipher_pipeline_test)

# Regression test for the negative-offset SignExtend bug (see
# relocation.cpp) -- backward_call.c's helper_before/caller_after exercise a
# real negative-offset BL that every other fixture happened to avoid.
add_executable(quark_codecipher_relocation_test quark_codecipher_relocation_test.cpp)
target_link_libraries(quark_codecipher_relocation_test PRIVATE quark_codecipher)
target_compile_definitions(quark_codecipher_relocation_test PRIVATE
    FIXTURES_DYLIB_PATH="$<TARGET_FILE:quark_codecipher_fixtures>"
)
add_dependencies(quark_codecipher_relocation_test quark_codecipher_fixtures)
add_test(NAME quark_codecipher_relocation_test COMMAND quark_codecipher_relocation_test)

# The real, complex-program stress test: captures MacHwidBackend::Collect()
# itself (not a toy fixture) and proves it still produces byte-identical
# real hardware fingerprint data after being scrambled/reconstructed/
# relocated. macOS-only, real IOKit/DiskArbitration/CoreFoundation calls.
add_executable(quark_codecipher_hwid_test quark_codecipher_hwid_test.cpp)
target_link_libraries(quark_codecipher_hwid_test PRIVATE quark_codecipher quark_platform_macos)
target_compile_definitions(quark_codecipher_hwid_test PRIVATE
    HWID_FIXTURE_DYLIB_PATH="$<TARGET_FILE:quark_codecipher_hwid_fixture>"
)
add_dependencies(quark_codecipher_hwid_test quark_codecipher_hwid_fixture)
add_test(NAME quark_codecipher_hwid_test COMMAND quark_codecipher_hwid_test)
