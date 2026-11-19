# Tiny, standalone, normally-compiled executable -- zero Quark awareness
# anywhere in its source -- sealed and loaded WHOLE (no symbol extraction,
# no linker re-invocation) to prove the mechanism in isolation before
# scaling to a real, complex program below.
add_executable(quark_linkload_simple_fixture fixtures/simple_program.c)

add_executable(quark_linkload_simple_test quark_linkload_simple_test.cpp)
target_link_libraries(quark_linkload_simple_test PRIVATE quark_linkload)
target_compile_definitions(quark_linkload_simple_test PRIVATE
    SIMPLE_FIXTURE_EXE_PATH="$<TARGET_FILE:quark_linkload_simple_fixture>"
)
add_dependencies(quark_linkload_simple_test quark_linkload_simple_fixture)
add_test(NAME quark_linkload_simple_test COMMAND quark_linkload_simple_test)

# The real, complex-program proof: seals HWID_Extractor.exe -- the ENTIRE
# compiled binary, not a curated symbol -- and proves the fully protected
# copy's output is byte-identical to a real, unprotected fork+exec run.
add_executable(quark_linkload_hwid_test quark_linkload_hwid_test.cpp)
target_link_libraries(quark_linkload_hwid_test PRIVATE quark_linkload)
target_compile_definitions(quark_linkload_hwid_test PRIVATE
    HWID_EXTRACTOR_PATH="$<TARGET_FILE:HWID_Extractor>"
)
add_dependencies(quark_linkload_hwid_test HWID_Extractor)
add_test(NAME quark_linkload_hwid_test COMMAND quark_linkload_hwid_test)
