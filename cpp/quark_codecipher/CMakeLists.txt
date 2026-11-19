# quark_codecipher: reversible AES-256-CTR instruction-level scramble +
# real-machine-code reconstruction. See README.md for the mechanism and its
# honest scope limits. macOS-only today (Materialize uses MAP_JIT) -- gated
# by the top-level CMakeLists' `if(APPLE)`.
add_library(quark_codecipher STATIC
    src/relocation.cpp
    src/region.cpp
    src/capture.cpp
    src/materialize.cpp
)

target_include_directories(quark_codecipher PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(quark_codecipher PUBLIC quark_core)

add_subdirectory(tests)
