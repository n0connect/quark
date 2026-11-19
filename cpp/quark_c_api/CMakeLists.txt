# quark_c: the public C ABI over quark_core -- a plain extern "C" surface any
# language with an FFI (Go/cgo, Python/ctypes, Java/JNI, Rust/bindgen, C/C++
# directly) can link against in-process. See include/quark_c_api.h for the
# full contract. Builds on every OS quark_core builds on; the HWID/witness-
# store backends it wires up are whichever quark_platform_<os> target that OS
# already provides (Windows/macOS/Linux), so this library's actual
# capabilities scale with the platform layer's, without re-implementing any
# of it.
add_library(quark_c SHARED
    src/quark_c_api.cpp
)

target_include_directories(quark_c PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(quark_c PRIVATE quark_core)

if(WIN32)
    target_link_libraries(quark_c PRIVATE quark_platform_win)
elseif(APPLE)
    target_link_libraries(quark_c PRIVATE quark_platform_macos)
elseif(UNIX)
    target_link_libraries(quark_c PRIVATE quark_platform_linux)
endif()

add_subdirectory(tests)
