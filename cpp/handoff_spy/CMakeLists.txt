# Test stub: impersonates jre\bin\javaw.exe, validates QKH2 protocol.
# Windows CNG (bcrypt.lib) for HMAC on Windows, a from-scratch hand-rolled
# SHA-256/HMAC-SHA256 on macOS/Linux (see main.cpp's header comment for why
# this deliberately does NOT depend on quark_common/mbedTLS on any platform).
add_executable(handoff_spy main.cpp)
if(WIN32)
    target_link_libraries(handoff_spy PRIVATE bcrypt)
endif()

add_subdirectory(tests)
