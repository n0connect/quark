# Real, non-mocked tests for quark_core -- every assertion here exercises the
# actual mbedTLS-backed crypto, the actual Lamport chain, the actual
# state.bin codec against a real temp file on the real filesystem. Nothing in
# this binary is stubbed or faked (see CLAUDE.md engineering rule 1: no
# mocks, anywhere). This is exactly the point of the quark_core/quark_platform
# split -- these tests build and run on any OS, no Windows VM required,
# because the code under test never touches an OS-specific API in the first
# place.
add_executable(quark_core_tests core_smoke_test.cpp)
target_link_libraries(quark_core_tests PRIVATE quark_core)

enable_testing()
add_test(NAME quark_core_tests COMMAND quark_core_tests)

# Real, live-network test -- deliberately NOT registered with add_test() so
# ctest's default run never depends on network access. Run manually:
#   ./sandbox/build-host/cpp/common/tests/orchestrator_online_test
add_executable(orchestrator_online_test orchestrator_online_test.cpp)
target_link_libraries(orchestrator_online_test PRIVATE quark_core)

if(APPLE)
    # Real, non-mocked tests for quark_platform_macos -- this actually calls
    # sysctl/IOKit/DiskArbitration and reads/writes a real xattr on this
    # machine. No fake HWID, no stubbed IOKit -- CLAUDE.md engineering rule 1.
    add_executable(quark_platform_macos_tests platform_macos_test.cpp)
    target_link_libraries(quark_platform_macos_tests PRIVATE quark_platform_macos)
    add_test(NAME quark_platform_macos_tests COMMAND quark_platform_macos_tests)
endif()

if(UNIX AND NOT APPLE)
    # Real, non-mocked tests for quark_platform_linux -- reads the real
    # /proc/cpuinfo and /sys/class/dmi/id of whatever Linux kernel this runs
    # on (bare metal, VM, or container), and reads/writes a real "user."
    # xattr -- CLAUDE.md engineering rule 1.
    add_executable(quark_platform_linux_tests platform_linux_test.cpp)
    target_link_libraries(quark_platform_linux_tests PRIVATE quark_platform_linux)
    add_test(NAME quark_platform_linux_tests COMMAND quark_platform_linux_tests)
endif()
