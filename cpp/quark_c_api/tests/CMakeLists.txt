# Real, non-mocked end-to-end test of the C ABI itself -- a plain C
# translation unit (not C++) linked against libquark_c, exercising it exactly
# as an external consumer would: mint a license for THIS machine's real,
# freshly-collected HWID, then unlock it twice in a row through the same
# entry points a Go/Python/Java binding would call. No quark_core internals
# are touched directly from this file.
add_executable(quark_c_api_test quark_c_api_test.c)
target_link_libraries(quark_c_api_test PRIVATE quark_c)

enable_testing()
add_test(NAME quark_c_api_test COMMAND quark_c_api_test)

# Real concurrency test for the C ABI's IProcessLock protection -- plain C,
# real pthreads, calling into libquark_c exactly as a Go/Python/Java binding
# would from multiple threads. POSIX-only (pthreads); Windows re-verification
# of LockFileProcessLock is a separate, tracked gap.
if(NOT WIN32)
    find_package(Threads REQUIRED)
    add_executable(quark_c_api_lock_test quark_c_api_lock_test.c)
    target_link_libraries(quark_c_api_lock_test PRIVATE quark_c Threads::Threads)
    add_test(NAME quark_c_api_lock_test COMMAND quark_c_api_lock_test)
endif()
