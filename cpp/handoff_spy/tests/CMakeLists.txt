# POSIX-only real end-to-end test (fork/pipe/exec) -- see the test file's
# header comment. Not built on Windows; that side is re-verified separately
# per docs/superpowers/specs/2026-07-05-cross-platform-porting-roadmap.md.
if(NOT WIN32)
    add_executable(handoff_spy_e2e_test handoff_spy_e2e_test.cpp)
    target_link_libraries(handoff_spy_e2e_test PRIVATE quark_common)

    add_test(
        NAME handoff_spy_e2e_test
        COMMAND handoff_spy_e2e_test $<TARGET_FILE:handoff_spy>
    )
endif()
