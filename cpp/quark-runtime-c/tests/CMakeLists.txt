add_executable(test_protected_app test_protected_app.cpp)
target_link_libraries(test_protected_app PRIVATE quark_runtime)

if(NOT WIN32)
    add_executable(quark_runtime_e2e_test quark_runtime_e2e_test.cpp)
    target_link_libraries(quark_runtime_e2e_test PRIVATE quark_core)

    add_test(
        NAME quark_runtime_e2e_test
        COMMAND quark_runtime_e2e_test $<TARGET_FILE:test_protected_app>
    )
endif()
