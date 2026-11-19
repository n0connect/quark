# Real, non-mocked adversarial/robustness tests against the fully assembled
# DRM_Wrapper binary -- see drm_wrapper_robustness_test.cpp's header comment.
# macOS-only for now: the test mints licenses via the real MacHwidBackend and
# crafts witness artifacts via quark::platform::macos::XattrWitnessStore
# directly, mirroring what DRM_Wrapper itself does on this OS. A Linux
# equivalent (LinuxHwidBackend + linux_::XattrWitnessStore) is a tracked
# follow-up -- no Linux machine was available when this was written.
if(APPLE)
    add_executable(drm_wrapper_robustness_test drm_wrapper_robustness_test.cpp)
    target_link_libraries(drm_wrapper_robustness_test PRIVATE quark_common)
    target_include_directories(drm_wrapper_robustness_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)

    add_test(
        NAME drm_wrapper_robustness_test
        COMMAND drm_wrapper_robustness_test $<TARGET_FILE:DRM_Wrapper> $<TARGET_FILE:handoff_spy>
    )
    # DRM_Wrapper must exist before ctest can pass its path in -- CMake's
    # add_test COMMAND generator-expression doesn't imply a build dependency.
    add_dependencies(drm_wrapper_robustness_test DRM_Wrapper handoff_spy)
endif()
