# Console subsystem: the wrapper itself prompts the user for their one-time
# unlock key via stdin/stdout (see main.cpp's PromptForKey). The JVM it
# launches is a *separate* process. Cross-platform: quark_common already
# resolves to the right quark_core + quark_platform_<os> combination on
# every OS (see cpp/common/CMakeLists.txt).
add_executable(DRM_Wrapper main.cpp)
target_link_libraries(DRM_Wrapper PRIVATE quark_common)

if(WIN32)
    # /MT is enforced globally via CMAKE_MSVC_RUNTIME_LIBRARY in the top-level
    # CMakeLists -- no per-target override needed, which is itself a guard
    # against someone accidentally shipping a /MD build of just this binary.
endif()

add_subdirectory(tests)
