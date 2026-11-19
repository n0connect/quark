# quark-runtime-c: native C/C++ runtime for protected applications (QKH2
# pipe protocol). Cross-platform -- links quark_core for crypto instead of
# CNG/bcrypt, so it builds and runs identically on Windows/macOS/Linux.
add_library(quark_runtime STATIC quark_runtime.cpp)

target_include_directories(quark_runtime PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(quark_runtime PUBLIC quark_core)

add_subdirectory(tests)

install(TARGETS quark_runtime ARCHIVE DESTINATION lib)
install(FILES quark_runtime.h DESTINATION include)
