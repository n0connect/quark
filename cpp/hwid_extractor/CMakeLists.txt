# Console tool -- talks to the user via stdio, so no WIN32_EXECUTABLE.
add_executable(HWID_Extractor main.cpp)
target_link_libraries(HWID_Extractor PRIVATE quark_common)
