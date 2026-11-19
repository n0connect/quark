# Console tool -- developer-side, run from a terminal.
#
# main.cpp includes "../drm_wrapper/secret.hpp" directly (relative to this
# file) -- deliberate: Dev_Keygen and DRM_Wrapper must be built against the
# exact same SECRET, and a relative include makes "they're the same file" a
# compile-time fact rather than a deployment convention someone can violate.
add_executable(Dev_Keygen main.cpp)
target_link_libraries(Dev_Keygen PRIVATE quark_common)
