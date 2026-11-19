#!/usr/bin/env bash
# Builds all 8 cross-language protection demos (examples/{go,c,cpp,java}/method{1,2}_*)
# against an already-built quark_core/quark_c_api/quark-runtime-c tree.
#
# Written with cross-platform structure (OS detection, no hardcoded macOS-only
# assumption beyond what this pass could actually verify) even though it is
# only exercised on macOS today -- see README.md's testing-methodology section
# and docs/PLAN.md for the exact, honest verification scope. Linux should work
# unchanged (same clang/gcc + cgo + gradle toolchain shape); Windows needs a
# separate .bat/.ps1 equivalent (different compiler invocation, .exe suffix,
# .lib linkage) that is intentionally not attempted here without a Windows
# machine to verify it on, per CLAUDE.md rule 1.
#
# Per CLAUDE.md rule 1, all build output lands under sandbox/ -- never here in
# examples/ (source only) and never in a system temp directory.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${QUARK_BUILD_DIR:-$REPO_ROOT/sandbox/build-macos}"
OUT_DIR="${QUARK_EXAMPLES_OUT:-$REPO_ROOT/sandbox/examples_build}"

UNAME_S="$(uname -s)"
case "$UNAME_S" in
    Darwin) OS=macos; SHLIB_EXT=dylib ;;
    Linux)  OS=linux; SHLIB_EXT=so ;;
    *)      echo "build_all.sh: unsupported OS '$UNAME_S' -- Windows needs its own script (see header comment)" >&2; exit 1 ;;
esac

echo "== Quark cross-language example build ($OS) =="
echo "BUILD_DIR = $BUILD_DIR"
echo "OUT_DIR   = $OUT_DIR"

if [[ ! -d "$BUILD_DIR" ]]; then
    echo "error: $BUILD_DIR does not exist -- build the C++ tree first (cmake -S . -B $BUILD_DIR && cmake --build $BUILD_DIR)" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

QUARK_C_API_INCLUDE="$REPO_ROOT/cpp/quark_c_api/include"
QUARK_RUNTIME_INCLUDE="$REPO_ROOT/cpp/quark-runtime-c"
QUARK_C_API_LIBDIR="$BUILD_DIR/cpp/quark_c_api"
QUARK_C_API_LIB="$QUARK_C_API_LIBDIR/libquark_c.$SHLIB_EXT"

# Exact static-link set/order for anything linking quark_runtime directly,
# mirrored from this build tree's own CMake-generated link.txt for
# test_protected_app (see cpp/quark-runtime-c/tests/CMakeLists.txt) --
# mbedtls's internal sub-libraries are order-sensitive for a static link.
QUARK_RUNTIME_STATIC_LIBS=(
    "$BUILD_DIR/cpp/quark-runtime-c/libquark_runtime.a"
    "$BUILD_DIR/cpp/common/libquark_core.a"
    "$BUILD_DIR/_deps/mbedtls-build/library/libmbedtls.a"
    "$BUILD_DIR/_deps/mbedtls-build/library/libmbedx509.a"
    "$BUILD_DIR/_deps/mbedtls-build/library/libmbedcrypto.a"
    "$BUILD_DIR/_deps/mbedtls-build/3rdparty/everest/libeverest.a"
    "$BUILD_DIR/_deps/mbedtls-build/3rdparty/p256-m/libp256m.a"
)

for f in "$QUARK_C_API_LIB" "${QUARK_RUNTIME_STATIC_LIBS[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "error: expected build artifact missing: $f" >&2
        exit 1
    fi
done

echo
echo "-- quark_seal_tool (dev-side helper, links libquark_c) --"
c++ -std=c++17 -I "$QUARK_C_API_INCLUDE" "$REPO_ROOT/examples/tools/quark_seal_tool.cpp" \
    -L "$QUARK_C_API_LIBDIR" -lquark_c \
    -Wl,-rpath,"$QUARK_C_API_LIBDIR" \
    -o "$OUT_DIR/quark_seal_tool"

echo "-- C, method 1 (links quark_runtime) --"
cc -std=c11 -I "$QUARK_RUNTIME_INCLUDE" -c "$REPO_ROOT/examples/c/method1_wrapper/main.c" \
    -o "$OUT_DIR/c_method1_wrapper.o"
c++ "$OUT_DIR/c_method1_wrapper.o" "${QUARK_RUNTIME_STATIC_LIBS[@]}" \
    -o "$OUT_DIR/c_method1_wrapper"
rm -f "$OUT_DIR/c_method1_wrapper.o"

echo "-- C, method 2 (links libquark_c) --"
cc -std=c11 -I "$QUARK_C_API_INCLUDE" "$REPO_ROOT/examples/c/method2_embedded/main.c" \
    -L "$QUARK_C_API_LIBDIR" -lquark_c \
    -Wl,-rpath,"$QUARK_C_API_LIBDIR" \
    -o "$OUT_DIR/c_method2_embedded"

echo "-- C++, method 1 (links quark_runtime) --"
c++ -std=c++17 -I "$QUARK_RUNTIME_INCLUDE" "$REPO_ROOT/examples/cpp/method1_wrapper/main.cpp" \
    "${QUARK_RUNTIME_STATIC_LIBS[@]}" \
    -o "$OUT_DIR/cpp_method1_wrapper"

echo "-- C++, method 2 (links libquark_c) --"
c++ -std=c++17 -I "$QUARK_C_API_INCLUDE" "$REPO_ROOT/examples/cpp/method2_embedded/main.cpp" \
    -L "$QUARK_C_API_LIBDIR" -lquark_c \
    -Wl,-rpath,"$QUARK_C_API_LIBDIR" \
    -o "$OUT_DIR/cpp_method2_embedded"

echo "-- Go, method 1 (pure Go, no cgo) --"
( cd "$REPO_ROOT/examples/go/method1_wrapper" && \
  CGO_ENABLED=0 go build -o "$OUT_DIR/go_method1_wrapper" . )

echo "-- Go, method 2 (cgo -> libquark_c) --"
( cd "$REPO_ROOT/examples/go/method2_embedded" && \
  CGO_ENABLED=1 CGO_CFLAGS="-I$QUARK_C_API_INCLUDE" CGO_LDFLAGS="-L$QUARK_C_API_LIBDIR -Wl,-rpath,$QUARK_C_API_LIBDIR" \
  go build -o "$OUT_DIR/go_method2_embedded" . )

echo "-- Java, method 2 (FFM/Panama -> libquark_c) --"
javac -d "$OUT_DIR" "$REPO_ROOT/examples/java/method2_embedded/Method2Embedded.java"
cp "$QUARK_C_API_LIB" "$OUT_DIR/"

echo
echo "All example binaries built into $OUT_DIR"
echo "(Java method 1 reuses java/test-app + java/drm-core -- already built via gradle, see examples/README.md)"
