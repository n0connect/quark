#include <stdio.h>

int g_counter = 100;  // global/static data -- PC-relative (ADRP) access, EXTERNAL to the function

// Real, compiler-generated ARM64 function with two external PC-relative
// dependencies: a global variable (ADRP) and an external library call
// (printf, via BL to a dynamic stub). Tests that Capture()'s scan correctly
// finds and records these as relocations, and that Materialize() correctly
// patches them so the reconstructed function still mutates the real global
// and calls the real printf after being placed at a brand-new address.
__attribute__((noinline))
long dep_func(long a, long b) {
    g_counter += (int)(a + b);
    printf("dep_func called with a=%ld b=%ld\n", a, b);
    return g_counter;
}
