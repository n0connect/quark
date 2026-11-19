// Real, compiler-generated ARM64 function with an internal conditional
// branch (B.cond). Tests that internal PC-relative targets -- which stay
// correct automatically once the whole function moves as one contiguous
// block -- are correctly identified as needing NO relocation entry.
__attribute__((noinline))
long branchy_func(long a, long b) {
    long c;
    if (a > b) {
        c = a - b;
    } else {
        c = b - a;
    }
    return c + 100;
}
