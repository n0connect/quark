// Real, compiler-generated ARM64 function -- no branches, no PC-relative
// addressing. Tests the simplest case: scramble/reconstruct/execute with
// zero relocations needed.
__attribute__((noinline))
long tiny_func(long a, long b) {
    long c = a + b;
    long d = c * 2;
    long e = d + 7;
    return e;
}
