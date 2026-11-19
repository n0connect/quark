// helper_before is compiled first; caller_after calls it with a BL whose
// encoded offset is NEGATIVE (a backward call). Regression fixture for a
// real bug found via a full HWID_Extractor capture: relocation.cpp's
// SignExtend widened an already-correct negative bit pattern from uint32_t
// to int64_t with zero-extension instead of sign-extension, corrupting
// every negative-offset B/BL/B.cond/ADRP target by +2^34. Every other
// fixture (tiny_func, branchy_func, dep_func) happened to only exercise
// forward offsets, so this went undetected until a real, large, complex
// function surfaced it.
__attribute__((noinline))
long helper_before(long x) {
    return x + 1;
}

__attribute__((noinline))
long caller_after(long x) {
    return helper_before(x) * 2;
}
