// Method 1 ("protect an already-written program"), C++.
//
// Links quark_runtime (cpp/quark-runtime-c) exactly like a real protected
// native application would. DRM_Wrapper does not distinguish this from a
// JVM: it writes the QKH2 initial frame to stdin and challenges every
// `challenge_interval_ms`, and this binary answers using quark_runtime's
// heartbeat thread. See examples/c/method1_wrapper/main.c for the same
// pattern compiled with a plain C compiler instead of a C++ one.
#include <cstdio>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "quark_runtime.h"

int main() {
    if (!quark_init()) {
        std::fprintf(stderr, "quark_init failed\n");
        return 1;
    }
    quark_heartbeat_start();

    int64_t token = quark_checkpoint(0x0001);
    std::fprintf(stderr, "CHECKPOINT_RESULT=%lld\n", static_cast<long long>(token));
    std::fflush(stderr);

    for (;;) {
#if defined(_WIN32)
        Sleep(60000);
#else
        pause();
#endif
    }
}
