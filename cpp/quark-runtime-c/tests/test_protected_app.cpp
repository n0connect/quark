// A minimal stand-in for a real protected native application, linking
// quark_runtime exactly like a real one would. Driven by
// quark_runtime_e2e_test.cpp over real pipes. Prints the quark_checkpoint()
// result to STDERR (not stdout) so it doesn't corrupt the heartbeat
// thread's stdout protocol, which the parent test reads separately.

#include <cstdio>

#include "quark_runtime.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

int main() {
    if (!quark_init()) {
        std::fprintf(stderr, "quark_init failed\n");
        return 1;
    }
    quark_heartbeat_start();

    int64_t token = quark_checkpoint(0x1001);
    std::fprintf(stderr, "CHECKPOINT_RESULT=%lld\n", static_cast<long long>(token));
    std::fflush(stderr);

    // Keep the process alive so the heartbeat thread can answer a challenge
    // sent by the parent test after this point.
    for (;;) {
#if defined(_WIN32)
        Sleep(60000);
#else
        pause();
#endif
    }
}
