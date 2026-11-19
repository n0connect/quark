/*
 * Method 1 ("protect an already-written program"), C.
 *
 * Links quark_runtime (cpp/quark-runtime-c) -- the same "native protected
 * app" runtime Quark ships for C/C++ consumers. DRM_Wrapper launches this
 * binary exactly like it would a JVM: writes the QKH2 initial frame to its
 * stdin, then challenges it every `challenge_interval_ms`. quark_init()/
 * quark_heartbeat_start()/quark_checkpoint() implement the client side of
 * that protocol; this file only has to call them in the right order.
 *
 * quark_runtime.h is a plain C header (extern "C" throughout), so this file
 * is genuinely compiled with a C compiler (cc), not just C++ pretending to
 * be C -- proving the extern "C" ABI boundary really is language-neutral.
 */
#include <stdio.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "quark_runtime.h"

int main(void) {
    if (!quark_init()) {
        fprintf(stderr, "quark_init failed\n");
        return 1;
    }
    quark_heartbeat_start();

    long long token = (long long)quark_checkpoint(0x0001);
    fprintf(stderr, "CHECKPOINT_RESULT=%lld\n", token);
    fflush(stderr);

    /* Keep the process alive so the heartbeat thread can keep answering
     * challenges; DRM_Wrapper terminates us when the session ends. */
    for (;;) {
#if defined(_WIN32)
        Sleep(60000);
#else
        pause();
#endif
    }
    return 0;
}
