#include "quark/error.hpp"

#include <cstdio>
#include <ctime>
#include <fstream>
#include <string>

namespace quark::error {

namespace {

constexpr const char* kCrashLogPath = "debug-crash.txt";

std::string Timestamp() {
    std::time_t now = std::time(nullptr);
    std::tm local{};
#if defined(_WIN32)
    localtime_s(&local, &now);
#else
    localtime_r(&now, &local);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &local);
    return std::string(buf);
}

}  // namespace

const char* Describe(Code code) {
    switch (code) {
        case Code::kOk:
            return "no error";

        // 1xxx -- shared HWID collection
        case Code::kHwidFieldUnreadable:
            return "one or more of the 11 hardware fingerprint fields could not be read (or the result was incomplete and was rejected)";

        // 2xxx -- HWID_Extractor.exe
        case Code::kExtractorOutputOpenFailed:
            return "could not open the output JSON file for writing";
        case Code::kExtractorJsonWriteFailed:
            return "writing the fingerprint JSON to disk failed mid-stream";

        // 3xxx -- Dev_Keygen.exe
        case Code::kKeygenInputReadFailed:
            return "could not read the customer's HWID export file";
        case Code::kKeygenInputInvalid:
            return "the HWID export file is not well-formed";
        case Code::kKeygenChainLengthInvalid:
            return "chain length must be a positive integer up to 1,000,000";
        case Code::kKeygenStateWriteFailed:
            return "could not seal and write the initial state.bin";
        case Code::kKeygenKeysWriteFailed:
            return "could not write the unlock_keys.txt file";
        case Code::kKeygenSelfTestFailed:
            return "self-test failed: the freshly minted license did not unlock with its own first key";
        case Code::kKeygenPastePostFailed:
            return "could not POST the online-witness blob to rentry.co (check network access and verify rentry.co is reachable)";

        // 4xxx -- DRM_Wrapper.exe
        case Code::kWrapperDebuggerDetected:
            return "a debugger was detected attached to this process";
        case Code::kWrapperHwidCollectionFailed:
            return "this machine's hardware fingerprint could not be fully collected";
        case Code::kWrapperStateOpenFailed:
            return "state.bin could not be opened and authenticated (missing, corrupt, tampered, or wrong machine -- indistinguishable by design)";
        case Code::kWrapperHwidDigestMismatch:
            return "state.bin's internal HWID digest disagreed with its own authenticated seal";
        case Code::kWrapperLicenseExhausted:
            return "this license has no remaining uses";
        case Code::kWrapperUnlockKeyInvalid:
            return "the supplied one-time unlock key is invalid for this license";
        case Code::kWrapperStatePersistFailed:
            return "could not persist the rolled license state before launch";
        case Code::kWrapperPipeSetupFailed:
            return "could not create or configure the handoff pipe";
        case Code::kWrapperProcessLaunchFailed:
            return "could not launch the protected application process";
        case Code::kWrapperHandoffWriteFailed:
            return "writing the handoff frame to the child process failed or was incomplete";
        case Code::kWrapperRegistryOpenFailed:
            return "the registry license witness exists but could not be opened and authenticated (tampered or wrong machine)";
        case Code::kWrapperRegistryWriteFailed:
            return "could not seal and commit the registry license witness";
        case Code::kWrapperWitnessMismatch:
            return "one or more license witnesses disagree on the chain position -- a backup/restore was used to rewind state.bin, or a witness was selectively tampered with";
        case Code::kWrapperClockRollbackDetected:
            return "the system clock has moved backwards relative to the highest time this machine has ever reported";
        case Code::kWrapperWitnessMissingAfterUse:
            return "license witnesses are absent but state.bin shows uses already spent -- the signature of deleting witnesses and restoring an older, already-used state.bin";
        case Code::kWrapperJarIntegrityFailed:
            return "quark.jar's SHA-256 digest does not match the one embedded in this build -- the jar has been swapped or modified";
        case Code::kWrapperAdsOpenFailed:
            return "the NTFS-ADS license witness exists but could not be authenticated (tampered, wrong machine, or corrupt)";
        case Code::kWrapperAdsWriteFailed:
            return "could not seal and commit the NTFS-ADS license witness";
        case Code::kWrapperOverlayOpenFailed:
            return "the PE-overlay license witness exists but could not be authenticated (tampered, wrong machine, or corrupt)";
        case Code::kWrapperOverlayWriteFailed:
            return "could not seal and commit the PE-overlay witness into DRM_Wrapper.exe";
        case Code::kWrapperOnlineFetchFailed:
            return "the online-witness paste could not be fetched from rentry.co (network failure or paste deleted -- revocation effective)";
        case Code::kWrapperOnlineDecryptFailed:
            return "the online-witness paste blob failed authentication (wrong machine, tampered paste, or mismatched SECRET)";
        case Code::kWrapperOnlineSigInvalid:
            return "the P-256 ECDSA signature inside the online-witness paste did not verify against the embedded public key";
        case Code::kWrapperLockFailed:
            return "could not acquire the per-license process lock (another instance may be mid-launch against the same license)";

        // 5xxx -- quark.jar (Java side; kept here too so a C++ reader can
        // make sense of a code copied out of a customer's debug-crash.txt
        // even if it was quark.jar, not DRM_Wrapper, that wrote that line)
        case Code::kJarFrameReadFailed:
            return "quark.jar: reading the handoff frame from stdin timed out or was incomplete";
        case Code::kJarFrameInvalid:
            return "quark.jar: the handoff frame had a bad magic value or unsupported version";
        case Code::kJarCoreEncReadFailed:
            return "quark.jar: could not read core.enc from disk";
        case Code::kJarCoreEncDecryptFailed:
            return "quark.jar: core.enc failed to authenticate/decrypt with the derived key";
        case Code::kJarClassLoadFailed:
            return "quark.jar: the decrypted bundle did not yield a loadable application core";
        case Code::kJarEntryPointFailed:
            return "quark.jar: the application's entry point could not be invoked";
    }
    return "unrecognized error code";
}

void Report(Code code, const char* component, const char* detail) {
    const auto numeric = static_cast<unsigned>(code);
    const char* description = Describe(code);

    // 1) Append one line to debug-crash.txt next to the executable. Opened
    //    fresh each time (not held open) -- crashes are by definition rare,
    //    and a held-open handle would itself be one more thing to leak.
    {
        std::ofstream log(kCrashLogPath, std::ios::app);
        if (log) {
            log << "[" << Timestamp() << "] "
                << "component=" << component << " "
                << "code=" << numeric << " (QUARK-ERR-" << numeric << ") "
                << description;
            if (detail && *detail) {
                log << " detail=" << detail;
            }
            log << "\n";
        }
        // A failed crash-log write is itself not a new failure worth
        // recursing over -- the terminal line below is the fallback.
    }

    // 2) Mirror to stderr for anyone watching a console.
    if (detail && *detail) {
        std::fprintf(stderr, "[QUARK-ERR-%u] %s: %s (%s)\n", numeric, component, description, detail);
    } else {
        std::fprintf(stderr, "[QUARK-ERR-%u] %s: %s\n", numeric, component, description);
    }
}

}  // namespace quark::error
