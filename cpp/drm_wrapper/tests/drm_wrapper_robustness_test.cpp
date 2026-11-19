// Real, non-mocked adversarial/robustness test suite for the FULLY ASSEMBLED
// DRM_Wrapper binary. CLAUDE.md rule 1: no mocks -- every scenario mints a
// real license against this machine's real HWID (via the real
// MacHwidBackend, the same one DRM_Wrapper itself uses), writes real
// AES-256-GCM-sealed state.bin/witness artifacts to a real scratch
// directory under sandbox/, then spawns the real compiled DRM_Wrapper
// executable via fork/exec/pipe and inspects its real exit code and real
// stderr output -- exactly the interface an actual attacker or a confused
// customer would produce, never a stub standing in for any of it.
//
// Each scenario gets its own scratch subdirectory (removed at the end) so
// tamper/mint state from one scenario can never leak into another.
//
// POSIX-only (fork/pipe/execv/xattr syscalls), mirroring
// handoff_spy_e2e_test.cpp's convention. Windows-side robustness testing is
// a separate, tracked gap -- no Windows machine available in this pass.
//
// One scenario (the happy-path baseline) genuinely takes ~30 real seconds:
// quark::platform::posix::RunChallengeLoop only sends its first "CHAL" frame
// after confirming the child did NOT exit within one full 30s heartbeat
// interval (see process_handoff.cpp) -- this is deliberate heartbeat design,
// not something this test works around. Every other scenario here is a
// failure path that fail-deadlies before DRM_Wrapper ever launches a child
// process, so it returns in milliseconds.

#include <fcntl.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/error.hpp"
#include "quark/lamport.hpp"
#include "quark/platform/file_witness_store.hpp"
#include "quark/platform/hwid_backend.hpp"
#include "quark/platform/macos/hwid_backend_macos.hpp"
#include "quark/platform/macos/xattr_witness_store.hpp"
#include "quark/state.hpp"
#include "quark/token.hpp"
#include "quark/witness.hpp"

#include "secret.hpp"

namespace fs = std::filesystem;

namespace {

int g_failures = 0;

void Check(bool condition, const std::string& what) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
        ++g_failures;
    } else {
        std::printf("ok: %s\n", what.c_str());
    }
}

std::string ErrTag(quark::error::Code code) {
    return "[QUARK-ERR-" + std::to_string(static_cast<unsigned>(code)) + "]";
}

// --- real subprocess harness -------------------------------------------------

struct RunResult {
    int exit_code = -1;
    std::string stderr_output;
};

struct PendingRun {
    pid_t pid = -1;
    int err_read_fd = -1;
};

// Forks and execs `path` with cwd `workdir`, writes `stdin_data` to its
// stdin then closes it, and returns immediately without waiting -- lets a
// caller start several instances back-to-back so they genuinely race, not
// just "run one after another". Real fork/exec/pipe/chdir -- the process
// boundary is never faked.
PendingRun StartWrapper(const std::string& path, const std::string& workdir,
                        const std::string& stdin_data) {
    int in_pipe[2];
    int err_pipe[2];
    if (pipe(in_pipe) != 0 || pipe(err_pipe) != 0) {
        return {-1, -1};
    }

    pid_t pid = fork();
    if (pid < 0) return {-1, -1};

    if (pid == 0) {
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(in_pipe[0]);
        close(in_pipe[1]);
        close(err_pipe[0]);
        close(err_pipe[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            close(devnull);
        }
        if (chdir(workdir.c_str()) != 0) _exit(126);
        execl(path.c_str(), path.c_str(), static_cast<char*>(nullptr));
        _exit(127);  // execl only returns on failure
    }

    close(in_pipe[0]);
    close(err_pipe[1]);

    if (!stdin_data.empty()) {
        ssize_t written = write(in_pipe[1], stdin_data.data(), stdin_data.size());
        (void)written;
    }
    close(in_pipe[1]);

    PendingRun p;
    p.pid = pid;
    p.err_read_fd = err_pipe[0];
    return p;
}

// Drains stderr to EOF and reaps the child -- the second half of
// StartWrapper, split out so a caller can Start() several processes before
// Finish()-ing any of them.
RunResult FinishWrapper(PendingRun& p) {
    std::string captured;
    char buf[4096];
    ssize_t n;
    while ((n = read(p.err_read_fd, buf, sizeof(buf))) > 0) {
        captured.append(buf, static_cast<size_t>(n));
    }
    close(p.err_read_fd);

    int status = 0;
    waitpid(p.pid, &status, 0);
    RunResult r;
    r.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    r.stderr_output = captured;
    return r;
}

RunResult RunWrapper(const std::string& path, const std::string& workdir,
                      const std::string& stdin_data) {
    PendingRun p = StartWrapper(path, workdir, stdin_data);
    if (p.pid < 0) return {-1, "fork()/pipe() failed"};
    return FinishWrapper(p);
}

// --- real license minting ----------------------------------------------------

std::vector<uint8_t> RealHwidCanonical() {
    quark::platform::macos::MacHwidBackend backend;
    auto fp = backend.Collect();
    if (!fp) {
        std::fprintf(stderr, "FATAL: could not collect this machine's real HWID\n");
        std::exit(2);
    }
    return quark::platform::CanonicalBytes(*fp);
}

struct Scenario {
    std::string dir;
    std::vector<uint8_t> hwid_canonical;
    std::vector<quark::crypto::Sha256Digest> chain;  // chain[0..n], chain[n] is the anchor
    uint32_t chain_length = 0;
    std::string jar_sha256_hex;
};

std::string Sha256Hex(const quark::crypto::Sha256Digest& d) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (uint8_t b : d) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

// Sets up a fresh scratch directory with a real quark.jar, a real
// drm_wrapper.conf pointing jvm_path at the real handoff_spy binary, a
// touched xattr-host file, and a real Dev_Keygen-equivalent minted license
// (state_key/state.bin) -- everything a real Dev_Keygen + real deployment
// would produce, just done in-process instead of shelling out to the
// already-tested Dev_Keygen binary.
Scenario SetupScenario(const std::string& base_dir, const std::string& name,
                        uint32_t chain_length, const std::vector<uint8_t>& hwid_canonical,
                        const std::string& handoff_spy_path) {
    Scenario s;
    s.dir = base_dir + "/" + name;
    fs::remove_all(s.dir);
    fs::create_directories(s.dir);
    s.hwid_canonical = hwid_canonical;
    s.chain_length = chain_length;

    auto seed = quark::crypto::RandomBytes(32);
    s.chain = quark::lamport::BuildChain(seed, chain_length);

    quark::crypto::AesKey state_key =
        quark::token::DeriveStateKey(quark::drm_wrapper::kBuildSecret, hwid_canonical);

    quark::state::LicenseState license;
    license.anchor = s.chain[chain_length];
    license.remaining_links = chain_length;
    license.hwid_digest = quark::crypto::Sha256(hwid_canonical);
    license.original_chain_length = chain_length;

    bool saved = quark::state::Save(s.dir + "/state.bin", state_key, hwid_canonical, license);
    if (!saved) {
        std::fprintf(stderr, "FATAL: state::Save failed while setting up scenario '%s'\n", name.c_str());
        std::exit(2);
    }

    const std::string jar_contents = "not a real jar, just needs a stable hash -- scenario " + name;
    {
        std::ofstream jar(s.dir + "/quark.jar", std::ios::binary);
        jar << jar_contents;
    }
    s.jar_sha256_hex = Sha256Hex(quark::crypto::Sha256(
        std::vector<uint8_t>(jar_contents.begin(), jar_contents.end())));

    {
        std::ofstream host(s.dir + "/quark_witness_host.bin", std::ios::binary);
        host << "witness host file\n";
    }

    {
        std::ofstream conf(s.dir + "/drm_wrapper.conf");
        conf << "state_path = state.bin\n"
             << "quark_jar_path = quark.jar\n"
             << "quark_jar_sha256_hex = " << s.jar_sha256_hex << "\n"
             << "jvm_path = " << fs::absolute(handoff_spy_path).string() << "\n"
             << "jvm_args =\n"
             << "challenge_interval_ms = 200\n"
             << "challenge_timeout_ms = 2000\n"
             << "witness_xattr_host_path = quark_witness_host.bin\n"
             << "witness_xattr1_attr = com.quark.robustness_test.witness1\n"
             << "witness_xattr2_attr = com.quark.robustness_test.witness2\n"
             << "witness_file_path = quark_witness_file.bin\n";
    }

    return s;
}

std::string KeyAt(const Scenario& s, uint32_t index_from_end) {
    // index_from_end == 1 -> the first redeemable key (chain[chain_length-1]).
    return quark::lamport::FormatKey(s.chain[s.chain_length - index_from_end]);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s <path-to-DRM_Wrapper> <path-to-handoff_spy>\n", argv[0]);
        return 2;
    }
    const std::string wrapper_path = argv[1];
    const std::string handoff_spy_path = argv[2];

    const std::string base_dir = "drm_wrapper_robustness_scratch";
    fs::remove_all(base_dir);
    fs::create_directories(base_dir);

    std::vector<uint8_t> hwid_canonical = RealHwidCanonical();

    // --- Scenario 1: happy path (real handoff_spy, real full challenge loop) ---
    {
        Scenario s = SetupScenario(base_dir, "01_happy_path", 2, hwid_canonical, handoff_spy_path);
        RunResult r = RunWrapper(wrapper_path, s.dir, KeyAt(s, 1) + "\n");
        Check(r.exit_code == 0, "happy path: valid first key succeeds end to end (real handoff_spy handshake)");
        Check(r.stderr_output.find("PASS: 1 challenge cycles completed") != std::string::npos,
              "happy path: real challenge-response cycle actually completed");
    }

    // --- Scenario 2: tampered state.bin -----------------------------------------
    {
        Scenario s = SetupScenario(base_dir, "02_tampered_state", 2, hwid_canonical, handoff_spy_path);
        {
            std::fstream f(s.dir + "/state.bin", std::ios::binary | std::ios::in | std::ios::out);
            f.seekp(40);  // inside the AES-GCM ciphertext region, past magic+version+iv+tag
            char byte = 0;
            f.read(&byte, 1);
            f.seekp(40);
            byte = static_cast<char>(byte ^ 0xFF);
            f.write(&byte, 1);
        }
        RunResult r = RunWrapper(wrapper_path, s.dir, KeyAt(s, 1) + "\n");
        Check(r.exit_code != 0, "tampered state.bin: DRM_Wrapper refuses to launch");
        Check(r.stderr_output.find(ErrTag(quark::error::Code::kWrapperStateOpenFailed)) != std::string::npos,
              "tampered state.bin: reports kWrapperStateOpenFailed");
    }

    // --- Scenario 3: license minted for a different machine ---------------------
    {
        quark::platform::Fingerprint fake_fp;
        fake_fp.fields.push_back({"test_field", "definitely-not-this-real-machine"});
        std::vector<uint8_t> fake_hwid = quark::platform::CanonicalBytes(fake_fp);

        Scenario s = SetupScenario(base_dir, "03_wrong_machine", 2, fake_hwid, handoff_spy_path);
        RunResult r = RunWrapper(wrapper_path, s.dir, KeyAt(s, 1) + "\n");
        Check(r.exit_code != 0, "wrong-machine license: DRM_Wrapper refuses to launch");
        Check(r.stderr_output.find(ErrTag(quark::error::Code::kWrapperStateOpenFailed)) != std::string::npos,
              "wrong-machine license: reports the SAME code as tampering (kWrapperStateOpenFailed) -- "
              "indistinguishable by design, per CLAUDE.md rule 2");
    }

    // --- Scenario 4: selective witness absence (one of three missing) -----------
    {
        Scenario s = SetupScenario(base_dir, "04_selective_witness_absent", 2, hwid_canonical, handoff_spy_path);
        RunResult baseline = RunWrapper(wrapper_path, s.dir, KeyAt(s, 1) + "\n");
        Check(baseline.exit_code == 0, "selective witness absence setup: baseline run mints all three witnesses");

        // Remove only the file-backed witness (w2) -- the other two (xattrs) remain.
        fs::remove(s.dir + "/quark_witness_file.bin");

        RunResult r = RunWrapper(wrapper_path, s.dir, KeyAt(s, 2) + "\n");
        Check(r.exit_code != 0, "selective witness absence: DRM_Wrapper refuses to launch");
        Check(r.stderr_output.find(ErrTag(quark::error::Code::kWrapperWitnessMismatch)) != std::string::npos,
              "selective witness absence: reports kWrapperWitnessMismatch");
    }

    // --- Scenario 5: all witnesses missing, but state.bin shows uses spent ------
    {
        Scenario s = SetupScenario(base_dir, "05_all_witness_missing_after_use", 2, hwid_canonical, handoff_spy_path);
        RunResult baseline = RunWrapper(wrapper_path, s.dir, KeyAt(s, 1) + "\n");
        Check(baseline.exit_code == 0, "all-witness-missing setup: baseline run mints all three witnesses and rolls state.bin");

        fs::remove(s.dir + "/quark_witness_file.bin");
        Check(removexattr((s.dir + "/quark_witness_host.bin").c_str(),
                           "com.quark.robustness_test.witness1", 0) == 0,
              "all-witness-missing setup: removed xattr witness 1");
        Check(removexattr((s.dir + "/quark_witness_host.bin").c_str(),
                           "com.quark.robustness_test.witness2", 0) == 0,
              "all-witness-missing setup: removed xattr witness 2");

        RunResult r = RunWrapper(wrapper_path, s.dir, KeyAt(s, 2) + "\n");
        Check(r.exit_code != 0, "all witnesses missing after use: DRM_Wrapper refuses to launch");
        Check(r.stderr_output.find(ErrTag(quark::error::Code::kWrapperWitnessMissingAfterUse)) != std::string::npos,
              "all witnesses missing after use: reports kWrapperWitnessMissingAfterUse (delete-and-restore signature)");
    }

    // --- Scenario 6: a present witness fails to authenticate (corrupted bytes) --
    {
        Scenario s = SetupScenario(base_dir, "06_witness_value_tamper", 2, hwid_canonical, handoff_spy_path);
        RunResult baseline = RunWrapper(wrapper_path, s.dir, KeyAt(s, 1) + "\n");
        Check(baseline.exit_code == 0, "witness value tamper setup: baseline run mints all three witnesses");

        {
            std::fstream f(s.dir + "/quark_witness_file.bin", std::ios::binary | std::ios::in | std::ios::out);
            f.seekp(40);
            char byte = 0;
            f.read(&byte, 1);
            f.seekp(40);
            byte = static_cast<char>(byte ^ 0xFF);
            f.write(&byte, 1);
        }

        RunResult r = RunWrapper(wrapper_path, s.dir, KeyAt(s, 2) + "\n");
        Check(r.exit_code != 0, "witness value tamper: DRM_Wrapper refuses to launch");
        Check(r.stderr_output.find(ErrTag(quark::error::Code::kWrapperOverlayOpenFailed)) != std::string::npos,
              "witness value tamper: the corrupted file-backed witness (slot 2) reports kWrapperOverlayOpenFailed");
    }

    // --- Scenario 7: clock rollback via a forged future high-water mark ---------
    {
        Scenario s = SetupScenario(base_dir, "07_clock_rollback", 2, hwid_canonical, handoff_spy_path);
        RunResult baseline = RunWrapper(wrapper_path, s.dir, KeyAt(s, 1) + "\n");
        Check(baseline.exit_code == 0, "clock rollback setup: baseline run mints all three witnesses and rolls state.bin once");

        quark::crypto::AesKey state_key =
            quark::token::DeriveStateKey(quark::drm_wrapper::kBuildSecret, hwid_canonical);
        auto rolled = quark::state::Load(s.dir + "/state.bin", state_key, hwid_canonical);
        Check(rolled.has_value(), "clock rollback setup: can read back the rolled state.bin to build a matching witness record");

        if (rolled) {
            quark::witness::Record forged{};
            forged.anchor = rolled->anchor;
            forged.remaining_links = rolled->remaining_links;
            forged.hwid_digest = rolled->hwid_digest;
            forged.high_water_unix_time =
                static_cast<uint64_t>(std::time(nullptr)) + 1'000'000;  // ~11.5 days in the future

            quark::crypto::AesKey k0 = quark::token::DeriveRegistryKey(quark::drm_wrapper::kBuildSecret, hwid_canonical);
            quark::crypto::AesKey k1 = quark::token::DeriveAdsKey(quark::drm_wrapper::kBuildSecret, hwid_canonical);
            quark::crypto::AesKey k2 = quark::token::DeriveOverlayKey(quark::drm_wrapper::kBuildSecret, hwid_canonical);

            quark::platform::macos::XattrWitnessStore w0(
                s.dir + "/quark_witness_host.bin", "com.quark.robustness_test.witness1", {'Q', 'W', 'X', '1'}, "xattr1");
            quark::platform::macos::XattrWitnessStore w1(
                s.dir + "/quark_witness_host.bin", "com.quark.robustness_test.witness2", {'Q', 'W', 'X', '2'}, "xattr2");
            quark::platform::FileWitnessStore w2(s.dir + "/quark_witness_file.bin", {'Q', 'W', 'F', '0'}, "file");

            Check(w0.Save(k0, hwid_canonical, forged), "clock rollback setup: forged high-water mark saved to witness 0");
            Check(w1.Save(k1, hwid_canonical, forged), "clock rollback setup: forged high-water mark saved to witness 1");
            Check(w2.Save(k2, hwid_canonical, forged), "clock rollback setup: forged high-water mark saved to witness 2");
        }

        RunResult r = RunWrapper(wrapper_path, s.dir, KeyAt(s, 2) + "\n");
        Check(r.exit_code != 0, "clock rollback: DRM_Wrapper refuses to launch against a future high-water mark");
        Check(r.stderr_output.find(ErrTag(quark::error::Code::kWrapperClockRollbackDetected)) != std::string::npos,
              "clock rollback: reports kWrapperClockRollbackDetected");
    }

    // --- Scenario 8: chain exhaustion --------------------------------------------
    {
        Scenario s = SetupScenario(base_dir, "08_chain_exhaustion", 1, hwid_canonical, handoff_spy_path);
        RunResult first = RunWrapper(wrapper_path, s.dir, KeyAt(s, 1) + "\n");
        Check(first.exit_code == 0, "chain exhaustion setup: the license's only key succeeds once");

        RunResult r = RunWrapper(wrapper_path, s.dir, KeyAt(s, 1) + "\n");
        Check(r.exit_code != 0, "chain exhaustion: a second attempt on a 1-link license is refused");
        Check(r.stderr_output.find(ErrTag(quark::error::Code::kWrapperLicenseExhausted)) != std::string::npos,
              "chain exhaustion: reports kWrapperLicenseExhausted");
    }

    // --- Scenario 9: malformed (non-hex) unlock key ------------------------------
    {
        Scenario s = SetupScenario(base_dir, "09_malformed_key", 2, hwid_canonical, handoff_spy_path);
        RunResult r = RunWrapper(wrapper_path, s.dir, "not-a-valid-hex-key-at-all\n");
        Check(r.exit_code != 0, "malformed key: DRM_Wrapper refuses to launch, does not crash");
        Check(r.stderr_output.find(ErrTag(quark::error::Code::kWrapperUnlockKeyInvalid)) != std::string::npos,
              "malformed key: reports kWrapperUnlockKeyInvalid");
    }

    // --- Scenario 10: well-formed but never-issued key ---------------------------
    {
        Scenario s = SetupScenario(base_dir, "10_wrong_key", 2, hwid_canonical, handoff_spy_path);
        auto random_digest_bytes = quark::crypto::RandomBytes(32);
        quark::crypto::Sha256Digest random_digest{};
        std::copy(random_digest_bytes.begin(), random_digest_bytes.end(), random_digest.begin());
        RunResult r = RunWrapper(wrapper_path, s.dir, quark::lamport::FormatKey(random_digest) + "\n");
        Check(r.exit_code != 0, "never-issued key: DRM_Wrapper refuses to launch");
        Check(r.stderr_output.find(ErrTag(quark::error::Code::kWrapperUnlockKeyInvalid)) != std::string::npos,
              "never-issued key: reports kWrapperUnlockKeyInvalid");
    }

    // --- Scenario 11: jar hash mismatch, and state must be untouched ------------
    {
        Scenario s = SetupScenario(base_dir, "11_jar_hash_mismatch", 2, hwid_canonical, handoff_spy_path);
        {
            // Overwrite the conf's hash with something that doesn't match quark.jar's real bytes.
            std::ofstream conf(s.dir + "/drm_wrapper.conf");
            conf << "state_path = state.bin\n"
                 << "quark_jar_path = quark.jar\n"
                 << "quark_jar_sha256_hex = " << std::string(64, '0') << "\n"
                 << "jvm_path = " << fs::absolute(handoff_spy_path).string() << "\n"
                 << "jvm_args =\n"
                 << "challenge_interval_ms = 200\n"
                 << "challenge_timeout_ms = 2000\n"
                 << "witness_xattr_host_path = quark_witness_host.bin\n"
                 << "witness_xattr1_attr = com.quark.robustness_test.witness1\n"
                 << "witness_xattr2_attr = com.quark.robustness_test.witness2\n"
                 << "witness_file_path = quark_witness_file.bin\n";
        }

        RunResult r = RunWrapper(wrapper_path, s.dir, KeyAt(s, 1) + "\n");
        Check(r.exit_code != 0, "jar hash mismatch: DRM_Wrapper refuses to launch");
        Check(r.stderr_output.find(ErrTag(quark::error::Code::kWrapperJarIntegrityFailed)) != std::string::npos,
              "jar hash mismatch: reports kWrapperJarIntegrityFailed");

        quark::crypto::AesKey state_key =
            quark::token::DeriveStateKey(quark::drm_wrapper::kBuildSecret, hwid_canonical);
        auto still = quark::state::Load(s.dir + "/state.bin", state_key, hwid_canonical);
        Check(still.has_value() && still->remaining_links == s.chain_length,
              "jar hash mismatch: the jar check fires BEFORE RunUnlockFlow -- the unconsumed key was never touched");
    }

    // --- Scenario 12: missing jar file entirely ----------------------------------
    {
        Scenario s = SetupScenario(base_dir, "12_missing_jar", 2, hwid_canonical, handoff_spy_path);
        fs::remove(s.dir + "/quark.jar");
        RunResult r = RunWrapper(wrapper_path, s.dir, KeyAt(s, 1) + "\n");
        Check(r.exit_code != 0, "missing jar file: DRM_Wrapper refuses to launch");
        Check(r.stderr_output.find(ErrTag(quark::error::Code::kWrapperJarIntegrityFailed)) != std::string::npos,
              "missing jar file: reports kWrapperJarIntegrityFailed");
    }

    // --- Scenario 13: concurrent launches racing on the same single-use key ----
    // Real, demonstrated finding (not theoretical): without
    // quark::platform::IProcessLock, N processes launched simultaneously
    // against the same license could ALL redeem the same single-use key --
    // a real license clone, not just a narrow TOCTOU. This is the
    // permanent regression test for that fix.
    {
        Scenario s = SetupScenario(base_dir, "13_concurrent_race", 1, hwid_canonical, handoff_spy_path);
        const std::string key = KeyAt(s, 1) + "\n";

        constexpr int kRacers = 8;
        std::vector<PendingRun> pending;
        pending.reserve(kRacers);
        for (int i = 0; i < kRacers; ++i) {
            pending.push_back(StartWrapper(wrapper_path, s.dir, key));
        }

        int success_count = 0;
        for (auto& p : pending) {
            RunResult r = FinishWrapper(p);
            if (r.exit_code == 0) ++success_count;
        }
        Check(success_count == 1,
              "concurrent race: exactly one of " + std::to_string(kRacers) +
                  " simultaneous launches redeems the single-use key (IProcessLock excludes the rest)");
    }

    fs::remove_all(base_dir);

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
