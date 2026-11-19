// DRM_Wrapper
//
// Customer-facing shield. Flow (every launch):
//   1.   Anti-debug speed bumps -- any hit -> FailDeadly() immediately.
//   1.5. Hash quark.jar and compare against the expected digest (config
//        override, or the compiled-in jar_digest.hpp default) -- closes the
//        "swap the jar" gap.
//   2-7. quark::orchestrator::RunUnlockFlow does the rest: HWID collection,
//        state.bin open, three-witness cross-check, online-witness
//        fetch/verify, chain-exhaustion check, one-time key verification,
//        chain roll-forward + persistence, and session key derivation.
//   8.   Launch the JVM with a QKH2 initial frame (136 B) on stdin; stdin
//        stays OPEN. A second pipe (child stdout -> parent) carries
//        challenge responses.
//   9.   Run the challenge loop until the child exits or fails a challenge.
//
// Every failure is the same outward event: exit(1), also funneled through
// the numbered registry (fail_deadly.hpp / CLAUDE.md rule 5).
//
// Cross-platform: the flow above is identical on every OS (it's all
// quark_core/quark::orchestrator now). Only four small, explicitly-marked
// seams differ per OS -- anti-debug, the HWID backend, the three witness
// stores, and the process-launch/challenge-loop pair.

#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/config.hpp"
#include "quark/error.hpp"
#include "quark/handoff.hpp"
#include "quark/orchestrator.hpp"
#include "quark/platform/file_witness_store.hpp"
#include "quark/platform/hwid_backend.hpp"
#include "quark/platform/process_lock.hpp"
#include "quark/platform/witness_store.hpp"

#include "fail_deadly.hpp"
#include "jar_digest.hpp"
#include "secret.hpp"

#if defined(_WIN32)
#include "anti_debug.hpp"
#include "handoff.hpp"
#include "quark/platform/windows/hwid_backend_win.hpp"
#include "quark/platform/windows/process_lock_win.hpp"
#include "quark/platform/windows/witness_stores_win.hpp"
#elif defined(__APPLE__)
#include "quark/platform/macos/anti_debug_macos.hpp"
#include "quark/platform/macos/hwid_backend_macos.hpp"
#include "quark/platform/macos/xattr_witness_store.hpp"
#include "quark/platform/posix/process_handoff.hpp"
#include "quark/platform/posix/process_lock_posix.hpp"
#elif defined(__linux__)
#include "quark/platform/linux/anti_debug_linux.hpp"
#include "quark/platform/linux/hwid_backend_linux.hpp"
#include "quark/platform/linux/xattr_witness_store.hpp"
#include "quark/platform/posix/process_handoff.hpp"
#include "quark/platform/posix/process_lock_posix.hpp"
#endif

namespace {

using namespace quark::drm_wrapper;

constexpr const char* kComponent = "DRM_Wrapper";
constexpr const char* kConfigPath = "drm_wrapper.conf";

std::optional<quark::crypto::Sha256Digest> HashFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::vector<uint8_t> contents((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());
    if (in.bad()) return std::nullopt;
    return quark::crypto::Sha256(contents);
}

bool DigestsEqual(const quark::crypto::Sha256Digest& a, const quark::crypto::Sha256Digest& b) {
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

std::optional<quark::crypto::Sha256Digest> HexDecodeDigest(const std::string& hex) {
    if (hex.size() != 64) return std::nullopt;
    quark::crypto::Sha256Digest out{};
    for (size_t i = 0; i < 32; ++i) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nibble(hex[i * 2]);
        int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

std::string PromptForKey() {
    std::cout << "Enter your one-time unlock key: ";
    std::string line;
    std::getline(std::cin, line);
    return line;
}

std::unique_ptr<quark::platform::IHwidBackend> MakeHwidBackend() {
#if defined(_WIN32)
    return std::make_unique<quark::platform::win::WindowsHwidBackend>();
#elif defined(__APPLE__)
    return std::make_unique<quark::platform::macos::MacHwidBackend>();
#elif defined(__linux__)
    return std::make_unique<quark::platform::linux_::LinuxHwidBackend>();
#else
    return nullptr;
#endif
}

// Excludes two DRM_Wrapper launches racing on the same license from both
// redeeming the same single-use key -- see quark/platform/process_lock.hpp
// for the real concurrent-launch testing that found this was necessary.
std::unique_ptr<quark::platform::IProcessLock> MakeProcessLock() {
#if defined(_WIN32)
    return std::make_unique<quark::platform::win::LockFileProcessLock>();
#elif defined(__APPLE__) || defined(__linux__)
    return std::make_unique<quark::platform::posix::FlockProcessLock>();
#else
    return nullptr;
#endif
}

bool DebuggerDetected() {
#if defined(_WIN32)
    return quark::drm_wrapper::DebuggerDetected();
#elif defined(__APPLE__)
    return quark::platform::macos::DebuggerDetected();
#elif defined(__linux__)
    return quark::platform::linux_::DebuggerDetected();
#else
    return false;
#endif
}

// Split "a b c" into {"a", "b", "c"} -- used to turn the config's jvm_args
// string into an argv vector on POSIX.
std::vector<std::string> SplitArgs(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ' ') {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

}  // namespace

int main() {
    // --- Step 1: anti-debug speed bumps ------------------------------------
    if (DebuggerDetected()) {
        FailDeadly(quark::error::Code::kWrapperDebuggerDetected);
    }

    auto config = quark::config::Config::Load(kConfigPath);
    quark::config::Config cfg = config.value_or(quark::config::Config{});

    const std::string state_path = cfg.GetOr("state_path", "state.bin");
    const std::string quark_jar_path = cfg.GetOr("quark_jar_path", "quark.jar");
    const std::string jvm_path = cfg.GetOr(
        "jvm_path",
#if defined(_WIN32)
        "jre\\bin\\javaw.exe"
#else
        "jre/bin/java"
#endif
    );
    const std::string jvm_args = cfg.GetOr(
        "jvm_args", "-cp quark.jar main.jar quark.drmcore.Bootstrap");
    const int challenge_interval_ms = cfg.GetIntOr("challenge_interval_ms", 30'000);
    const int challenge_timeout_ms = cfg.GetIntOr("challenge_timeout_ms", 10'000);

    // --- Step 1.5: jar integrity --------------------------------------------
    quark::crypto::Sha256Digest expected_jar_hash = kQuarkJarSha256;
    if (auto override_hex = cfg.GetOr("quark_jar_sha256_hex", ""); !override_hex.empty()) {
        auto decoded = HexDecodeDigest(override_hex);
        if (!decoded) FailDeadly(quark::error::Code::kWrapperJarIntegrityFailed);
        expected_jar_hash = *decoded;
    }

    auto jar_digest = HashFile(quark_jar_path);
    if (!jar_digest || !DigestsEqual(*jar_digest, expected_jar_hash)) {
        FailDeadly(quark::error::Code::kWrapperJarIntegrityFailed);
    }

    // --- Steps 2-7: the entire unlock flow -----------------------------------
    auto hwid_backend = MakeHwidBackend();
    if (!hwid_backend) FailDeadly(quark::error::Code::kWrapperHwidCollectionFailed);

    auto process_lock = MakeProcessLock();

#if defined(_WIN32)
    quark::platform::win::RegistryWitnessStore w0;
    quark::platform::win::AdsWitnessStore w1;
    quark::platform::win::OverlayWitnessStore w2;
#else
    const std::string xattr_host = cfg.GetOr("witness_xattr_host_path", "quark_witness_host.bin");
    const std::string xattr1_attr = cfg.GetOr("witness_xattr1_attr", "com.quark.witness1");
    const std::string xattr2_attr = cfg.GetOr("witness_xattr2_attr", "com.quark.witness2");
    const std::string file_path = cfg.GetOr("witness_file_path", "quark_witness_file.bin");

#if defined(__APPLE__)
    quark::platform::macos::XattrWitnessStore w0(xattr_host, xattr1_attr, {'Q', 'W', 'X', '1'}, "xattr1");
    quark::platform::macos::XattrWitnessStore w1(xattr_host, xattr2_attr, {'Q', 'W', 'X', '2'}, "xattr2");
#elif defined(__linux__)
    quark::platform::linux_::XattrWitnessStore w0(xattr_host, xattr1_attr, {'Q', 'W', 'X', '1'}, "xattr1");
    quark::platform::linux_::XattrWitnessStore w1(xattr_host, xattr2_attr, {'Q', 'W', 'X', '2'}, "xattr2");
#endif
    quark::platform::FileWitnessStore w2(file_path, {'Q', 'W', 'F', '0'}, "file");
#endif

    quark::orchestrator::Config unlock_config;
    unlock_config.build_secret = quark::drm_wrapper::kBuildSecret;
    unlock_config.state_path = state_path;
    unlock_config.ec_public_key = quark::drm_wrapper::kEcPublicKey;

    std::string raw_key = PromptForKey();

    quark::orchestrator::UnlockResult result;
    quark::error::Code code = quark::orchestrator::RunUnlockFlow(
        unlock_config, *hwid_backend, {&w0, &w1, &w2}, raw_key, result, process_lock.get());
    quark::crypto::SecureZero(raw_key.data(), raw_key.size());

    if (code != quark::error::Code::kOk) {
        FailDeadly(code);
    }

    // --- encode the QKH2 initial frame --------------------------------------
    std::vector<uint8_t> initial_frame = quark::handoff::EncodeInitialFrame(
        result.handoff_secret, result.session_id, result.initial_seal, result.core_enc_key);
    quark::crypto::SecureZero(result.handoff_secret.data(), result.handoff_secret.size());

    // --- Step 8/9: launch + challenge loop -----------------------------------
#if defined(_WIN32)
    std::wstring wjvm_path(jvm_path.begin(), jvm_path.end());
    std::string command_line_str = jvm_path + " " + jvm_args;
    std::wstring wcommand_line(command_line_str.begin(), command_line_str.end());

    JvmSession session = LaunchJvmWithInitialHandoff(wjvm_path, wcommand_line, initial_frame);
    RunChallengeLoop(session, result.content_key, result.session_id,
                      static_cast<DWORD>(challenge_interval_ms), static_cast<DWORD>(challenge_timeout_ms));

    DWORD exit_code = 1;
    GetExitCodeProcess(session.process.Get(), &exit_code);
    return static_cast<int>(exit_code);
#else
    std::vector<std::string> argv = {jvm_path};
    for (auto& arg : SplitArgs(jvm_args)) argv.push_back(arg);

    quark::platform::posix::JvmSession session =
        quark::platform::posix::LaunchWithInitialHandoff(kComponent, jvm_path, argv, initial_frame);
    quark::platform::posix::RunChallengeLoop(session, result.content_key, result.session_id,
                                              challenge_interval_ms, challenge_timeout_ms);
    return quark::platform::posix::WaitAndGetExitCode(session);
#endif
}
