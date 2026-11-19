# Quark VM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `quark_vm`, a small embedded bytecode interpreter whose blocks decrypt only under a key derived from a real Quark unlock, so a protected application's actual computation (not a boolean flag) is what fails when the license flow wasn't completed honestly.

**Architecture:** A new, OS-independent static library `cpp/quark_vm` (stack-machine bytecode, `BlockCache` for on-demand decrypt/wipe, `Interpreter` for execution) built on top of the existing `quark_core` primitives (`quark::payload::Seal/Unseal`, `quark::token`), plus a small `quark-vmasm` text-assembler tool for producing `.qvm` programs at issuance time.

**Tech Stack:** C++17, CMake, the project's existing hand-rolled `Check()`-style test harness (no test framework dependency, matching `cpp/common/tests`).

Reference: [docs/superpowers/specs/2026-07-04-quark-vm-cryptographic-interlocking-design.md](../specs/2026-07-04-quark-vm-cryptographic-interlocking-design.md)

---

## File structure

```
cpp/common/include/quark/token.hpp        modify: add DeriveVmKey
cpp/common/src/token.cpp                  modify: add DeriveVmKey
cpp/common/tests/core_smoke_test.cpp      modify: add DeriveVmKey test

cpp/quark_vm/CMakeLists.txt               new
cpp/quark_vm/include/quark/vm/opcode.hpp  new: Opcode enum, Instruction, encode/decode
cpp/quark_vm/src/opcode.cpp               new
cpp/quark_vm/include/quark/vm/program.hpp new: Block, Program, (de)serialize, SealBlock
cpp/quark_vm/src/program.cpp              new
cpp/quark_vm/include/quark/vm/block_cache.hpp   new
cpp/quark_vm/src/block_cache.cpp          new
cpp/quark_vm/include/quark/vm/host_function_table.hpp  new: C-ABI host callback table
cpp/quark_vm/include/quark/vm/interpreter.hpp   new
cpp/quark_vm/src/interpreter.cpp          new
cpp/quark_vm/tests/CMakeLists.txt         new
cpp/quark_vm/tests/quark_vm_test.cpp      new

cpp/quark_vmasm/CMakeLists.txt            new
cpp/quark_vmasm/main.cpp                  new: text assembly -> .qvm

CMakeLists.txt                            modify: add_subdirectory for both new modules
docs/PLAN.md                              modify: record the new phase
cpp/quark_vm/README.md                    new: module doc (tracked per .gitignore's module-README rule)
```

---

### Task 1: `DeriveVmKey` in quark_core

**Files:**
- Modify: `cpp/common/include/quark/token.hpp`
- Modify: `cpp/common/src/token.cpp`
- Test: `cpp/common/tests/core_smoke_test.cpp`

- [ ] **Step 1: Write the failing test**

Add to `cpp/common/tests/core_smoke_test.cpp`, right after `TestTokenDerivationIsDeterministicAndDomainSeparated()`'s definition (find that function and insert this one immediately after its closing `}`):

```cpp
void TestVmKeyDerivation() {
    quark::crypto::AesKey content_key{};
    auto random = quark::crypto::RandomBytes(32);
    std::copy(random.begin(), random.end(), content_key.begin());

    auto vm_key_a = quark::token::DeriveVmKey(content_key);
    auto vm_key_b = quark::token::DeriveVmKey(content_key);
    Check(vm_key_a == vm_key_b, "DeriveVmKey is deterministic for the same content_key");

    quark::crypto::AesKey other_content_key{};
    auto random2 = quark::crypto::RandomBytes(32);
    std::copy(random2.begin(), random2.end(), other_content_key.begin());
    auto vm_key_c = quark::token::DeriveVmKey(other_content_key);
    Check(vm_key_a != vm_key_c, "DeriveVmKey differs for a different content_key");
}
```

Then add `TestVmKeyDerivation();` to `main()`, right after the existing `TestTokenDerivationIsDeterministicAndDomainSeparated();` call.

- [ ] **Step 2: Run test to verify it fails (does not compile)**

Run: `cmake --build sandbox/build-host --target quark_core_tests`
Expected: FAIL with `error: no member named 'DeriveVmKey' in namespace 'quark::token'`

- [ ] **Step 3: Add the declaration**

In `cpp/common/include/quark/token.hpp`, add this immediately before the closing `}  // namespace quark::token`:

```cpp
// vm_key = HMAC-SHA256(content_key, "QUARK-VM-KEY")
//
// Domain-separated key for quark_vm's per-block bytecode sealing (see
// cpp/quark_vm and docs/superpowers/specs/2026-07-04-quark-vm-cryptographic-
// interlocking-design.md). Deterministic in content_key: a block sealed at
// issuance time with the target machine's expected content_key is opened
// correctly by that same machine's real runtime unlock, and by no other.
crypto::AesKey DeriveVmKey(const crypto::AesKey& content_key);
```

- [ ] **Step 4: Add the implementation**

In `cpp/common/src/token.cpp`, add this immediately before the closing `}  // namespace quark::token`:

```cpp
crypto::AesKey DeriveVmKey(const crypto::AesKey& content_key) {
    std::vector<uint8_t> msg;
    AppendDomain(msg, "QUARK-VM-KEY");

    crypto::Sha256Digest digest = crypto::HmacSha256(content_key.data(), content_key.size(),
                                                      msg.data(), msg.size());
    crypto::AesKey key{};
    std::memcpy(key.data(), digest.data(), key.size());
    return key;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cmake --build sandbox/build-host --target quark_core_tests && ./sandbox/build-host/cpp/common/tests/quark_core_tests`
Expected: `ok: DeriveVmKey is deterministic for the same content_key`, `ok: DeriveVmKey differs for a different content_key`, and `all checks passed.` at the end with exit code 0.

- [ ] **Step 6: Commit**

```bash
git add cpp/common/include/quark/token.hpp cpp/common/src/token.cpp cpp/common/tests/core_smoke_test.cpp
git commit -m "Add DeriveVmKey for quark_vm's per-block bytecode sealing"
```

---

### Task 2: Opcode and instruction encoding

**Files:**
- Create: `cpp/quark_vm/include/quark/vm/opcode.hpp`
- Create: `cpp/quark_vm/src/opcode.cpp`
- Create: `cpp/quark_vm/CMakeLists.txt`
- Create: `cpp/quark_vm/tests/CMakeLists.txt`
- Create: `cpp/quark_vm/tests/quark_vm_test.cpp`
- Modify: `CMakeLists.txt` (top-level)

- [ ] **Step 1: Create the module skeleton so the test target can exist**

Create `cpp/quark_vm/include/quark/vm/opcode.hpp`:

```cpp
#pragma once
// The Quark VM instruction set -- a minimal stack machine. See
// docs/superpowers/specs/2026-07-04-quark-vm-cryptographic-interlocking-design.md
// for why a custom bytecode interpreter (rather than raw native code or an
// existing VM like WASM) is the chosen mechanism.
//
// Every instruction is a fixed 24 bytes on disk/in a sealed block: 1 byte
// opcode + 7 bytes padding + 8 bytes operand `a` (little-endian, signed) + 8
// bytes operand `b` (little-endian, signed). Fixed size, no variable-length
// parsing -- CLAUDE.md rule 3, simple over clever. Most instructions only use
// `a`; CALL and CALL_HOST use both (target/host-fn id in `a`, argument count
// in `b`).
//
// Control transfer is always between whole blocks (JMP/JMP_IF_ZERO/CALL
// target a block id, never an in-block offset) -- a block is the unit
// BlockCache decrypts and wipes, so control flow never needs to jump into
// the middle of one.

#include <cstddef>
#include <cstdint>
#include <vector>

namespace quark::vm {

enum class Opcode : uint8_t {
    kPushI64 = 1,     // push immediate `a`
    kLoadLocal = 2,   // push locals[a]
    kStoreLocal = 3,  // locals[a] = pop()
    kAdd = 4,
    kSub = 5,
    kMul = 6,
    kDiv = 7,   // pop b, pop a, push (b == 0 ? 0 : a / b)
    kMod = 8,   // pop b, pop a, push (b == 0 ? 0 : a % b)
    kAnd = 9,
    kOr = 10,
    kXor = 11,
    kNot = 12,  // pop a, push ~a
    kShl = 13,
    kShr = 14,
    kCmpEq = 15,
    kCmpLt = 16,
    kCmpGt = 17,
    kJmp = 18,        // jump to block `a`
    kJmpIfZero = 19,  // pop v; if v == 0, jump to block `a`
    kCall = 20,       // call block `a` with `b` (unused, reserved) -- pushes a return frame
    kCallHost = 21,   // call host function `a` with `b` arguments popped off the stack
    kRet = 22,        // return to caller's block/pc, or halt if no caller
    kHalt = 23,
};

struct Instruction {
    Opcode op = Opcode::kHalt;
    int64_t a = 0;
    int64_t b = 0;

    bool operator==(const Instruction& other) const {
        return op == other.op && a == other.a && b == other.b;
    }
};

constexpr size_t kInstructionEncodedSize = 24;

// Encodes exactly kInstructionEncodedSize bytes.
std::vector<uint8_t> EncodeInstruction(const Instruction& instr);

// Reads exactly kInstructionEncodedSize bytes starting at `bytes`. Caller
// must ensure at least that many bytes are available.
Instruction DecodeInstruction(const uint8_t* bytes);

}  // namespace quark::vm
```

Create `cpp/quark_vm/src/opcode.cpp`:

```cpp
#include "quark/vm/opcode.hpp"

#include <cstring>

namespace quark::vm {

namespace {

void AppendI64(std::vector<uint8_t>& buf, int64_t v) {
    auto u = static_cast<uint64_t>(v);
    for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>((u >> (8 * i)) & 0xFF));
}

int64_t ReadI64(const uint8_t* p) {
    uint64_t u = 0;
    for (int i = 0; i < 8; ++i) u |= static_cast<uint64_t>(p[i]) << (8 * i);
    return static_cast<int64_t>(u);
}

}  // namespace

std::vector<uint8_t> EncodeInstruction(const Instruction& instr) {
    std::vector<uint8_t> out;
    out.reserve(kInstructionEncodedSize);
    out.push_back(static_cast<uint8_t>(instr.op));
    for (int i = 0; i < 7; ++i) out.push_back(0);
    AppendI64(out, instr.a);
    AppendI64(out, instr.b);
    return out;
}

Instruction DecodeInstruction(const uint8_t* bytes) {
    Instruction instr;
    instr.op = static_cast<Opcode>(bytes[0]);
    instr.a = ReadI64(bytes + 8);
    instr.b = ReadI64(bytes + 16);
    return instr;
}

}  // namespace quark::vm
```

Create `cpp/quark_vm/CMakeLists.txt`:

```cmake
# quark_vm: a small embedded bytecode interpreter whose blocks only decrypt
# under a key derived from a real Quark unlock (quark::token::DeriveVmKey).
# Zero OS-specific code -- depends only on quark_core, builds and is
# genuinely testable on any OS. See docs/superpowers/specs/2026-07-04-quark-
# vm-cryptographic-interlocking-design.md for the full rationale.
add_library(quark_vm STATIC
    src/opcode.cpp
    src/program.cpp
    src/block_cache.cpp
    src/interpreter.cpp
)

target_include_directories(quark_vm PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(quark_vm PUBLIC quark_core)

add_subdirectory(tests)
```

Create `cpp/quark_vm/tests/CMakeLists.txt`:

```cmake
add_executable(quark_vm_tests quark_vm_test.cpp)
target_link_libraries(quark_vm_tests PRIVATE quark_vm)
add_test(NAME quark_vm_tests COMMAND quark_vm_tests)
```

Create `cpp/quark_vm/tests/quark_vm_test.cpp` (this task only needs the opcode round-trip test; later tasks append more `Test*` functions to this same file):

```cpp
// Real, deterministic, non-mocked tests for quark_vm -- the interpreter has
// no OS dependency at all, so unlike most of this project's platform-layer
// tests, there is nothing here that *couldn't* be tested for real; see
// CLAUDE.md engineering rule 1.

#include <cstdio>

#include "quark/vm/opcode.hpp"

namespace {

int g_failures = 0;

void Check(bool condition, const char* what) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++g_failures;
    } else {
        std::printf("ok: %s\n", what);
    }
}

void TestInstructionEncodeDecodeRoundTrip() {
    quark::vm::Instruction instr;
    instr.op = quark::vm::Opcode::kCall;
    instr.a = 42;
    instr.b = -7;

    auto encoded = quark::vm::EncodeInstruction(instr);
    Check(encoded.size() == quark::vm::kInstructionEncodedSize,
          "EncodeInstruction produces exactly kInstructionEncodedSize bytes");

    auto decoded = quark::vm::DecodeInstruction(encoded.data());
    Check(decoded == instr, "DecodeInstruction(EncodeInstruction(x)) == x");
}

}  // namespace

int main() {
    TestInstructionEncodeDecodeRoundTrip();

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
```

This task's CMakeLists.txt for `quark_vm` already lists `src/program.cpp`, `src/block_cache.cpp`, and `src/interpreter.cpp`, which don't exist yet -- create empty placeholders so the build succeeds; Tasks 3, 4, and 5 fill them in:

```bash
mkdir -p cpp/quark_vm/src
echo '#include "quark/vm/program.hpp"' > cpp/quark_vm/src/program.cpp
echo '#include "quark/vm/block_cache.hpp"' > cpp/quark_vm/src/block_cache.cpp
echo '#include "quark/vm/interpreter.hpp"' > cpp/quark_vm/src/interpreter.cpp
```

These `#include` a header that doesn't exist yet either -- also stub the headers minimally so the includes resolve (Tasks 3-6 replace these with the real contents):

```bash
mkdir -p cpp/quark_vm/include/quark/vm
printf '#pragma once\n' > cpp/quark_vm/include/quark/vm/program.hpp
printf '#pragma once\n' > cpp/quark_vm/include/quark/vm/block_cache.hpp
printf '#pragma once\n' > cpp/quark_vm/include/quark/vm/interpreter.hpp
```

- [ ] **Step 2: Wire into the top-level build**

In the top-level `CMakeLists.txt`, right after the existing `add_subdirectory(cpp/quark_c_api)` line, add:

```cmake
# quark_vm: embedded bytecode interpreter (see cpp/quark_vm/README.md).
# Also never gated behind WIN32 -- zero OS-specific code.
add_subdirectory(cpp/quark_vm)
```

- [ ] **Step 3: Run test to verify it fails first (sanity: confirm clean configure, then that the real test file's assertions would fail without Step 1's opcode.cpp)**

Since Step 1 already included the real implementation, instead run this to confirm the whole new target builds and the test passes:

Run: `cmake -S . -B sandbox/build-host && cmake --build sandbox/build-host --target quark_vm_tests`
Expected: builds successfully (the stub headers/sources for program/block_cache/interpreter are enough to compile empty translation units).

- [ ] **Step 4: Run the test**

Run: `./sandbox/build-host/cpp/quark_vm/tests/quark_vm_tests`
Expected:
```
ok: EncodeInstruction produces exactly kInstructionEncodedSize bytes
ok: DecodeInstruction(EncodeInstruction(x)) == x

all checks passed.
```
Exit code 0.

- [ ] **Step 5: Commit**

```bash
git add cpp/quark_vm CMakeLists.txt
git commit -m "Add quark_vm module scaffold with opcode encode/decode"
```

---

### Task 3: Program container format

**Files:**
- Modify: `cpp/quark_vm/include/quark/vm/program.hpp` (replace stub)
- Modify: `cpp/quark_vm/src/program.cpp` (replace stub)
- Modify: `cpp/quark_vm/tests/quark_vm_test.cpp` (add test)

- [ ] **Step 1: Write the failing test**

In `cpp/quark_vm/tests/quark_vm_test.cpp`, add `#include "quark/vm/program.hpp"` to the includes, and add this function right after `TestInstructionEncodeDecodeRoundTrip()`:

```cpp
void TestProgramSerializeRoundTrip() {
    quark::vm::Program program;
    program.entry_block_id = 7;
    program.sealed_blocks[7] = {1, 2, 3, 4};
    program.sealed_blocks[9] = {5, 6};

    auto bytes = quark::vm::SerializeProgram(program);
    auto decoded = quark::vm::DeserializeProgram(bytes);
    Check(decoded.has_value(), "DeserializeProgram succeeds on well-formed bytes");
    Check(decoded->entry_block_id == 7, "entry_block_id round-trips");
    Check(decoded->sealed_blocks.size() == 2, "block count round-trips");
    Check(decoded->sealed_blocks.at(7) == std::vector<uint8_t>({1, 2, 3, 4}),
          "block 7's sealed bytes round-trip");
    Check(decoded->sealed_blocks.at(9) == std::vector<uint8_t>({5, 6}),
          "block 9's sealed bytes round-trip");

    std::vector<uint8_t> truncated(bytes.begin(), bytes.begin() + 4);
    Check(!quark::vm::DeserializeProgram(truncated).has_value(),
          "DeserializeProgram rejects truncated input");

    std::vector<uint8_t> bad_magic = bytes;
    bad_magic[0] = 'X';
    Check(!quark::vm::DeserializeProgram(bad_magic).has_value(),
          "DeserializeProgram rejects wrong magic");
}
```

Add `TestProgramSerializeRoundTrip();` to `main()` after `TestInstructionEncodeDecodeRoundTrip();`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build sandbox/build-host --target quark_vm_tests`
Expected: FAIL -- `error: no member named 'SerializeProgram' in namespace 'quark::vm'` (the stub header is empty).

- [ ] **Step 3: Write the real header**

Replace the contents of `cpp/quark_vm/include/quark/vm/program.hpp`:

```cpp
#pragma once
// A Block is a decoded (plaintext) sequence of instructions; a Program is
// what actually ships and runs -- every block's SEALED bytes, keyed by block
// id, plus which block execution starts at. Nothing in Program is ever
// decrypted as a whole; BlockCache (see block_cache.hpp) opens one block at
// a time, on demand.

#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include "quark/crypto.hpp"
#include "quark/vm/opcode.hpp"

namespace quark::vm {

struct Block {
    uint32_t id = 0;
    std::vector<Instruction> instructions;
};

struct Program {
    uint32_t entry_block_id = 0;
    std::unordered_map<uint32_t, std::vector<uint8_t>> sealed_blocks;
};

// On-disk/.qvm container format (all integers little-endian):
//   magic(4)="QVM1" + version(u32) + entry_block_id(u32) + block_count(u32)
//   + per block: block_id(u32) + sealed_len(u32) + sealed_bytes
std::vector<uint8_t> SerializeProgram(const Program& program);

// Returns nullopt on bad magic, unsupported version, or truncation. Does
// NOT decrypt anything -- sealed_blocks stay sealed.
std::optional<Program> DeserializeProgram(const std::vector<uint8_t>& bytes);

// Dev/issuance-time helper: encodes `block`'s instructions and seals them
// under `vm_key` via quark::payload::Seal. The runtime never calls this --
// only BlockCache's Unseal path (Task 4) does the inverse.
std::vector<uint8_t> SealBlock(const crypto::AesKey& vm_key, const Block& block);

}  // namespace quark::vm
```

- [ ] **Step 4: Write the real implementation**

Replace the contents of `cpp/quark_vm/src/program.cpp`:

```cpp
#include "quark/vm/program.hpp"

#include <cstring>

#include "quark/payload.hpp"

namespace quark::vm {

namespace {

constexpr char kMagic[4] = {'Q', 'V', 'M', '1'};
constexpr uint32_t kFormatVersion = 1;

void AppendU32(std::vector<uint8_t>& buf, uint32_t v) {
    for (int i = 0; i < 4; ++i) buf.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

uint32_t ReadU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

}  // namespace

std::vector<uint8_t> SerializeProgram(const Program& program) {
    std::vector<uint8_t> out;
    out.insert(out.end(), std::begin(kMagic), std::end(kMagic));
    AppendU32(out, kFormatVersion);
    AppendU32(out, program.entry_block_id);
    AppendU32(out, static_cast<uint32_t>(program.sealed_blocks.size()));
    for (const auto& [block_id, sealed] : program.sealed_blocks) {
        AppendU32(out, block_id);
        AppendU32(out, static_cast<uint32_t>(sealed.size()));
        out.insert(out.end(), sealed.begin(), sealed.end());
    }
    return out;
}

std::optional<Program> DeserializeProgram(const std::vector<uint8_t>& bytes) {
    constexpr size_t kHeaderSize = 4 + 4 + 4 + 4;
    if (bytes.size() < kHeaderSize) return std::nullopt;
    if (std::memcmp(bytes.data(), kMagic, sizeof(kMagic)) != 0) return std::nullopt;

    size_t off = sizeof(kMagic);
    if (ReadU32(bytes.data() + off) != kFormatVersion) return std::nullopt;
    off += 4;

    Program program;
    program.entry_block_id = ReadU32(bytes.data() + off);
    off += 4;
    uint32_t block_count = ReadU32(bytes.data() + off);
    off += 4;

    for (uint32_t i = 0; i < block_count; ++i) {
        if (off + 8 > bytes.size()) return std::nullopt;
        uint32_t block_id = ReadU32(bytes.data() + off);
        off += 4;
        uint32_t sealed_len = ReadU32(bytes.data() + off);
        off += 4;
        if (off + sealed_len > bytes.size()) return std::nullopt;
        program.sealed_blocks[block_id] =
            std::vector<uint8_t>(bytes.begin() + static_cast<ptrdiff_t>(off),
                                 bytes.begin() + static_cast<ptrdiff_t>(off + sealed_len));
        off += sealed_len;
    }
    if (off != bytes.size()) return std::nullopt;
    return program;
}

std::vector<uint8_t> SealBlock(const crypto::AesKey& vm_key, const Block& block) {
    std::vector<uint8_t> plaintext;
    plaintext.reserve(block.instructions.size() * kInstructionEncodedSize);
    for (const auto& instr : block.instructions) {
        auto encoded = EncodeInstruction(instr);
        plaintext.insert(plaintext.end(), encoded.begin(), encoded.end());
    }
    return quark::payload::Seal(vm_key, plaintext);
}

}  // namespace quark::vm
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cmake --build sandbox/build-host --target quark_vm_tests && ./sandbox/build-host/cpp/quark_vm/tests/quark_vm_tests`
Expected: all `TestProgramSerializeRoundTrip` checks print `ok:` and the binary exits 0.

- [ ] **Step 6: Commit**

```bash
git add cpp/quark_vm/include/quark/vm/program.hpp cpp/quark_vm/src/program.cpp cpp/quark_vm/tests/quark_vm_test.cpp
git commit -m "Add Program container serialization to quark_vm"
```

---

### Task 4: BlockCache -- decrypt on demand, poison on failure, idle wipe

**Files:**
- Modify: `cpp/quark_vm/include/quark/vm/block_cache.hpp` (replace stub)
- Modify: `cpp/quark_vm/src/block_cache.cpp` (replace stub)
- Modify: `cpp/quark_vm/tests/quark_vm_test.cpp` (add test)

- [ ] **Step 1: Write the failing test**

Add `#include <chrono>`, `#include <thread>`, and `#include "quark/vm/block_cache.hpp"` to the test file's includes. Add this function after `TestProgramSerializeRoundTrip()`:

```cpp
void TestBlockCacheDecryptExecuteWipeCycle() {
    quark::crypto::AesKey vm_key{};
    auto random = quark::crypto::RandomBytes(32);
    std::copy(random.begin(), random.end(), vm_key.begin());

    quark::vm::Block block;
    block.id = 1;
    block.instructions = {quark::vm::Instruction{quark::vm::Opcode::kPushI64, 99, 0}};

    quark::vm::Program program;
    program.entry_block_id = 1;
    program.sealed_blocks[1] = quark::vm::SealBlock(vm_key, block);

    quark::vm::BlockCache cache(vm_key, program, std::chrono::seconds(0));
    Check(!cache.IsResidentForTest(1), "block starts non-resident");

    const auto& decoded = cache.Acquire(1);
    Check(decoded.size() == 1 && decoded[0].op == quark::vm::Opcode::kPushI64 && decoded[0].a == 99,
          "Acquire decrypts the correct instruction with the right vm_key");
    Check(cache.IsResidentForTest(1), "block is resident after Acquire");

    cache.Release(1);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    cache.Sweep();
    Check(!cache.IsResidentForTest(1), "Sweep wipes an idle, released block (idle_timeout=0)");

    const auto& redecoded = cache.Acquire(1);
    Check(redecoded.size() == 1 && redecoded[0].a == 99,
          "block re-decrypts correctly the second time");
    cache.Release(1);
}

void TestBlockCacheWrongKeyProducesPoisonNotCrash() {
    quark::crypto::AesKey right_key{};
    auto r1 = quark::crypto::RandomBytes(32);
    std::copy(r1.begin(), r1.end(), right_key.begin());

    quark::crypto::AesKey wrong_key{};
    auto r2 = quark::crypto::RandomBytes(32);
    std::copy(r2.begin(), r2.end(), wrong_key.begin());

    quark::vm::Block block;
    block.id = 1;
    block.instructions = {quark::vm::Instruction{quark::vm::Opcode::kPushI64, 99, 0}};

    quark::vm::Program program;
    program.entry_block_id = 1;
    program.sealed_blocks[1] = quark::vm::SealBlock(right_key, block);

    quark::vm::BlockCache cache(wrong_key, program, std::chrono::seconds(60));
    const auto& decoded = cache.Acquire(1);
    Check(!decoded.empty(), "a decrypt failure never yields an empty/absent block");
    Check(!(decoded.size() == 1 && decoded[0].a == 99),
          "wrong vm_key does not yield the real instruction (poison, not the real block)");
    cache.Release(1);
}
```

Add both calls to `main()` after `TestProgramSerializeRoundTrip();`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build sandbox/build-host --target quark_vm_tests`
Expected: FAIL -- `error: no member named 'BlockCache' in namespace 'quark::vm'`.

- [ ] **Step 3: Write the real header**

Replace the contents of `cpp/quark_vm/include/quark/vm/block_cache.hpp`:

```cpp
#pragma once
// Decrypts Program blocks on demand under `vm_key`, tracks a reference count
// and last-used time per resident block, and wipes (SecureZero) any block
// whose ref-count is 0 and has been idle past `idle_timeout` when Sweep()
// runs. The embedder drives Sweep() from whatever timer it already has --
// quark_vm never spawns its own thread (see the design spec's "Data flow").
//
// A block that fails to authenticate under vm_key (wrong key, tampered
// bytes) is NEVER surfaced as an error the caller branches on: Acquire()
// substitutes a fixed single-instruction {kHalt} placeholder and returns
// that instead. This is the anti-boolean-trap discipline the whole design
// exists to provide -- see docs/superpowers/specs/2026-07-04-quark-vm-
// cryptographic-interlocking-design.md.

#include <chrono>
#include <unordered_map>

#include "quark/crypto.hpp"
#include "quark/vm/program.hpp"

namespace quark::vm {

class BlockCache {
public:
    BlockCache(crypto::AesKey vm_key, Program program, std::chrono::seconds idle_timeout);

    // Decrypts (if not already resident) block `block_id`, bumps its
    // ref-count and last-used time, and returns its instructions. Always
    // returns a valid, non-empty reference -- an unknown block id and a
    // decrypt failure both resolve to the same single-instruction {kHalt}
    // placeholder, indistinguishably.
    const std::vector<Instruction>& Acquire(uint32_t block_id);

    // Decrements the ref-count for `block_id`. No-op if not resident.
    void Release(uint32_t block_id);

    // Wipes the plaintext of every resident block with ref-count 0 whose
    // idle time exceeds idle_timeout. Safe to call as often as desired.
    void Sweep();

    // Test-only: true if `block_id`'s plaintext is currently resident.
    bool IsResidentForTest(uint32_t block_id) const;

    uint32_t entry_block_id() const { return program_.entry_block_id; }

private:
    struct Entry {
        std::vector<Instruction> decoded;
        int ref_count = 0;
        std::chrono::steady_clock::time_point last_used;
    };

    crypto::AesKey vm_key_;
    Program program_;
    std::chrono::seconds idle_timeout_;
    std::unordered_map<uint32_t, Entry> resident_;
};

}  // namespace quark::vm
```

- [ ] **Step 4: Write the real implementation**

Replace the contents of `cpp/quark_vm/src/block_cache.cpp`:

```cpp
#include "quark/vm/block_cache.hpp"

#include "quark/payload.hpp"

namespace quark::vm {

namespace {

const std::vector<Instruction>& PoisonBlock() {
    static const std::vector<Instruction> kPoison = {Instruction{Opcode::kHalt, 0, 0}};
    return kPoison;
}

}  // namespace

BlockCache::BlockCache(crypto::AesKey vm_key, Program program, std::chrono::seconds idle_timeout)
    : vm_key_(vm_key), program_(std::move(program)), idle_timeout_(idle_timeout) {}

const std::vector<Instruction>& BlockCache::Acquire(uint32_t block_id) {
    auto it = resident_.find(block_id);
    if (it == resident_.end()) {
        std::vector<Instruction> decoded;
        auto sealed_it = program_.sealed_blocks.find(block_id);
        if (sealed_it == program_.sealed_blocks.end()) {
            decoded = PoisonBlock();
        } else {
            auto plaintext = quark::payload::Unseal(vm_key_, sealed_it->second);
            if (!plaintext || plaintext->size() % kInstructionEncodedSize != 0) {
                decoded = PoisonBlock();
            } else {
                for (size_t off = 0; off < plaintext->size(); off += kInstructionEncodedSize) {
                    decoded.push_back(DecodeInstruction(plaintext->data() + off));
                }
                crypto::SecureZero(plaintext->data(), plaintext->size());
            }
        }
        Entry entry;
        entry.decoded = std::move(decoded);
        it = resident_.emplace(block_id, std::move(entry)).first;
    }
    it->second.ref_count++;
    it->second.last_used = std::chrono::steady_clock::now();
    return it->second.decoded;
}

void BlockCache::Release(uint32_t block_id) {
    auto it = resident_.find(block_id);
    if (it != resident_.end() && it->second.ref_count > 0) {
        it->second.ref_count--;
    }
}

void BlockCache::Sweep() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = resident_.begin(); it != resident_.end();) {
        if (it->second.ref_count == 0 && (now - it->second.last_used) >= idle_timeout_) {
            if (!it->second.decoded.empty()) {
                crypto::SecureZero(it->second.decoded.data(),
                                   it->second.decoded.size() * sizeof(Instruction));
            }
            it = resident_.erase(it);
        } else {
            ++it;
        }
    }
}

bool BlockCache::IsResidentForTest(uint32_t block_id) const {
    return resident_.find(block_id) != resident_.end();
}

}  // namespace quark::vm
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cmake --build sandbox/build-host --target quark_vm_tests && ./sandbox/build-host/cpp/quark_vm/tests/quark_vm_tests`
Expected: all checks including the two new `TestBlockCache*` functions print `ok:`, exit code 0.

- [ ] **Step 6: Commit**

```bash
git add cpp/quark_vm/include/quark/vm/block_cache.hpp cpp/quark_vm/src/block_cache.cpp cpp/quark_vm/tests/quark_vm_test.cpp
git commit -m "Add BlockCache with decrypt-on-demand, idle wipe, and poison-on-failure"
```

---

### Task 5: HostFunctionTable (C ABI) and the Interpreter

**Files:**
- Create: `cpp/quark_vm/include/quark/vm/host_function_table.hpp`
- Modify: `cpp/quark_vm/include/quark/vm/interpreter.hpp` (replace stub)
- Modify: `cpp/quark_vm/src/interpreter.cpp` (replace stub)
- Modify: `cpp/quark_vm/tests/quark_vm_test.cpp` (add test)

- [ ] **Step 1: Write the failing test**

Add `#include "quark/vm/interpreter.hpp"` to the test file. Add this function after `TestBlockCacheWrongKeyProducesPoisonNotCrash()`:

```cpp
int64_t TestHostDouble(const int64_t* args, size_t argc, void* user_data) {
    (void)user_data;
    return argc == 1 ? args[0] * 2 : 0;
}

void TestInterpreterArithmeticAndHostCall() {
    quark::crypto::AesKey vm_key{};
    auto random = quark::crypto::RandomBytes(32);
    std::copy(random.begin(), random.end(), vm_key.begin());

    // Program: push 3, push 4, add (-> 7), call_host(0, argc=1) which
    // doubles its single argument (-> 14).
    quark::vm::Block entry;
    entry.id = 0;
    entry.instructions = {
        quark::vm::Instruction{quark::vm::Opcode::kPushI64, 3, 0},
        quark::vm::Instruction{quark::vm::Opcode::kPushI64, 4, 0},
        quark::vm::Instruction{quark::vm::Opcode::kAdd, 0, 0},
        quark::vm::Instruction{quark::vm::Opcode::kCallHost, 0, 1},
        quark::vm::Instruction{quark::vm::Opcode::kHalt, 0, 0},
    };

    quark::vm::Program program;
    program.entry_block_id = 0;
    program.sealed_blocks[0] = quark::vm::SealBlock(vm_key, entry);

    quark::vm::BlockCache cache(vm_key, program, std::chrono::seconds(60));

    quark::vm::quark_vm_host_fn_t functions[1] = {&TestHostDouble};
    quark::vm::quark_vm_host_table_t host_table{functions, 1, nullptr};

    quark::vm::Interpreter interp(cache, host_table);
    int64_t result = interp.Run();
    Check(result == 14, "interpreter computes (3+4)*2 == 14 via arithmetic + CALL_HOST");
}

void TestInterpreterWrongKeyGivesWrongResultNotCrash() {
    quark::crypto::AesKey right_key{};
    auto r1 = quark::crypto::RandomBytes(32);
    std::copy(r1.begin(), r1.end(), right_key.begin());
    quark::crypto::AesKey wrong_key{};
    auto r2 = quark::crypto::RandomBytes(32);
    std::copy(r2.begin(), r2.end(), wrong_key.begin());

    quark::vm::Block entry;
    entry.id = 0;
    entry.instructions = {
        quark::vm::Instruction{quark::vm::Opcode::kPushI64, 3, 0},
        quark::vm::Instruction{quark::vm::Opcode::kPushI64, 4, 0},
        quark::vm::Instruction{quark::vm::Opcode::kAdd, 0, 0},
        quark::vm::Instruction{quark::vm::Opcode::kHalt, 0, 0},
    };
    quark::vm::Program program;
    program.entry_block_id = 0;
    program.sealed_blocks[0] = quark::vm::SealBlock(right_key, entry);

    quark::vm::BlockCache cache(wrong_key, program, std::chrono::seconds(60));
    quark::vm::quark_vm_host_table_t host_table{nullptr, 0, nullptr};
    quark::vm::Interpreter interp(cache, host_table);

    int64_t result = interp.Run();
    Check(result != 7, "wrong vm_key does not compute the correct 3+4 result");
    Check(true, "interpreter did not crash on a wrong-key (poisoned) program");
}
```

Add both calls to `main()`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cmake --build sandbox/build-host --target quark_vm_tests`
Expected: FAIL -- `error: no type named 'quark_vm_host_fn_t' in namespace 'quark::vm'` (and `Interpreter` undeclared).

- [ ] **Step 3: Create the host function table header**

Create `cpp/quark_vm/include/quark/vm/host_function_table.hpp`:

```cpp
#pragma once
// The only way protected bytecode reaches outside the VM (file I/O,
// network, anything OS-specific) -- CALL_HOST invokes one of these. Plain
// C struct, not a C++ interface: a Go or Python embedder building on
// quark_c_api has no way to implement a C++ virtual class, so this crosses
// that boundary the same way every other quark_c_api type does (an array of
// function pointers the host fills in).

#include <cstddef>
#include <cstdint>

namespace quark::vm {

extern "C" {

typedef int64_t (*quark_vm_host_fn_t)(const int64_t* args, size_t argc, void* user_data);

typedef struct {
    const quark_vm_host_fn_t* functions;  // indexed by host_fn_id (CALL_HOST's `a` operand)
    size_t function_count;
    void* user_data;                      // opaque context passed to every call
} quark_vm_host_table_t;

}  // extern "C"

}  // namespace quark::vm
```

- [ ] **Step 4: Write the real Interpreter header**

Replace the contents of `cpp/quark_vm/include/quark/vm/interpreter.hpp`:

```cpp
#pragma once
// Fetch-decode-execute loop over a BlockCache. Never branches on whether a
// block's decrypt authenticated -- it relies entirely on BlockCache's
// placeholder-on-failure behavior for the "wrong key -> wrong computation,
// not a blocked branch" guarantee (see block_cache.hpp and the design spec).

#include <array>
#include <cstdint>
#include <vector>

#include "quark/vm/block_cache.hpp"
#include "quark/vm/host_function_table.hpp"

namespace quark::vm {

class Interpreter {
public:
    Interpreter(BlockCache& cache, const quark_vm_host_table_t& host_table);

    // Runs from the program's entry block until a top-level RET or HALT.
    // Returns the top of the value stack at that point (0 if empty) -- the
    // single result value the embedding shell consumes.
    int64_t Run();

private:
    struct Frame {
        uint32_t return_block_id = 0;
        size_t return_pc = 0;
        std::array<int64_t, 16> locals{};
    };

    void ExecuteOne(const Instruction& instr, uint32_t& block_id, size_t& pc, bool& halted);
    int64_t Pop();

    BlockCache& cache_;
    const quark_vm_host_table_t& host_table_;
    std::vector<int64_t> value_stack_;
    std::vector<Frame> call_stack_;
};

}  // namespace quark::vm
```

- [ ] **Step 5: Write the real Interpreter implementation**

Replace the contents of `cpp/quark_vm/src/interpreter.cpp`:

```cpp
#include "quark/vm/interpreter.hpp"

namespace quark::vm {

Interpreter::Interpreter(BlockCache& cache, const quark_vm_host_table_t& host_table)
    : cache_(cache), host_table_(host_table) {}

int64_t Interpreter::Pop() {
    if (value_stack_.empty()) return 0;
    int64_t v = value_stack_.back();
    value_stack_.pop_back();
    return v;
}

void Interpreter::ExecuteOne(const Instruction& instr, uint32_t& block_id, size_t& pc, bool& halted) {
    switch (instr.op) {
        case Opcode::kPushI64:
            value_stack_.push_back(instr.a);
            break;
        case Opcode::kLoadLocal: {
            int64_t v = call_stack_.empty() ? 0 : call_stack_.back().locals[static_cast<size_t>(instr.a) % 16];
            value_stack_.push_back(v);
            break;
        }
        case Opcode::kStoreLocal: {
            int64_t v = Pop();
            if (!call_stack_.empty()) call_stack_.back().locals[static_cast<size_t>(instr.a) % 16] = v;
            break;
        }
        case Opcode::kAdd: { int64_t b = Pop(), a = Pop(); value_stack_.push_back(a + b); break; }
        case Opcode::kSub: { int64_t b = Pop(), a = Pop(); value_stack_.push_back(a - b); break; }
        case Opcode::kMul: { int64_t b = Pop(), a = Pop(); value_stack_.push_back(a * b); break; }
        case Opcode::kDiv: { int64_t b = Pop(), a = Pop(); value_stack_.push_back(b == 0 ? 0 : a / b); break; }
        case Opcode::kMod: { int64_t b = Pop(), a = Pop(); value_stack_.push_back(b == 0 ? 0 : a % b); break; }
        case Opcode::kAnd: { int64_t b = Pop(), a = Pop(); value_stack_.push_back(a & b); break; }
        case Opcode::kOr:  { int64_t b = Pop(), a = Pop(); value_stack_.push_back(a | b); break; }
        case Opcode::kXor: { int64_t b = Pop(), a = Pop(); value_stack_.push_back(a ^ b); break; }
        case Opcode::kNot: { int64_t a = Pop(); value_stack_.push_back(~a); break; }
        case Opcode::kShl: { int64_t b = Pop(), a = Pop(); value_stack_.push_back(a << (b & 63)); break; }
        case Opcode::kShr: { int64_t b = Pop(), a = Pop(); value_stack_.push_back(a >> (b & 63)); break; }
        case Opcode::kCmpEq: { int64_t b = Pop(), a = Pop(); value_stack_.push_back(a == b ? 1 : 0); break; }
        case Opcode::kCmpLt: { int64_t b = Pop(), a = Pop(); value_stack_.push_back(a < b ? 1 : 0); break; }
        case Opcode::kCmpGt: { int64_t b = Pop(), a = Pop(); value_stack_.push_back(a > b ? 1 : 0); break; }
        case Opcode::kJmp:
            block_id = static_cast<uint32_t>(instr.a);
            pc = 0;
            break;
        case Opcode::kJmpIfZero: {
            int64_t v = Pop();
            if (v == 0) { block_id = static_cast<uint32_t>(instr.a); pc = 0; }
            break;
        }
        case Opcode::kCall: {
            Frame frame;
            frame.return_block_id = block_id;
            frame.return_pc = pc;
            call_stack_.push_back(frame);
            block_id = static_cast<uint32_t>(instr.a);
            pc = 0;
            break;
        }
        case Opcode::kCallHost: {
            auto host_id = static_cast<size_t>(instr.a);
            auto argc = static_cast<size_t>(instr.b);
            std::vector<int64_t> args(argc);
            for (size_t i = 0; i < argc; ++i) {
                args[argc - 1 - i] = Pop();
            }
            int64_t result = 0;
            if (host_table_.functions != nullptr && host_id < host_table_.function_count &&
                host_table_.functions[host_id] != nullptr) {
                result = host_table_.functions[host_id](args.data(), args.size(), host_table_.user_data);
            }
            value_stack_.push_back(result);
            break;
        }
        case Opcode::kRet:
            if (call_stack_.empty()) {
                halted = true;
            } else {
                Frame frame = call_stack_.back();
                call_stack_.pop_back();
                block_id = frame.return_block_id;
                pc = frame.return_pc;
            }
            break;
        case Opcode::kHalt:
            halted = true;
            break;
    }
}

int64_t Interpreter::Run() {
    uint32_t block_id = cache_.entry_block_id();
    size_t pc = 0;
    bool halted = false;
    const std::vector<Instruction>* block = &cache_.Acquire(block_id);

    while (!halted) {
        if (pc >= block->size()) {
            halted = true;
            break;
        }
        Instruction instr = (*block)[pc];
        uint32_t next_block_id = block_id;
        size_t next_pc = pc + 1;
        ExecuteOne(instr, next_block_id, next_pc, halted);

        if (next_block_id != block_id) {
            cache_.Release(block_id);
            block = &cache_.Acquire(next_block_id);
        }
        block_id = next_block_id;
        pc = next_pc;
    }
    cache_.Release(block_id);
    return value_stack_.empty() ? 0 : value_stack_.back();
}

}  // namespace quark::vm
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cmake --build sandbox/build-host --target quark_vm_tests && ./sandbox/build-host/cpp/quark_vm/tests/quark_vm_tests`
Expected: all checks print `ok:`, including `interpreter computes (3+4)*2 == 14 via arithmetic + CALL_HOST` and the wrong-key checks; exit code 0.

- [ ] **Step 7: Commit**

```bash
git add cpp/quark_vm/include/quark/vm/host_function_table.hpp cpp/quark_vm/include/quark/vm/interpreter.hpp cpp/quark_vm/src/interpreter.cpp cpp/quark_vm/tests/quark_vm_test.cpp
git commit -m "Add HostFunctionTable and the Interpreter fetch-decode-execute loop"
```

---

### Task 6: `quark-vmasm` text assembler

**Files:**
- Create: `cpp/quark_vmasm/CMakeLists.txt`
- Create: `cpp/quark_vmasm/main.cpp`
- Modify: `CMakeLists.txt` (top-level)

Text format (one instruction per line inside a `block <id> [entry]` .. next `block` or EOF):
```
block 0 entry
  push 3
  push 4
  add
  halt
```
Mnemonics map 1:1 to `Opcode` names (`push <imm>`, `load <slot>`, `store <slot>`, `add`, `sub`, `mul`, `div`, `mod`, `and`, `or`, `xor`, `not`, `shl`, `shr`, `eq`, `lt`, `gt`, `jmp <block>`, `jz <block>`, `call <block>`, `callhost <id> <argc>`, `ret`, `halt`).

- [ ] **Step 1: Create the tool**

Create `cpp/quark_vmasm/main.cpp`:

```cpp
// quark-vmasm: dev/issuance-time text assembler for quark_vm programs.
// Usage: quark_vmasm <input.qvmasm> <output.qvm> <vm_key_hex>
//
// vm_key_hex is a 64-character hex string (32 bytes) -- in a real issuance
// pipeline this is quark::token::DeriveVmKey(content_key) for the target
// machine's expected content_key, printed as hex by whatever tool derives
// it. This tool has no notion of licenses or machines; it only assembles
// and seals.
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "quark/vm/opcode.hpp"
#include "quark/vm/program.hpp"

namespace {

std::optional<quark::crypto::AesKey> ParseHexKey(const std::string& hex) {
    if (hex.size() != 64) return std::nullopt;
    quark::crypto::AesKey key{};
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
        key[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return key;
}

const std::unordered_map<std::string, quark::vm::Opcode> kMnemonics = {
    {"push", quark::vm::Opcode::kPushI64},   {"load", quark::vm::Opcode::kLoadLocal},
    {"store", quark::vm::Opcode::kStoreLocal}, {"add", quark::vm::Opcode::kAdd},
    {"sub", quark::vm::Opcode::kSub},         {"mul", quark::vm::Opcode::kMul},
    {"div", quark::vm::Opcode::kDiv},         {"mod", quark::vm::Opcode::kMod},
    {"and", quark::vm::Opcode::kAnd},         {"or", quark::vm::Opcode::kOr},
    {"xor", quark::vm::Opcode::kXor},         {"not", quark::vm::Opcode::kNot},
    {"shl", quark::vm::Opcode::kShl},         {"shr", quark::vm::Opcode::kShr},
    {"eq", quark::vm::Opcode::kCmpEq},        {"lt", quark::vm::Opcode::kCmpLt},
    {"gt", quark::vm::Opcode::kCmpGt},        {"jmp", quark::vm::Opcode::kJmp},
    {"jz", quark::vm::Opcode::kJmpIfZero},    {"call", quark::vm::Opcode::kCall},
    {"callhost", quark::vm::Opcode::kCallHost}, {"ret", quark::vm::Opcode::kRet},
    {"halt", quark::vm::Opcode::kHalt},
};

std::optional<std::vector<quark::vm::Block>> Assemble(std::istream& in, uint32_t& entry_block_id) {
    std::vector<quark::vm::Block> blocks;
    quark::vm::Block* current = nullptr;
    bool have_entry = false;
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ls(line);
        std::string first;
        if (!(ls >> first)) continue;

        if (first == "block") {
            uint32_t id = 0;
            std::string maybe_entry;
            ls >> id;
            blocks.push_back(quark::vm::Block{id, {}});
            current = &blocks.back();
            if (ls >> maybe_entry && maybe_entry == "entry") {
                entry_block_id = id;
                have_entry = true;
            }
            continue;
        }
        if (current == nullptr) return std::nullopt;

        auto it = kMnemonics.find(first);
        if (it == kMnemonics.end()) return std::nullopt;
        quark::vm::Instruction instr;
        instr.op = it->second;
        ls >> instr.a;
        ls >> instr.b;
        current->instructions.push_back(instr);
    }
    if (!have_entry) return std::nullopt;
    return blocks;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage: quark_vmasm <input.qvmasm> <output.qvm> <vm_key_hex>\n";
        return 1;
    }
    std::ifstream in(argv[1]);
    if (!in) {
        std::cerr << "could not open input file: " << argv[1] << "\n";
        return 1;
    }
    auto vm_key = ParseHexKey(argv[3]);
    if (!vm_key) {
        std::cerr << "vm_key must be a 64-character hex string\n";
        return 1;
    }

    uint32_t entry_block_id = 0;
    auto blocks = Assemble(in, entry_block_id);
    if (!blocks) {
        std::cerr << "assembly failed: bad syntax, unknown mnemonic, or missing 'entry' block\n";
        return 1;
    }

    quark::vm::Program program;
    program.entry_block_id = entry_block_id;
    for (const auto& block : *blocks) {
        program.sealed_blocks[block.id] = quark::vm::SealBlock(*vm_key, block);
    }

    std::ofstream out(argv[2], std::ios::binary);
    if (!out) {
        std::cerr << "could not open output file: " << argv[2] << "\n";
        return 1;
    }
    auto serialized = quark::vm::SerializeProgram(program);
    out.write(reinterpret_cast<const char*>(serialized.data()), static_cast<std::streamsize>(serialized.size()));
    return 0;
}
```

Create `cpp/quark_vmasm/CMakeLists.txt`:

```cmake
# quark-vmasm: dev/issuance-time text assembler producing sealed .qvm
# programs for quark_vm. Not linked into any shipped runtime.
add_executable(quark_vmasm main.cpp)
target_link_libraries(quark_vmasm PRIVATE quark_vm)
```

- [ ] **Step 2: Wire into the top-level build**

In the top-level `CMakeLists.txt`, right after `add_subdirectory(cpp/quark_vm)`, add:

```cmake
add_subdirectory(cpp/quark_vmasm)
```

- [ ] **Step 3: Build it**

Run: `cmake -S . -B sandbox/build-host && cmake --build sandbox/build-host --target quark_vmasm`
Expected: builds successfully, producing `sandbox/build-host/cpp/quark_vmasm/quark_vmasm` (or `.exe` on Windows).

- [ ] **Step 4: Manually verify end-to-end (this doubles as the round-trip check; Task 7 automates it)**

```bash
cat > /tmp/quark_vmasm_test_program.qvmasm <<'EOF'
block 0 entry
  push 3
  push 4
  add
  halt
EOF
./sandbox/build-host/cpp/quark_vmasm/quark_vmasm \
  /tmp/quark_vmasm_test_program.qvmasm /tmp/quark_vmasm_test_program.qvm \
  0000000000000000000000000000000000000000000000000000000000000000
```
Expected: exits 0 and creates `/tmp/quark_vmasm_test_program.qvm` (a non-empty binary file). Note the key above is 66 hex chars by mistake if miscounted -- use exactly 64 zeros; verify with `python3 -c "print(len(open('/dev/stdin').read().strip()))" <<< 0000000000000000000000000000000000000000000000000000000000000000` before running if unsure.

- [ ] **Step 5: Commit**

```bash
git add cpp/quark_vmasm CMakeLists.txt
git commit -m "Add quark-vmasm text assembler tool"
```

---

### Task 7: End-to-end automated test tying assembler, sealing, and interpretation together

**Files:**
- Create: `cpp/quark_vm/tests/quark_vmasm_e2e_test.cpp`
- Modify: `cpp/quark_vm/tests/CMakeLists.txt`

This test assembles a program via `Assemble`-equivalent logic reused directly (not by shelling out to the built `quark_vmasm` binary, to keep the test hermetic and fast) -- it exercises the exact same `Program`/`BlockCache`/`Interpreter` types Tasks 3-5 built, proving they compose correctly end to end, including the "wrong key" property one more time against a slightly larger, branching program (to also prove `JMP`/`JMP_IF_ZERO`/`CALL`/`RET` work, not just straight-line arithmetic).

- [ ] **Step 1: Write the test**

Create `cpp/quark_vm/tests/quark_vmasm_e2e_test.cpp`:

```cpp
// End-to-end test: a program with a function call and a conditional branch,
// sealed and run through the real BlockCache + Interpreter. Proves control
// transfer between blocks (CALL/RET/JMP_IF_ZERO) works, and re-confirms the
// wrong-key property on a program that isn't pure straight-line arithmetic.

#include <cstdio>

#include "quark/crypto.hpp"
#include "quark/vm/block_cache.hpp"
#include "quark/vm/interpreter.hpp"
#include "quark/vm/program.hpp"

namespace {

int g_failures = 0;

void Check(bool condition, const char* what) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++g_failures;
    } else {
        std::printf("ok: %s\n", what);
    }
}

// block 0 (entry): push 10, call block 1, halt (result = whatever block 1 left on the stack)
// block 1: push 0, load_local unused; compare top-of-stack (the 10) to 5 via a copy trick --
//   simplified: push 5, cmp_gt (10 > 5 -> 1), jz block 2 (not taken), push 100, ret
// block 2: push -1, ret   (would run if 10 was NOT > 5)
quark::vm::Program BuildBranchingProgram(const quark::crypto::AesKey& vm_key) {
    quark::vm::Block entry;
    entry.id = 0;
    entry.instructions = {
        quark::vm::Instruction{quark::vm::Opcode::kPushI64, 10, 0},
        quark::vm::Instruction{quark::vm::Opcode::kCall, 1, 0},
        quark::vm::Instruction{quark::vm::Opcode::kHalt, 0, 0},
    };

    quark::vm::Block func;
    func.id = 1;
    func.instructions = {
        quark::vm::Instruction{quark::vm::Opcode::kPushI64, 5, 0},
        quark::vm::Instruction{quark::vm::Opcode::kCmpGt, 0, 0},   // pops 5 and 10 -> pushes (10>5)=1
        quark::vm::Instruction{quark::vm::Opcode::kJmpIfZero, 2, 0},
        quark::vm::Instruction{quark::vm::Opcode::kPushI64, 100, 0},
        quark::vm::Instruction{quark::vm::Opcode::kRet, 0, 0},
    };

    quark::vm::Block else_block;
    else_block.id = 2;
    else_block.instructions = {
        quark::vm::Instruction{quark::vm::Opcode::kPushI64, -1, 0},
        quark::vm::Instruction{quark::vm::Opcode::kRet, 0, 0},
    };

    quark::vm::Program program;
    program.entry_block_id = 0;
    program.sealed_blocks[0] = quark::vm::SealBlock(vm_key, entry);
    program.sealed_blocks[1] = quark::vm::SealBlock(vm_key, func);
    program.sealed_blocks[2] = quark::vm::SealBlock(vm_key, else_block);
    return program;
}

void TestBranchingProgramWithCorrectKey() {
    quark::crypto::AesKey vm_key{};
    auto random = quark::crypto::RandomBytes(32);
    std::copy(random.begin(), random.end(), vm_key.begin());

    auto program = BuildBranchingProgram(vm_key);
    quark::vm::BlockCache cache(vm_key, program, std::chrono::seconds(60));
    quark::vm::quark_vm_host_table_t host_table{nullptr, 0, nullptr};
    quark::vm::Interpreter interp(cache, host_table);

    int64_t result = interp.Run();
    Check(result == 100, "10 > 5 branch taken correctly: CALL into block 1, JMP_IF_ZERO not taken, RET with 100");
}

void TestBranchingProgramWithWrongKey() {
    quark::crypto::AesKey right_key{};
    auto r1 = quark::crypto::RandomBytes(32);
    std::copy(r1.begin(), r1.end(), right_key.begin());
    quark::crypto::AesKey wrong_key{};
    auto r2 = quark::crypto::RandomBytes(32);
    std::copy(r2.begin(), r2.end(), wrong_key.begin());

    auto program = BuildBranchingProgram(right_key);
    quark::vm::BlockCache cache(wrong_key, program, std::chrono::seconds(60));
    quark::vm::quark_vm_host_table_t host_table{nullptr, 0, nullptr};
    quark::vm::Interpreter interp(cache, host_table);

    int64_t result = interp.Run();
    Check(result != 100, "wrong vm_key does not reproduce the correct branching result");
}

}  // namespace

int main() {
    TestBranchingProgramWithCorrectKey();
    TestBranchingProgramWithWrongKey();

    if (g_failures > 0) {
        std::fprintf(stderr, "\n%d check(s) failed.\n", g_failures);
        return 1;
    }
    std::printf("\nall checks passed.\n");
    return 0;
}
```

- [ ] **Step 2: Register the new test binary**

Replace the contents of `cpp/quark_vm/tests/CMakeLists.txt`:

```cmake
add_executable(quark_vm_tests quark_vm_test.cpp)
target_link_libraries(quark_vm_tests PRIVATE quark_vm)
add_test(NAME quark_vm_tests COMMAND quark_vm_tests)

add_executable(quark_vmasm_e2e_test quark_vmasm_e2e_test.cpp)
target_link_libraries(quark_vmasm_e2e_test PRIVATE quark_vm)
add_test(NAME quark_vmasm_e2e_test COMMAND quark_vmasm_e2e_test)
```

- [ ] **Step 3: Run to verify it fails first, confirming the test is real**

Temporarily change the expected value in `TestBranchingProgramWithCorrectKey` from `100` to `999`, run:
Run: `cmake --build sandbox/build-host --target quark_vmasm_e2e_test && ./sandbox/build-host/cpp/quark_vm/tests/quark_vmasm_e2e_test`
Expected: `FAIL: 10 > 5 branch taken correctly...`. Revert the value back to `100`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cmake --build sandbox/build-host --target quark_vmasm_e2e_test && ./sandbox/build-host/cpp/quark_vm/tests/quark_vmasm_e2e_test`
Expected:
```
ok: 10 > 5 branch taken correctly: CALL into block 1, JMP_IF_ZERO not taken, RET with 100
ok: wrong vm_key does not reproduce the correct branching result

all checks passed.
```

- [ ] **Step 5: Run the full suite via ctest**

Run: `ctest --test-dir sandbox/build-host --output-on-failure`
Expected: `quark_core_tests`, `quark_vm_tests`, and `quark_vmasm_e2e_test` (plus every pre-existing test) all report `Passed`.

- [ ] **Step 6: Commit**

```bash
git add cpp/quark_vm/tests/quark_vmasm_e2e_test.cpp cpp/quark_vm/tests/CMakeLists.txt
git commit -m "Add end-to-end branching-program test for quark_vm"
```

---

### Task 8: Documentation

**Files:**
- Create: `cpp/quark_vm/README.md`
- Modify: `docs/PLAN.md`

- [ ] **Step 1: Write the module README**

Create `cpp/quark_vm/README.md`:

```markdown
# quark_vm

A small embedded bytecode interpreter whose blocks decrypt only under a key
derived from a real Quark license unlock (`quark::token::DeriveVmKey`,
applied to `content_key` from `quark_unlock_and_decrypt`). A wrong key does
not block execution -- it makes every block's decoded instructions wrong, so
the interpreter computes an incorrect result using the exact same code path
a legitimate run would use. See
[docs/superpowers/specs/2026-07-04-quark-vm-cryptographic-interlocking-design.md](../../docs/superpowers/specs/2026-07-04-quark-vm-cryptographic-interlocking-design.md)
for the full design rationale, including why this replaces raw native-code
runtime decryption for `quark_c_api` consumers.

## Layout

- `include/quark/vm/opcode.hpp`, `src/opcode.cpp` -- the instruction set and
  its fixed 24-byte encoding.
- `include/quark/vm/program.hpp`, `src/program.cpp` -- the `.qvm` container
  format and per-block sealing (`quark::payload::Seal`/`Unseal`).
- `include/quark/vm/block_cache.hpp`, `src/block_cache.cpp` -- decrypt on
  demand, ref-counted residency, idle-timeout wipe via `Sweep()`.
- `include/quark/vm/host_function_table.hpp` -- the C-ABI callback table an
  embedder fills in to expose native capabilities to `CALL_HOST`.
- `include/quark/vm/interpreter.hpp`, `src/interpreter.cpp` -- the
  fetch-decode-execute loop.

`tools/quark-vmasm` (a sibling to this module under `cpp/quark_vmasm`) is the
dev-time text assembler that produces `.qvm` files; it is never linked into
a shipped runtime.

## Zero OS dependency

Nothing in this module touches an OS API. It never marks memory executable
and never generates or modifies machine code -- bytecode is read as ordinary
data by ordinary interpreter code, which is what lets it build and be
genuinely, non-mock tested on any OS (CLAUDE.md rule 1) and sidesteps the
entire class of problems (W^X, code-signing, MAP_JIT entitlements) raw
native-code runtime decryption runs into.

## v1 scope

Single-threaded interpreter, a minimal integer-only opcode set, and a plain
text assembler -- see the design spec's "Non-goals" for what is deliberately
deferred (dispatch-table permutation hardening, a higher-level compiler,
multi-threaded execution, native machine-code virtualization).
```

- [ ] **Step 2: Update docs/PLAN.md**

Add a new phase section to `docs/PLAN.md`, immediately after the existing "Phase VIII" section (find the line starting with `### Explicitly deferred` under Phase VIII and insert this new `## Phase IX` heading after that entire subsection ends, i.e. right before the next `##` heading or end of file -- if Phase VIII is currently the last section in the file, append at the end):

```markdown
## Phase IX — Quark VM: cryptographically interlocked protected logic
Implements docs/superpowers/specs/2026-07-04-quark-vm-cryptographic-
interlocking-design.md and docs/superpowers/plans/2026-07-04-quark-vm-
implementation.md.

- [x] `quark::token::DeriveVmKey` -- domain-separated key derived from
      `content_key`, following the exact convention every other Derive*
      function in `quark/token.hpp` already uses.
- [x] `cpp/quark_vm` -- new, OS-independent static library: fixed 24-byte
      instruction encoding, a `.qvm` program container (sealed per block,
      never decrypted as a whole), `BlockCache` (decrypt-on-demand,
      ref-counted residency, idle-timeout wipe via `Sweep()`, and a fixed
      poison placeholder on any decrypt authentication failure -- no branch
      on success/failure, only a data substitution), a C-ABI
      `quark_vm_host_table_t` for CALL_HOST, and a stack-machine
      `Interpreter`.
- [x] `cpp/quark_vmasm` -- dev/issuance-time text assembler producing sealed
      `.qvm` files. Not linked into any shipped runtime.
- [x] Real, non-mocked, deterministic tests throughout (this module has zero
      OS dependency, so unlike most platform-layer work in this repo,
      nothing here needed a real-OS test environment to be genuinely
      tested) -- including an explicit "wrong key produces a wrong result,
      not a crash or a blocked branch" check, which is the property the
      whole design exists to prove.

### Explicitly not done yet (do not claim otherwise)
- `HostFunctionTable`'s C-ABI shape is defined and used internally, but it
  is not yet wired into `cpp/quark_c_api`'s public header -- a Go/Python
  host cannot yet actually supply one through `quark_c_api.h`. Tracked as
  the natural next step once this module is verified end to end.
- No dispatch-table permutation or other bytecode-obfuscation hardening
  (explicitly deferred in the design spec).
- No higher-level compiler targeting quark_vm -- `quark-vmasm`'s text format
  is hand-written only.
- Not yet built or tested on Linux/Windows in this session -- verify on
  those platforms the same way every other quark_core-adjacent module in
  this repo has been (see "Cross-platform build & test strategy" in
  CLAUDE.md) before relying on the cross-platform claim in practice.
```

- [ ] **Step 3: Commit**

```bash
git add cpp/quark_vm/README.md docs/PLAN.md
git commit -m "Document quark_vm module and record Phase IX in the plan"
```

---

## Self-review notes (from writing this plan)

- **Spec coverage:** Architecture (Task 2-5), bytecode format (Task 2),
  cryptographic interlocking mechanism (Task 1, 4), data flow (Task 6-7),
  cross-platform story (all tasks -- zero OS code, verified by building on
  the host OS available during implementation; the spec's Linux/Windows
  claim is cross-platform *by construction*, not yet independently verified
  on those OSes in this plan -- flagged in Task 8's PLAN.md update rather
  than glossed over), testing strategy (Tasks 2-7 each include real tests),
  anti-boolean-trap discipline (Task 4's poison-on-failure design, Task 5 and
  7's explicit wrong-key tests). The two "Open items" from the spec
  (`HostFunctionTable`'s C ABI shape, `.qvm` container format) are resolved
  concretely in Tasks 3 and 5 rather than left open.
- **Placeholder scan:** no TBD/TODO; every step has complete, runnable code.
- **Type consistency:** `Instruction`, `Opcode`, `Program`, `Block`,
  `BlockCache`, `Interpreter`, `quark_vm_host_table_t` are defined once (in
  the tasks that create them) and used identically (same field/method names)
  in every later task.
- **Not covered by this plan, deliberately:** wiring `HostFunctionTable`
  into `quark_c_api.h`'s public surface, so a Go/Python host can actually
  supply one. This plan only proves the interpreter/crypto mechanism itself
  end to end in C++; exposing it across the C boundary is naturally-scoped
  follow-up work, not a gap in this plan's own stated goal.
