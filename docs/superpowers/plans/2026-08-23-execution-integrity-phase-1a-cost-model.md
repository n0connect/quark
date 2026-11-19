# Execution Integrity Phase 1A Cost-Model Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Select or reject a production-shaped macOS ARM64 critical-region evidence mechanism using separated, reproducible cost and completeness measurements.

**Architecture:** Build a new independent measurement repository under `sandbox/eip-phase1a` and preserve the completed Phase 0 spike unchanged. One shared workload library is linked into baseline, automaton-only, automaton-plus-summary, ordered-ring, inline-counter, and gated-callback variants; a parent runner calibrates real workload duration and randomizes fresh-process execution, and a strict analyzer separates decision, evidence, finalize, serialization, memory, and binary-size costs before applying fixed gates.

**Tech Stack:** C++17, CMake 3.20+, Apple Clang 21, CTest, pthreads, Apple Clang SanitizerCoverage capability probes, POSIX `posix_spawn`, real filesystem/process/thread behavior, no external runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-08-23-execution-integrity-platform-v2-design.md`

## Global Constraints

- This is measurement software, not enforcement or attestation. Every report carries `claim_level=measurement`.
- All newly created source, builds, tests, child processes, traces, and scratch
  state stay under `sandbox/eip-phase1a`; no system temporary directory is used.
  The real Quark fixture may compile the read-only production
  `cpp/common/src/crypto.cpp` and `lamport.cpp` directly, but records their
  SHA-256 digests and emits every generated artifact under the Phase 1A sandbox.
- Initialize `sandbox/eip-phase1a` as an independent nested Git repository. Do not add Phase 1A source to Quark's outer repository.
- Use real macOS ARM64 compiler, threads, process spawning, filesystem, and instrumentation. No mocks, fake trace producers, or synthetic success capabilities.
- The existing `sandbox/eip-phase0` repository and its evidence remain read-only reference material.
- Configuration rejects unknown, duplicate, missing, absolute-path, parent-traversal, zero, and overflow values.
- The timed operation performs no filesystem I/O. Finalization, drain, serialization, and file write have separate timers.
- No candidate may allocate, lock, perform a syscall, write a file, access the network, symbolize, or perform cryptography per hot-path event.
- Baseline and candidate binaries compile the exact same workload source with Release optimization; instrumentation flags are the only candidate-specific workload difference.
- Every unavailable compiler/platform feature produces a typed capability record and an omitted benchmark mode, never a substitute implementation labeled as the missing feature.
- Calibrate each baseline workload once to a 50 ms target round and freeze that iteration count for every candidate; reject a calibration below 20 ms or above 100 ms.
- Each workload/mode uses ten fresh child processes, five warmup rounds, and 50 measured rounds. The parent randomizes process-level mode order from a checked-in seed.
- Report raw samples, process-cluster p50/p95/p99, hierarchical-bootstrap 95% confidence intervals, binary size, post-warmup RSS delta, lifetime peak RSS, evidence bytes, event count, gaps, and result mismatches.
- Never discard outliers. A failed/gap/mismatched sample fails its candidate rather than disappearing from statistics.
- An environmental preflight records host/toolchain/power/load state and blocks the matrix when baseline process-level coefficient of variation exceeds 5%; it never retries automatically to hunt for a favorable sample.
- Phase 1C is blocked unless automaton-only passes p95 <= 5%, p99 <= 8%, zero
  mismatch, and transition-state correctness on every required workload. The
  later Phase 1C plan must still prove build-time effect mediation; Phase 1A
  makes no such claim. Phase 1D is independently blocked unless
  automaton-plus-summary passes its default completeness/cost gate. Phase 1B
  artifact-only work may proceed for one bounded optimization iteration only
  under Task 11's limitation rule.

## File and responsibility map

```text
sandbox/eip-phase1a/
  CMakeLists.txt                         target graph and real capability probes
  .gitignore                            build/test/run/results exclusions
  README.md                             measurement-only use and commands
  config/phase1a.conf                   all tunable counts, limits, seed, paths
  include/ei/measure/config.hpp         strict Config contract
  include/ei/measure/types.hpp          candidate, metric, capability types
  include/ei/measure/automaton.hpp      deterministic transition-state API
  include/ei/measure/evidence.hpp       bounded summary and ordered-ring APIs
  include/ei/measure/coverage.hpp       inline/gated coverage registration API
  include/ei/measure/workloads.hpp      common workload contract
  include/ei/measure/quark_fixture.hpp  real Lamport fixture contract
  include/ei/measure/sample.hpp         stable binary sample codec
  src/config.cpp                        strict parser
  src/automaton.cpp                     automaton-only decision candidate
  src/evidence.cpp                      summary and ordered-ring candidates
  src/coverage.cpp                      real SanitizerCoverage callbacks/counters
  src/workloads.cpp                     identical deterministic workloads
  src/quark_fixture.cpp                 adapter over real Quark Lamport source
  src/sample.cpp                        sample validation and codec
  apps/candidate_main.cpp               one child-process benchmark execution
  apps/runner_main.cpp                  randomized posix_spawn orchestration
  apps/analyze_main.cpp                 statistics, attribution, fixed gate result
  cmake/probe_gated_callbacks.cmake     actual compiler capability check
  cmake/measure_release_build.cmake     clean configure/build wall-cost capture
  tests/config_test.cpp                 parser rejection matrix
  tests/sample_test.cpp                 codec corruption and range tests
  tests/workload_test.cpp               real deterministic workload equivalence
  tests/automaton_test.cpp              transition-state correctness and cost rules
  tests/evidence_test.cpp               summary/ring order/count/gap behavior
  tests/coverage_test.cpp               real counter/callback registration
  tests/runner_test.cmake               real child ordering and failure propagation
  tests/analyzer_test.cpp               strict statistics and decision rules
  tests/stability_test.cmake            clean-build/ASLR/DSO/thread/crash cases
  tests/e2e_test.cmake                  small real measurement matrix
  results/release/                      ignored raw and summarized evidence
```

---

### Task 1: Establish the independent repository and strict experiment contract

**Files:**
- Create: `sandbox/eip-phase1a/.gitignore`
- Create: `sandbox/eip-phase1a/CMakeLists.txt`
- Create: `sandbox/eip-phase1a/README.md`
- Create: `sandbox/eip-phase1a/config/phase1a.conf`
- Create: `sandbox/eip-phase1a/include/ei/measure/config.hpp`
- Create: `sandbox/eip-phase1a/include/ei/measure/types.hpp`
- Create: `sandbox/eip-phase1a/src/config.cpp`
- Create: `sandbox/eip-phase1a/tests/config_test.cpp`
- Create: `sandbox/eip-phase1a/cmake/probe_gated_callbacks.cmake`
- Create: `sandbox/eip-phase1a/cmake/measure_release_build.cmake`

**Interfaces:**
- Produces: `ei::measure::Config`, `CandidateMode`, `WorkloadKind`, `Capability`, and a generated `capabilities.txt`.
- Consumes: only the checked-in key/value config and the real Apple Clang toolchain.

- [ ] **Step 1: Initialize the nested repository and write the failing parser test**

Run `git init sandbox/eip-phase1a`, then define the test around this exact API:

```cpp
namespace ei::measure {
enum class CandidateMode : uint16_t { kBaseline=0, kAutomaton=1,
                                      kAutomatonSummary=2, kOrderedRing=3,
                                      kInlineCounter=4, kGatedCallback=5 };
enum class WorkloadKind : uint16_t { kBranch=0, kCallReturn=1, kAllocation=2,
                                     kLongLivedThreads=3, kShortLivedThreads=4,
                                     kQuarkLamport=5 };
enum class EvidenceSemantics : uint8_t { kNone=0, kOrdered=1,
                                         kTransitionSummary=2,
                                         kUnorderedCoverage=3 };
enum class CapabilityState : uint8_t { kSupported=1, kUnavailable=2 };
struct Capability {
    std::string name;
    CapabilityState state;
    std::string reason;
};
struct Config {
    size_t iterations;
    size_t threads;
    size_t warmup_rounds;
    size_t measured_rounds;
    size_t child_processes;
    size_t calibration_rounds;
    size_t calibration_max_steps;
    size_t evidence_capacity_per_worker;
    uint64_t target_round_ns;
    uint64_t target_tolerance_ns;
    uint64_t minimum_round_ns;
    uint64_t maximum_round_ns;
    uint32_t environment_cv_limit_basis_points;
    uint64_t schedule_seed;
    size_t bootstrap_resamples;
    std::filesystem::path output_dir;
};
std::optional<Config> LoadConfig(const std::filesystem::path& path);
}
```

`config_test.cpp` writes only working-directory-relative files and asserts one
valid config plus rejection of every unknown, duplicate, missing, zero,
overflow, absolute, and `..` output value.

- [ ] **Step 2: Run the test and observe the missing implementation failure**

```bash
cmake -S sandbox/eip-phase1a -B sandbox/eip-phase1a/build -DCMAKE_BUILD_TYPE=Release
cmake --build sandbox/eip-phase1a/build --target ei_config_test --parallel
```

Expected: link failure naming `ei::measure::LoadConfig`.

- [ ] **Step 3: Implement the strict parser and checked-in config**

Use exact keys and values:

```text
iterations=200000
threads=4
warmup_rounds=5
measured_rounds=50
child_processes=10
calibration_rounds=11
calibration_max_steps=6
evidence_capacity_per_worker=1048576
target_round_ns=50000000
target_tolerance_ns=5000000
minimum_round_ns=20000000
maximum_round_ns=100000000
environment_cv_limit_basis_points=500
schedule_seed=7640891576956012809
bootstrap_resamples=10000
output_dir=results
```

Parsing uses `std::from_chars`, range-checks conversion to `size_t`, and accepts
no whitespace aliases or implicit defaults. `Config` values, not source
constants, drive all experiment counts.

- [ ] **Step 4: Probe real compiler features at configure time**

`probe_gated_callbacks.cmake` uses `try_compile` on a real source defining
`__sanitizer_cov_trace_pc_guard` and these flags:

```text
-fsanitize-coverage=bb,no-prune,trace-pc-guard
-mllvm
-sanitizer-coverage-gated-trace-callbacks
```

Write `gated_callbacks=supported` only when the compile and link both succeed;
otherwise write `gated_callbacks=unavailable`. Also write
`xray_fdr=unavailable_on_darwin` without attempting to manufacture an XRay
runtime, matching LLVM's documented platform list.

`measure_release_build.cmake` requires `SOURCE_DIR`, `BUILD_DIR`, and
`OUTPUT_FILE`; rejects missing, absolute-escape, pre-existing build/output, and
in-tree-source destinations; invokes configure/build with `execute_process`
argument arrays wrapped by `cmake -E time`; parses exactly one finite positive
elapsed-seconds value for each; and writes one key/value evidence file only
after both commands succeed.

- [ ] **Step 5: Build, test, and commit**

```bash
cmake --build sandbox/eip-phase1a/build --parallel
ctest --test-dir sandbox/eip-phase1a/build -R ei_config --output-on-failure
git -C sandbox/eip-phase1a add .gitignore CMakeLists.txt README.md config include src/config.cpp tests/config_test.cpp cmake
git -C sandbox/eip-phase1a commit -m "Define the phase 1A experiment contract"
```

Expected: parser test passes and `build/capabilities.txt` reports the actual
compiler result.

---

### Task 2: Define a strictly validated raw sample format

**Files:**
- Create: `sandbox/eip-phase1a/include/ei/measure/sample.hpp`
- Create: `sandbox/eip-phase1a/src/sample.cpp`
- Create: `sandbox/eip-phase1a/tests/sample_test.cpp`
- Modify: `sandbox/eip-phase1a/CMakeLists.txt`

**Interfaces:**
- Consumes: `CandidateMode`, `WorkloadKind` from Task 1.
- Produces: `WriteSampleFile`/`ReadSampleFile` plus a separate process-cost codec.

- [ ] **Step 1: Write failing round-trip and corruption tests**

Define these exact records:

```cpp
struct SampleHeader {
    uint64_t schedule_seed;
    uint32_t process_index;
    CandidateMode mode;
    WorkloadKind workload;
};
struct MetricSample {
    uint32_t round;
    uint64_t operation_ns;
    uint64_t finalize_ns;
    uint64_t result;
    uint64_t decision_events;
    uint64_t evidence_events;
    uint64_t evidence_bytes;
    uint64_t violations;
    bool lifecycle_ok;
    bool gap;
};
struct ProcessCosts {
    uint64_t candidate_init_ns;
    uint64_t workload_init_ns;
    uint64_t encode_ns;
    uint64_t sample_write_ns;
    uint64_t configured_buffer_bytes;
    uint64_t rss_post_init_bytes;
    uint64_t rss_post_warmup_bytes;
    uint64_t rss_post_run_bytes;
    uint64_t peak_rss_bytes;
    uint64_t sample_file_bytes;
};
```

Tests require round-trip equality and rejection of wrong magic/version, invalid
enum, nonconsecutive round, zero operation time, truncated/extra bytes,
impossible booleans, and count/size overflow.

- [ ] **Step 2: Run and verify red**

```bash
cmake --build sandbox/eip-phase1a/build --target ei_sample_test --parallel
```

Expected: missing `WriteSampleFile`/`ReadSampleFile` symbols.

- [ ] **Step 3: Implement a fixed little-endian codec**

Use `EIM1`, version `1`, a fixed header, a declared sample count, and fixed-size
records. `EIC1` version `1` encodes exactly one `ProcessCosts` record in a
separate file, because the sample-file write duration is only known after that
file closes. Require exactly `measured_rounds` at the analyzer boundary; the
sample codec itself permits `1..100000` records so unit tests can remain small.
Do not use native struct serialization or trust padding.

- [ ] **Step 4: Run focused tests and commit**

```bash
cmake --build sandbox/eip-phase1a/build --parallel
ctest --test-dir sandbox/eip-phase1a/build -R ei_sample --output-on-failure
git -C sandbox/eip-phase1a add CMakeLists.txt include/ei/measure/sample.hpp src/sample.cpp tests/sample_test.cpp
git -C sandbox/eip-phase1a commit -m "Add strict phase 1A sample evidence"
```

---

### Task 3: Build six deterministic workloads including a real Quark fixture

**Files:**
- Create: `sandbox/eip-phase1a/include/ei/measure/workloads.hpp`
- Create: `sandbox/eip-phase1a/include/ei/measure/quark_fixture.hpp`
- Create: `sandbox/eip-phase1a/src/workloads.cpp`
- Create: `sandbox/eip-phase1a/src/quark_fixture.cpp`
- Create: `sandbox/eip-phase1a/tests/workload_test.cpp`
- Modify: `sandbox/eip-phase1a/CMakeLists.txt`

**Interfaces:**
- Consumes: `Config`, `WorkloadKind`.
- Produces: `WorkloadPool::Run`, `QuarkLamportFixture::Run`, and a candidate hook.

- [ ] **Step 1: Write the failing workload-equivalence test**

Use this contract:

```cpp
using SiteHook = void (*)(uint64_t site_id) noexcept;
struct InstrumentationHooks {
    SiteHook site;
    bool (*thread_enter)(uint32_t stable_worker_index) noexcept;
    void (*thread_exit)() noexcept;
};
struct WorkloadResult {
    uint64_t value;
    bool instrumentation_lifecycle_ok;
};
class WorkloadPool {
public:
    WorkloadPool(size_t threads, size_t iterations,
                 InstrumentationHooks hooks);
    ~WorkloadPool();
    WorkloadResult Run(WorkloadKind kind, uint32_t logical_round);
    WorkloadPool(const WorkloadPool&) = delete;
    WorkloadPool& operator=(const WorkloadPool&) = delete;
};
```

Construct workers once. Test every workload at threads `1`, `2`, and `4`, run
it twice, and require the same result with a null hook and a counting hook.
Verify worker thread IDs remain constant across rounds for
`kLongLivedThreads`; verify `kShortLivedThreads` intentionally creates and joins
threads as its workload behavior. In both cases require exactly one successful
`thread_enter(index)`/`thread_exit()` pair per real worker lifetime; duplicate
concurrent ownership of an index fails the workload rather than silently
sharing a slot.

- [ ] **Step 2: Run and verify red**

```bash
cmake --build sandbox/eip-phase1a/build --target ei_workload_test --parallel
```

Expected: missing `WorkloadPool` symbols.

- [ ] **Step 3: Implement the six workloads**

Implement distinct deterministic kernels:

```cpp
uint64_t BranchKernel(uint64_t begin, uint64_t count, SiteHook);
uint64_t CallReturnKernel(uint64_t seed, uint32_t depth, SiteHook);
uint64_t AllocationKernel(uint64_t begin, uint64_t count, SiteHook);
uint64_t LongLivedThreadKernel(uint64_t begin, uint64_t count, SiteHook);
uint64_t ShortLivedThreadKernel(uint64_t begin, uint64_t count, SiteHook);
uint64_t QuarkLamportKernel(uint64_t begin, uint64_t count, SiteHook);
```

The hook fires at the same semantically named sites in all candidate builds.
Site IDs are explicit constants in the test fixture only: `0x1001`, `0x1002`,
`0x2001`, `0x3001`, `0x4001`, plus `0x5001`/`0x5002` immediately before/after
the real Quark Lamport verification call. Allocation workload memory is owned
by the workload and occurs equally in baseline and candidates. Worker barriers
are outside the kernel's internal timed interval.

`QuarkLamportFixture` constructs 256 valid preimage/anchor pairs before warmup,
then `Run` selects among them deterministically and calls the production
`quark::lamport::VerifyStep` for every iteration. The Phase 1A CMake target
compiles the exact read-only `cpp/common/src/crypto.cpp` and `lamport.cpp`, uses
the production headers, links the same pinned mbedTLS 3.6.2 sources, and writes
the two Quark source SHA-256 values to `build/quark-fixture-digests.txt`.
Nothing is copied or reimplemented as a benchmark facsimile, and all dependency
downloads/build products stay under `sandbox/eip-phase1a/build/_deps`.

- [ ] **Step 4: Prove there is no filesystem work in `Run`**

The test records the working-directory file list before and after 100 `Run`
calls and requires equality. It also runs under TSan in the later sanitizer
gate; do not add a fake filesystem facade.

- [ ] **Step 5: Test and commit**

```bash
cmake --build sandbox/eip-phase1a/build --parallel
ctest --test-dir sandbox/eip-phase1a/build -R ei_workload --output-on-failure
git -C sandbox/eip-phase1a add CMakeLists.txt include/ei/measure/workloads.hpp include/ei/measure/quark_fixture.hpp src/workloads.cpp src/quark_fixture.cpp tests/workload_test.cpp
git -C sandbox/eip-phase1a commit -m "Add persistent real measurement workloads"
```

---

### Task 4: Implement the deterministic automaton-only candidate

**Files:**
- Create: `sandbox/eip-phase1a/include/ei/measure/automaton.hpp`
- Create: `sandbox/eip-phase1a/src/automaton.cpp`
- Create: `sandbox/eip-phase1a/tests/automaton_test.cpp`
- Create: `sandbox/eip-phase1a/tests/automaton_assembly_test.cmake`
- Modify: `sandbox/eip-phase1a/CMakeLists.txt`

**Interfaces:**
- Consumes: `WorkloadKind` and the workload `SiteHook`.
- Produces: a bounded, allocation-free deterministic transition decision with no raw evidence storage.

- [ ] **Step 1: Write failing transition and ownership tests**

Use this API:

```cpp
enum class AutomatonState : uint8_t { kIdle=0, kEntered=1,
                                      kAuthorized=2, kCommitted=3, kDone=4 };
enum class TransitionStatus : uint8_t { kAdvanced=0, kInvalidSite=1,
                                        kInvalidState=2, kWrongThread=3,
                                        kPoolExhausted=4, kNotActive=5 };
struct AutomatonSnapshot {
    uint64_t decision_events;
    uint64_t violations;
    AutomatonState final_state;
    bool pool_exhausted;
};
bool ConfigureAutomata(size_t worker_slots) noexcept;
bool RegisterAutomatonThread(uint32_t stable_worker_index) noexcept;
bool UnregisterAutomatonThread() noexcept;
bool BeginAutomatonRound(WorkloadKind workload) noexcept;
TransitionStatus AdvanceAutomatonSite(uint64_t site_id) noexcept;
AutomatonSnapshot FinalizeAutomatonRound() noexcept;
```

Tests use real worker threads and a checked-in transition table for all five
workloads. Require acceptance of every valid sequence and rejection of a
skipped, duplicated, reordered, unknown, post-finalize, and wrong-thread site.
Require deterministic aggregation by stable worker index, exhaustion to fail
closed, and zero heap allocations during 10,000 valid transitions. The test
executable may count calls to its real global allocator; it may not replace the
allocator or OS behavior.

- [ ] **Step 2: Run and verify red**

```bash
cmake --build sandbox/eip-phase1a/build --target ei_automaton_test --parallel
```

Expected: missing automaton symbols.

- [ ] **Step 3: Implement the minimal deterministic state machine**

Allocate one state slot per configured worker before measurement. Registration
binds a real thread to an explicit construction index; arrival order is never
identity. `BeginAutomatonRound` initializes the workload's fixed transition
table outside the timed region. `AdvanceAutomatonSite` performs only TLS slot
lookup, expected-site comparison, state advance, and violation count. It does
not append a record, hash, allocate, lock, call the kernel, or recover from an
invalid transition. Finalization aggregates only counters and terminal states
after workers leave the timed kernel.

- [ ] **Step 4: Record bounded code-generation evidence**

The CTest script runs `otool -tvV` on `AdvanceAutomatonSite` and `nm -u` on the
automaton object, storing both under `test-work/automaton-codegen/`. Fail on
known allocator, mutex, filesystem, network, clock, or crypto dependencies and
correlate that audit with the runtime allocation counter. State explicitly in
the generated evidence that disassembly and undefined-symbol inspection are
bounded evidence, not proof that arbitrary machine code can never issue an
inline syscall.

- [ ] **Step 5: Test and commit**

```bash
cmake --build sandbox/eip-phase1a/build --parallel
ctest --test-dir sandbox/eip-phase1a/build -R ei_automaton --output-on-failure
git -C sandbox/eip-phase1a add CMakeLists.txt include/ei/measure/automaton.hpp src/automaton.cpp tests/automaton_test.cpp tests/automaton_assembly_test.cmake
git -C sandbox/eip-phase1a commit -m "Measure deterministic transition decisions"
```

---

### Task 5: Implement bounded summary and ordered-ring evidence candidates

**Files:**
- Create: `sandbox/eip-phase1a/include/ei/measure/evidence.hpp`
- Create: `sandbox/eip-phase1a/src/evidence.cpp`
- Create: `sandbox/eip-phase1a/tests/evidence_test.cpp`
- Create: `sandbox/eip-phase1a/tests/evidence_assembly_test.cmake`
- Modify: `sandbox/eip-phase1a/CMakeLists.txt`

**Interfaces:**
- Consumes: the workload `SiteHook` and stable worker registration used by Task 4.
- Produces: separate transition-summary and ordered-ring snapshots without changing the automaton's decision semantics.

- [ ] **Step 1: Write failing semantics, concurrency, and overflow tests**

Define:

```cpp
enum class EvidenceMode : uint8_t { kTransitionSummary=0, kOrderedRing=1 };
struct EvidenceSnapshot {
    uint64_t evidence_events;
    uint64_t evidence_bytes;
    uint64_t measurement_hash;
    uint64_t ring_records;
    bool gap;
    EvidenceSemantics semantics;
};
bool ConfigureEvidence(size_t worker_slots,
                       size_t per_worker_ring_capacity) noexcept;
bool RegisterEvidenceThread(uint32_t stable_worker_index) noexcept;
bool UnregisterEvidenceThread() noexcept;
void BeginEvidenceRound(EvidenceMode mode) noexcept;
void RecordEvidenceSite(uint64_t site_id) noexcept;
EvidenceSnapshot FinalizeEvidenceRound() noexcept;
```

The summary test requires exact event count, order-sensitive fixed-state
`measurement_hash`, zero raw ring records, and `kTransitionSummary`. The ring
test requires exact `{worker_index, sequence, site_id}` records, deterministic
worker-index aggregation, and `kOrdered`. Both modes must allocate zero bytes in
the hot loop. Capacity+1 sets `gap=true`, preserves the last complete prefix,
and never invents or overwrites a record.

- [ ] **Step 2: Run and verify red**

```bash
cmake --build sandbox/eip-phase1a/build --target ei_evidence_test --parallel
```

- [ ] **Step 3: Implement the two evidence mechanisms independently**

The summary candidate keeps only fixed-size per-worker event count, last site,
transition counters for the fixture's checked-in stable-site table, and a clearly labeled
non-cryptographic `measurement_hash`; it is not a replay trace. The ordered ring
uses arrays allocated by `ConfigureEvidence` and a monotonically increasing
per-worker sequence. Neither mechanism performs dynamic site discovery. Begin,
drain, and cross-worker aggregation remain outside the timed operation.

- [ ] **Step 4: Audit evidence hot-path code generation**

Run the same bounded `otool` plus `nm -u` audit used for the automaton against
both summary and ring specializations of `RecordEvidenceSite`, and correlate it
with runtime allocation counts. Known allocator, mutex, syscall, clock, file,
network, and crypto dependencies fail the mode; the report retains the same
explicit “bounded evidence, not arbitrary-machine-code proof” caveat.

- [ ] **Step 5: Test and commit**

```bash
cmake --build sandbox/eip-phase1a/build --parallel
ctest --test-dir sandbox/eip-phase1a/build -R ei_evidence --output-on-failure
git -C sandbox/eip-phase1a add CMakeLists.txt include/ei/measure/evidence.hpp src/evidence.cpp tests/evidence_test.cpp tests/evidence_assembly_test.cmake
git -C sandbox/eip-phase1a commit -m "Separate bounded summaries from ordered evidence"
```

---

### Task 6: Implement unordered inline-counter and conditional gated-callback diagnostics

**Files:**
- Create: `sandbox/eip-phase1a/include/ei/measure/coverage.hpp`
- Create: `sandbox/eip-phase1a/src/coverage.cpp`
- Create: `sandbox/eip-phase1a/tests/coverage_test.cpp`
- Modify: `sandbox/eip-phase1a/CMakeLists.txt`

**Interfaces:**
- Consumes: real SanitizerCoverage-generated counter/PC tables and guard callbacks.
- Produces: `CoverageSnapshot` plus typed capability state for each candidate.

- [ ] **Step 1: Write the failing real-instrumentation tests**

Define:

```cpp
struct CoverageSnapshot {
    uint64_t instrumented_sites;
    uint64_t touched_sites;
    uint64_t callback_events;
    bool counter_saturated;
    bool gap;
    EvidenceSemantics semantics;
};
void BeginCoverageRound() noexcept;
CoverageSnapshot FinalizeCoverageRound() noexcept;
```

The inline-counter test binary is itself compiled with
`-fsanitize-coverage=bb,no-prune,inline-8bit-counters,pc-table` and requires real
counter/PC registration. It asserts `kUnorderedCoverage` and never treats the
counter sum as an exact ordered event count.

The gated target is added only when Task 1's `try_compile` succeeded. Its test
requires callbacks to remain zero while the compiler gate is off, become
nonzero while on, and stop increasing after off. If unavailable, CTest verifies
the capability file and does not create a passing substitute target.

- [ ] **Step 2: Run and verify red**

```bash
cmake --build sandbox/eip-phase1a/build --target ei_inline_counter_test --parallel
ctest --test-dir sandbox/eip-phase1a/build -R 'ei_(inline|gated)' --output-on-failure
```

- [ ] **Step 3: Implement real runtime registration and snapshots**

Provide the compiler callbacks with `no_sanitize("coverage")`:

```cpp
extern "C" void __sanitizer_cov_8bit_counters_init(char* begin, char* end);
extern "C" void __sanitizer_cov_pcs_init(const uintptr_t* begin,
                                         const uintptr_t* end);
extern "C" void __sanitizer_cov_trace_pc_guard_init(uint32_t* begin,
                                                    uint32_t* end);
extern "C" void __sanitizer_cov_trace_pc_guard(uint32_t* guard);
```

Validate matching counter/PC-table lengths and reject multiple overlapping
registrations. Counter reset and snapshot happen outside the timed operation.
Gated callbacks use the compiler's real gate symbol/behavior discovered by the
probe; a source-level `if` inside an always-invoked callback is not relabeled as
compiler-gated tracing.

- [ ] **Step 4: Audit generated diagnostic hot paths**

For inline counters, inspect the instrumented workload and require direct
counter increments with no per-event runtime call. For gated callbacks, inspect
both the compiler-emitted guarded call site and
`__sanitizer_cov_trace_pc_guard`; fail on known allocation, lock, clock,
filesystem, network, or crypto dependencies. Store evidence under
`test-work/coverage-codegen/` and preserve typed unavailability.

- [ ] **Step 5: Test and commit**

```bash
cmake --build sandbox/eip-phase1a/build --parallel
ctest --test-dir sandbox/eip-phase1a/build -R 'ei_(inline|gated)' --output-on-failure
git -C sandbox/eip-phase1a add CMakeLists.txt include/ei/measure/coverage.hpp src/coverage.cpp tests/coverage_test.cpp
git -C sandbox/eip-phase1a commit -m "Measure native coverage candidates honestly"
```

---

### Task 7: Build the child benchmark with separated decision and evidence timers

**Files:**
- Create: `sandbox/eip-phase1a/include/ei/measure/candidate.hpp`
- Create: `sandbox/eip-phase1a/apps/candidate_main.cpp`
- Create: `sandbox/eip-phase1a/tests/candidate_test.cmake`
- Modify: `sandbox/eip-phase1a/CMakeLists.txt`

**Interfaces:**
- Consumes: `Config`, workloads, candidates, and sample codec.
- Produces: `ei_baseline`, `ei_automaton`, `ei_automaton_summary`,
  `ei_ordered_ring`, `ei_inline_counter`, and optionally `ei_gated_callback`.

- [ ] **Step 1: Write the failing child-process integration test**

Define the adapter consumed by the shared child executable:

```cpp
struct CandidateSnapshot {
    uint64_t decision_events;
    uint64_t evidence_events;
    uint64_t evidence_bytes;
    uint64_t violations;
    bool gap;
    EvidenceSemantics semantics;
};
struct CandidateAdapter {
    CandidateMode mode;
    InstrumentationHooks hooks;
    bool (*initialize)(size_t worker_slots,
                       size_t evidence_capacity_per_worker) noexcept;
    bool (*begin_round)(WorkloadKind) noexcept;
    CandidateSnapshot (*finalize_round)() noexcept;
};
const CandidateAdapter& ActiveCandidate() noexcept;
```

Each binary supplies one adapter selected at compile time and links only its
real candidate runtime. Baseline uses a null site hook, no-op successful thread
lifecycle hooks, and a zero-evidence adapter; it
does not link the automaton, evidence, or SanitizerCoverage runtime.
`ei_automaton_summary` and `ei_ordered_ring` execute the same automaton decision
first and then record their respective evidence through one composed hook. A
decision violation prevents the evidence call and remains visible in
`violations`; evidence never converts a rejected transition into success.

Invoke each built candidate with:

```text
--config config/phase1a.conf
--workload branch|call-return|allocation|long-lived-threads|short-lived-threads|quark-lamport
--process-index 0
--iterations 400000
--output samples.eim
--cost-output process.eic
```

Require 50 records for the release config, identical `result` values across
modes, no baseline decision/evidence events, automaton decision events with zero
evidence bytes, and nonzero evidence only for evidence candidates. Reject
unknown modes, duplicate flags, iterations outside `1..SIZE_MAX`, unsafe output,
invalid process index, and an output file that already exists.

- [ ] **Step 2: Run and verify red**

```bash
cmake --build sandbox/eip-phase1a/build --parallel
ctest --test-dir sandbox/eip-phase1a/build -R ei_candidate --output-on-failure
```

- [ ] **Step 3: Implement the exact timing boundaries**

For every measured round:

```cpp
const CandidateAdapter& candidate = ActiveCandidate();
if (!candidate.begin_round(workload)) return kCandidateInitFailed;
const auto operation_start = Clock::now();
const WorkloadResult result = pool.Run(workload, logical_round);
const auto operation_stop = Clock::now();
const auto finalize_start = Clock::now();
const CandidateSnapshot snapshot = candidate.finalize_round();
const auto finalize_stop = Clock::now();
samples.push_back(MakeSample(operation_start, operation_stop,
                             finalize_start, finalize_stop,
                             result, snapshot));
```

After all rounds, encode the complete sample vector into memory and time only
that encoding. Then write the encoded sample file and time only the write/close.
Capture resident bytes after initialization, after warmup, and after measured
rounds through real Mach `task_info(MACH_TASK_BASIC_INFO_64)`; record lifetime
peak RSS separately through `getrusage`. Finally write those values, both I/O
measurements, configured buffer bytes, candidate/workload initialization times,
and sample size to `EIC1`. The cost-file write is outside all
reported intervals. Do not label lifetime peak as steady-state RSS. Do not start
or join persistent workers inside `operation_ns`; the short-lived-thread
workload is the one deliberate exception and applies equally to every mode.

The benchmark does not claim to time decision and evidence independently inside
one composed event. Their incremental hot-path costs are estimated only from
separate binaries: `automaton - baseline`, `automaton_summary - automaton`, and
`ordered_ring - automaton`, using the same frozen iteration count and clustered
analysis in Task 9.

- [ ] **Step 4: Build, run focused integration, and commit**

```bash
cmake --build sandbox/eip-phase1a/build --parallel
ctest --test-dir sandbox/eip-phase1a/build -R ei_candidate --output-on-failure
git -C sandbox/eip-phase1a add CMakeLists.txt include/ei/measure/candidate.hpp apps/candidate_main.cpp tests/candidate_test.cmake
git -C sandbox/eip-phase1a commit -m "Separate operation and evidence costs"
```

---

### Task 8: Calibrate, randomize, and run real child processes

**Files:**
- Create: `sandbox/eip-phase1a/apps/runner_main.cpp`
- Create: `sandbox/eip-phase1a/tests/runner_test.cmake`
- Modify: `sandbox/eip-phase1a/CMakeLists.txt`

**Interfaces:**
- Consumes: candidate executables and config.
- Produces: `calibration.txt`, `environment.txt`, a canonical
  `run-manifest.txt`, and one raw sample/cost pair per mode/workload/process.

- [ ] **Step 1: Write the failing orchestration test**

The test uses a small real config but still spawns every available candidate.
It requires baseline calibration to converge, freezes one iteration count per
workload, and verifies every candidate receives that exact count. Require
exactly one entry for each Cartesian tuple
`(workload, mode, process_index)`, deterministic schedule for the same seed,
different schedule for a second seed, and nonzero parent exit if a child exits
nonzero or fails to create its declared output. A second real case deliberately
exceeds the environmental CV limit and requires a typed stop before the
candidate matrix; the runner must not retry it.

- [ ] **Step 2: Run and verify red**

```bash
cmake --build sandbox/eip-phase1a/build --target ei_runner --parallel
ctest --test-dir sandbox/eip-phase1a/build -R ei_runner --output-on-failure
```

- [ ] **Step 3: Implement baseline calibration and environmental preflight**

Add a mutually exclusive calibration mode to Task 7's child interface:

```text
--calibrate --workload <name> --iterations <n> --output <relative-path>
```

It performs `warmup_rounds`, then `calibration_rounds`, and writes their median
operation time using the same workload binary without candidate instrumentation.
The runner starts at config `iterations`, computes
`round(old_iterations * target_round_ns / observed_median_ns)` with checked
128-bit intermediate arithmetic, and repeats at most `calibration_max_steps`.
Convergence requires both the `[minimum_round_ns, maximum_round_ns]` safety
window and `abs(observed-target) <= target_tolerance_ns`; otherwise the run is
typed `calibration_failed`. Freeze the resulting per-workload counts in
`calibration.txt` before any candidate runs.

Then launch `child_processes` fresh baseline preflight processes per workload.
Compute CV across process medians, not across correlated rounds. If any CV
exceeds `environment_cv_limit_basis_points`, write `environment_unstable`, stop,
and do not retry automatically. Record real macOS version, machine model,
logical CPU count, physical memory, load average, Mach host CPU ticks, power
source through IOKit when available, toolchain identity, and every unavailable
field with a typed reason in `environment.txt`. The runner observes but never
changes affinity, priority, power, fan, sleep, or thermal settings.

- [ ] **Step 4: Implement safe randomized `posix_spawn` execution**

Build the complete schedule in memory, shuffle it with `std::mt19937_64` seeded
from config, and invoke explicit executable/argv arrays through `posix_spawn`.
Do not use a shell or `std::system`. Run children sequentially to avoid thermal
and CPU contention between modes. Stop at the first failure and preserve all
already-created evidence plus a typed manifest row.

Manifest rows are exact tab-separated fields:

```text
schedule_index mode workload process_index iterations exit_code relative_sample_path relative_cost_path
```

Baseline remains in the randomized release matrix even though preflight already
ran, so candidate deltas use temporally interleaved baseline data. Do not reuse
preflight samples in the decision analysis.

- [ ] **Step 5: Test and commit**

```bash
cmake --build sandbox/eip-phase1a/build --parallel
ctest --test-dir sandbox/eip-phase1a/build -R ei_runner --output-on-failure
git -C sandbox/eip-phase1a add CMakeLists.txt apps/runner_main.cpp tests/runner_test.cmake
git -C sandbox/eip-phase1a commit -m "Randomize reproducible candidate runs"
```

---

### Task 9: Implement clustered statistics, attribution, and fixed decisions

**Files:**
- Create: `sandbox/eip-phase1a/apps/analyze_main.cpp`
- Create: `sandbox/eip-phase1a/tests/analyzer_test.cpp`
- Modify: `sandbox/eip-phase1a/CMakeLists.txt`

**Interfaces:**
- Consumes: run manifest, raw sample files, candidate binary paths, capabilities.
- Produces: `summary.txt`, `summary.csv`, and exit `0` ready, `10` limitation, `20` blocked, `64` usage.

- [ ] **Step 1: Write failing deterministic statistics tests**

Use fixed sample vectors and require:

```cpp
struct ProcessSamples {
    uint32_t process_index;
    std::vector<uint64_t> rounds_ns;
};
uint64_t PercentileNearestRank(std::vector<uint64_t>, double percentile);
ConfidenceInterval HierarchicalOverheadCI(
    const std::vector<ProcessSamples>& baseline,
    const std::vector<ProcessSamples>& candidate,
    double percentile, uint64_t seed, size_t resamples);
double ProcessMedianCv(const std::vector<ProcessSamples>& samples);
GateDecision EvaluateGates(const ExperimentReport& report);
```

Tests cover p50/p95/p99, a negative overhead without unsigned underflow,
deterministic hierarchical-bootstrap bounds, a constructed example where naive
round resampling is falsely narrow, mismatched result, any gap/violation,
missing process, wrong round count, environmental CV failure, unavailable
candidate, unordered candidate rejection as a default mechanism, and exact
threshold boundaries at 5%/8%/10%/15%.

- [ ] **Step 2: Run and verify red**

```bash
cmake --build sandbox/eip-phase1a/build --target ei_analyzer_test --parallel
```

- [ ] **Step 3: Implement complete cost attribution**

For each workload/mode report:

```text
operation_p50_ns, operation_p95_ns, operation_p99_ns
operation_p95_overhead_percent, operation_p95_ci_low, operation_p95_ci_high
operation_p99_overhead_percent, operation_p99_ci_low, operation_p99_ci_high
incremental_vs_automaton_p95_percent, incremental_vs_automaton_p99_percent
candidate_init_p95_ns, workload_init_p95_ns, finalize_p95_ns
encode_p95_ns, sample_write_p95_ns
decision_events, evidence_events, evidence_bytes, configured_buffer_bytes
rss_post_warmup_delta_bytes, peak_rss_bytes, binary_bytes, binary_growth_percent
violations, lifecycle_failures, result_mismatches, gaps, missing_samples, process_median_cv
evidence_semantics, capability_state
```

For every bootstrap resample, sample process clusters with replacement and then
sample rounds within each selected process before computing the requested
candidate/baseline percentile ratio. Never flatten all rounds into one IID
vector. Use signed floating-point percentages with finite/range checks. The
readiness gate uses the upper 95% confidence bound, not the point estimate.

Apply the spec's fixed gates independently:

- automaton-only: p95 <=5% and p99 <=8% on every workload;
- automaton-plus-summary: p95 <=5% and p99 <=8% on every workload;
- ordered ring: p95 <=15%, laboratory diagnostic only;
- inline counters and gated callbacks: diagnostics only, never substitutes for
  deterministic decision or ordered/summary semantics;
- default modes: binary growth <=10%, post-warmup RSS growth <=16 MiB plus
  `configured_buffer_bytes`, candidate initialization p95 <=25 ms, zero gap,
  zero lifecycle failure, zero violation, and zero result mismatch.

The analyzer emits separate `phase1b`, `phase1c`, and `phase1d` results. Phase
1C requires automaton-only. Phase 1D requires automaton-plus-summary; a cheap
ordered ring cannot substitute for the default summary contract. Phase 1B is
`READY` when the automaton passes, `READY_WITH_LIMITATIONS` for exactly one
optimization iteration only when correctness passes and automaton p95/p99 upper
bounds are <=7%/10%, and otherwise `BLOCKED`. Overall is `READY` only when all
three phases are ready, `READY WITH NON-BLOCKING LIMITATIONS` when experiment
integrity holds but at least one later phase remains gated, and `BLOCKED` for
measurement/correctness failure or an automaton beyond 7%/10%. Print all
measurements and phase gates before returning an exit code.

- [ ] **Step 4: Reject malformed and selectively missing matrices**

Parse every manifest row and sample file strictly, validate path safety,
process/round uniqueness, candidate header consistency, capability agreement,
calibration count agreement, environment CV, and exact matrix cardinality. A
missing slow child is failure, not an outlier. Verify binary size from the actual
executables and reject a report-provided size. Treat `ru_maxrss` only as lifetime
peak and Mach post-warmup resident bytes as the steady-state gate input.

- [ ] **Step 5: Test and commit**

```bash
cmake --build sandbox/eip-phase1a/build --parallel
ctest --test-dir sandbox/eip-phase1a/build -R ei_analyzer --output-on-failure
git -C sandbox/eip-phase1a add CMakeLists.txt apps/analyze_main.cpp tests/analyzer_test.cpp
git -C sandbox/eip-phase1a commit -m "Apply fixed phase 1A measurement gates"
```

---

### Task 10: Prove identity, lifecycle, and failure semantics on the real host

**Files:**
- Create: `sandbox/eip-phase1a/tests/stability_test.cmake`
- Create: `sandbox/eip-phase1a/tests/e2e_test.cmake`
- Modify: `sandbox/eip-phase1a/CMakeLists.txt`

**Interfaces:**
- Consumes: all Phase 1A binaries.
- Produces: real clean-build, ASLR, DSO, sanitizer, thread, crash, and
  end-to-end evidence.

- [ ] **Step 1: Write the failing stability integration**

The CTest script creates two separate Release build directories under
`test-work/stability`, builds the candidates from the same source/config, and
runs both. It requires explicit automaton site IDs, transition tables, Quark
fixture source digests, and results to match across clean builds and ASLR
process launches. It loads a real test dylib in different orders and verifies
runtime-generated coverage IDs are not mistaken for stable manifest identities.

Real child cases skip, duplicate, reorder, and replace a site; invoke a site
from a wrong thread; and attempt a transition after finalization. Each must
produce a violation or typed failure without reporting a complete operation.
These are automaton-state tests, not a claim that an attacker with arbitrary
code execution cannot bypass an unmediated protected effect.

- [ ] **Step 2: Add real lifecycle cases**

Use child modes in the real candidate executable to exercise:

```text
--lifecycle normal-thread-exit
--lifecycle process-exit-without-finalize
--lifecycle signal-during-operation
--lifecycle exception-during-operation
--lifecycle fork-after-init
--lifecycle capacity-overflow
```

Expected semantics are explicit: normal exit is complete; missing finalize,
signal, exception crossing the protected operation, unsupported fork state, and
overflow are gaps or typed unavailable states. No test constructs a fake sample
to stand in for the child.

- [ ] **Step 3: Add real sanitizer configurations**

Configure distinct Debug builds under `test-work/sanitizers/asan-ubsan` with
`-fsanitize=address,undefined -fno-omit-frame-pointer` and under
`test-work/sanitizers/tsan` with `-fsanitize=thread`. Run the real config,
sample, workload, automaton, evidence, candidate, and analyzer tests. Any
ASan/UBSan finding fails every affected mode. Automaton and both evidence modes
must be TSan-clean. If Apple Clang's own non-atomic inline 8-bit counters report
races, record `inline_counter_tsan=unavailable_by_instrumentation_design` and
keep that mode diagnostic-only; do not suppress the race or relabel the target
TSan-clean. Gated callback TSan status is whatever the real capability build
proves.

- [ ] **Step 4: Add the small full matrix CTest**

`e2e_test.cmake` writes a real small config, runs `ei_runner`, runs `ei_analyze`,
and checks that the summary contains every available candidate/workload plus the
fixed decision. It accepts exit `0` or `10` for performance, but never `20`.

- [ ] **Step 5: Run the complete suite and commit**

```bash
cmake --build sandbox/eip-phase1a/build --parallel
ctest --test-dir sandbox/eip-phase1a/build --output-on-failure
git -C sandbox/eip-phase1a add CMakeLists.txt tests/stability_test.cmake tests/e2e_test.cmake apps/candidate_main.cpp
git -C sandbox/eip-phase1a commit -m "Validate real phase 1A lifecycle boundaries"
```

Expected: every correctness/lifecycle test passes. Performance may still produce
the defined non-blocking limitation exit in the small matrix.

---

### Task 11: Generate release evidence and the phase-specific gate decision

**Files:**
- Create: `sandbox/eip-phase1a/results/release/summary.txt` (generated, ignored)
- Create: `sandbox/eip-phase1a/results/release/summary.csv` (generated, ignored)
- Create: `sandbox/eip-phase1a/results/release/build-metrics.txt` (generated, ignored)
- Create: `docs/research/2026-08-23-execution-integrity-phase-1a-results.md`

**Interfaces:**
- Consumes: only fresh clean-build tests and raw release samples.
- Produces: phase-specific 1B/1C/1D gates plus one overall `READY`,
  `READY WITH NON-BLOCKING LIMITATIONS`, or `BLOCKED` decision.

- [ ] **Step 1: Perform and measure a separate clean Release build**

```bash
EIP_PHASE1A_RELEASE_BUILD=sandbox/eip-phase1a/build-release-evidence-1
cmake \
  -DSOURCE_DIR=sandbox/eip-phase1a \
  -DBUILD_DIR="$EIP_PHASE1A_RELEASE_BUILD" \
  -DOUTPUT_FILE=sandbox/eip-phase1a/results/release/build-metrics.txt \
  -P sandbox/eip-phase1a/cmake/measure_release_build.cmake
ctest --test-dir "$EIP_PHASE1A_RELEASE_BUILD" --output-on-failure
```

The script rejects an existing build directory/output file, resolves all three
paths under `sandbox/eip-phase1a`, invokes configure and build via
`execute_process` with argument arrays, and wraps each command in
`cmake -E time`. It parses exactly one `Elapsed time (seconds)` record per
command, records configure/build exit status and wall seconds, and propagates
failure. If suffix `-1` exists, inspect `-2`, then continue monotonically to the
first absent exact path and pass that path explicitly. Never move, delete, or
overwrite development/evidence builds merely to obtain a clean measurement.

- [ ] **Step 2: Execute the release matrix**

Run through an output option rather than shell redirection:

```bash
EIP_PHASE1A_RELEASE_BUILD=sandbox/eip-phase1a/build-release-evidence-1
"$EIP_PHASE1A_RELEASE_BUILD/ei_runner" \
  --config sandbox/eip-phase1a/config/phase1a.conf \
  --output sandbox/eip-phase1a/results/release
"$EIP_PHASE1A_RELEASE_BUILD/ei_analyze" \
  --config sandbox/eip-phase1a/config/phase1a.conf \
  --run-dir sandbox/eip-phase1a/results/release \
  --summary sandbox/eip-phase1a/results/release/summary.txt \
  --csv sandbox/eip-phase1a/results/release/summary.csv
```

Record the analyzer exit without converting `10` into shell success. Exit `20`
is `BLOCKED` and stops the plan.

- [ ] **Step 3: Write the outer evidence report**

Use exact sections:

```markdown
# Execution Integrity Phase 1A Results
## Scope and claim level
## Host and toolchain
## Calibration and environmental stability
## Clean-build tests
## Capability probe
## Real Quark fixture identity
## Workload matrix
## Cost attribution
## Completeness and lifecycle
## Selected mechanism or rejection
## Known limitations
## Phase 1B artifact decision
## Phase 1C enforcement decision
## Phase 1D collector decision
## Overall decision
```

The decision rules are fixed:

- `READY`: experiment integrity passes; automaton-only and
  automaton-plus-summary each pass correctness, identity, lifecycle, binary/RSS,
  initialization, p95 <=5%, and p99 <=8% gates using confidence-interval upper
  bounds. Phase 1B/1C/1D are all ready for their own implementation plans.
- `READY WITH NON-BLOCKING LIMITATIONS`: experiment integrity and correctness
  pass, but either (a) automaton-only is above 5%/8% and at most 7%/10%, allowing
  exactly one Phase 1B optimization iteration while Phase 1C/1D remain blocked,
  or (b) automaton-only passes while automaton-plus-summary fails, allowing Phase
  1B/1C while Phase 1D remains blocked. The report must name the exact phase
  gates; “overall limitation” cannot hide them.
- `BLOCKED`: environment instability, any mismatch, violation, silent gap,
  unstable explicit identity, altered Quark fixture digest, malformed/missing
  matrix entry, lifecycle ambiguity, or automaton p95/p99 upper bounds above
  7%/10%. Redesign before expanding the gated phase.

- [ ] **Step 4: Verify boundaries and commit only the report outside the spike**

```bash
rg -n 'T[B]D|T[O]DO|F[I]XME|<[[:alnum:]_-]+>' docs/research/2026-08-23-execution-integrity-phase-1a-results.md
git diff --check -- docs/research/2026-08-23-execution-integrity-phase-1a-results.md
git -C sandbox/eip-phase1a status --short
git add -- docs/research/2026-08-23-execution-integrity-phase-1a-results.md
git commit -m "Record execution integrity phase 1A evidence" -- docs/research/2026-08-23-execution-integrity-phase-1a-results.md
```

Expected: nested source is clean, ignored measurements remain available, and the
outer commit contains exactly one evidence document.

## Plan self-review record

- Spec coverage: Phase 1A implements only the v2 cost-selection gate. Artifact
  signing, enforcement, collector, SaaS, ML, Quark integration, platform ports,
  and attestation correctly remain in later independent plans.
- Measurement correction: operation timing excludes serialization and persistent
  worker teardown; all other costs are reported separately.
- Platform truth: XRay/FDR is explicitly unavailable on Darwin based on LLVM's
  documented runtime targets; no fake candidate is substituted.
- Type consistency: `Config`, `CandidateMode`, `WorkloadKind`, `MetricSample`,
  `AutomatonSnapshot`, `EvidenceSnapshot`, and `CoverageSnapshot` are defined
  once and consumed by later tasks under the same names.
- Security honesty: automaton decisions are measured separately from summary
  and ordered-ring evidence. This phase tests state correctness but does not
  claim build-mediated effects; inline counters and gated callbacks remain
  diagnostics.
- Statistical honesty: process clusters are the outer bootstrap unit, baseline
  rounds are calibrated near 50 ms, environmental instability stops rather than
  retriggers the matrix, and peak RSS is not relabeled as steady state.
- Product realism: the matrix includes the exact Quark Lamport/crypto sources
  with recorded digests in addition to synthetic kernels.
- Scope choice: a function-boundary pass is not included because no default
  decision/evidence requirement needs it after the automaton/summary split. A
  later diagnostic need requires a separate measured plan, not an unlabeled
  seventh candidate added after results are visible.
- Failure honesty: missing children, malformed samples, mismatch, overflow,
  unsupported lifecycle, and unavailable capabilities cannot produce readiness.
- Repository safety: Phase 0 stays unchanged, all Phase 1A execution remains
  under `sandbox/`, and the outer repository receives documentation/evidence only.
