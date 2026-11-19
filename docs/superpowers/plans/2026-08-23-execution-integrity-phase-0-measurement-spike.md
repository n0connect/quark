# Execution Integrity Phase 0 Measurement Spike Implementation Plan

> Status: completed and retained as historical execution evidence. Future work
> starts from `2026-08-23-execution-integrity-phase-1a-cost-model.md`; do not
> extend this disposable callback recorder into a production runtime.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a disposable, independent macOS ARM64 measurement spike that records real compiler-instrumented basic-block transitions, rejects incomplete traces, distinguishes learned-valid from novel paths, and measures whether the event volume and runtime overhead justify building the production execution-integrity SDK.

**Architecture:** A nested, independent spike repository lives under Quark's `sandbox/eip-phase0/`, so every build, test, trace, and scratch file remains inside the required sandbox boundary and no SaaS code enters Quark. Apple Clang SanitizerCoverage supplies real `bb,no-prune,trace-pc-guard` callbacks; a small C++17 runtime writes per-thread ordered trace files, and a separate analyzer learns/checks edge sets and summarizes baseline-versus-instrumented timings. This is a measurement instrument, not security enforcement or cryptographic attestation.

**Tech Stack:** Apple Clang 21.0.0, C++17, CMake 4.4+, CTest, pthreads, SanitizerCoverage, standard library only.

**Spec:** `docs/superpowers/specs/2026-08-23-execution-integrity-platform-design.md`

## Global Constraints

- Run on real Darwin ARM64; the observed host at plan time is `Darwin 25.5.0 arm64`.
- Put all spike source, nested git metadata, builds, test scratch, traces, and results under `sandbox/eip-phase0/`; never use `std::filesystem::temp_directory_path()`.
- Do not modify `quark_core`, `quark_c_api`, `quark_codecipher`, `quark_linkload`, or any existing Quark build target.
- Do not add a network call, SaaS service, database, model trainer, kernel module, TEE, mock, fake trace, or stubbed OS result.
- Compile and execute both baseline and instrumented binaries for real; compile-only output is not evidence.
- Treat every overflow, truncation, missing sequence, duplicate sequence, and malformed trace as an explicit evidence gap.
- Never call the spike output attestation, enforcement, production-ready, or cross-platform support.
- Keep the spike after measurement until the evidence report is reviewed; do not delete it as part of this plan.
- Commit spike tasks inside the nested `sandbox/eip-phase0/.git`; commit only the final evidence report and this plan to the outer Quark repository.

## Scope decomposition

The architecture spec contains independent native runtime, collector, SaaS,
ML, Quark adapter, and trusted-anchor subsystems. Planning all of them before
measuring native event completeness and cost would manufacture interfaces from
assumptions. This plan implements only Phase 0. Passing its exit gate authorizes
separate Phase 1 and Phase 2 plans; SaaS/ML plans follow the deterministic core,
and trusted-anchor work remains a platform-specific research plan.

## File structure

Create this independent tree during execution:

```text
sandbox/eip-phase0/
├── .git/
├── CMakeLists.txt
├── README.md
├── config/
│   └── eip-spike.conf
├── include/eip/spike/
│   ├── config.hpp
│   ├── runtime.hpp
│   └── trace.hpp
├── src/
│   ├── config.cpp
│   ├── runtime.cpp
│   └── trace.cpp
├── apps/
│   ├── analyze_trace.cpp
│   └── branch_fixture.cpp
├── tests/
│   ├── config_test.cpp
│   ├── runtime_test.cpp
│   └── trace_test.cpp
├── build/
├── test-work/
├── run-work/
│   ├── baseline/
│   └── instrumented/
└── results/
```

Outer-repository evidence created only after the spike passes:

```text
docs/research/2026-08-23-execution-integrity-phase-0-results.md
```

Responsibilities:

- `config.*`: strict `key=value` reader for trace capacity, iterations,
  thread count, mode, and relative output directory.
- `trace.*`: versioned binary trace codec and exact structural validation.
- `runtime.*`: SanitizerCoverage callbacks, per-thread fixed-capacity buffers,
  overflow/gap state, and real file flush on thread exit.
- `branch_fixture.cpp`: identical deterministic workload compiled once without
  instrumentation and once with instrumentation.
- `analyze_trace.cpp`: trace inspection, learned-edge baseline, novel-edge
  checking, and benchmark summary.
- `tests/*`: direct tests of real parser, codec, runtime, files, and threads.

---

### Task 1: Bootstrap the independent spike and strict configuration

**Files:**
- Create: `sandbox/eip-phase0/CMakeLists.txt`
- Create: `sandbox/eip-phase0/README.md`
- Create: `sandbox/eip-phase0/config/eip-spike.conf`
- Create: `sandbox/eip-phase0/include/eip/spike/config.hpp`
- Create: `sandbox/eip-phase0/src/config.cpp`
- Create: `sandbox/eip-phase0/tests/config_test.cpp`

**Interfaces:**
- Produces: `eip::spike::Config`, `eip::spike::LoadConfig(const std::filesystem::path&) -> std::optional<Config>`.
- Consumes: only C++17 standard-library filesystem and streams.

- [ ] **Step 1: Create and initialize the nested repository**

Run from the Quark root:

```bash
mkdir -p sandbox/eip-phase0
git -C sandbox/eip-phase0 init
```

Expected: `sandbox/eip-phase0/.git/` exists; the outer repository still reports
no tracked spike source because `sandbox/` is the experiment boundary.

- [ ] **Step 2: Write the failing configuration test**

Define the interface in `include/eip/spike/config.hpp`:

```cpp
#pragma once
#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>

namespace eip::spike {
struct Config {
    size_t buffer_events{};
    size_t iterations{};
    size_t threads{};
    std::string mode;
    std::filesystem::path output_dir;
};
std::optional<Config> LoadConfig(const std::filesystem::path& path);
}
```

In `tests/config_test.cpp`, write a real relative file under the test working
directory and verify strict behavior:

```cpp
#include "eip/spike/config.hpp"
#include <filesystem>
#include <fstream>

int main() {
    std::filesystem::create_directories("scratch");
    {
        std::ofstream out("scratch/valid.conf", std::ios::trunc);
        out << "buffer_events=4096\niterations=200000\nthreads=4\n"
               "mode=instrumented\noutput_dir=traces\n";
    }
    auto valid = eip::spike::LoadConfig("scratch/valid.conf");
    if (!valid || valid->buffer_events != 4096 || valid->iterations != 200000 ||
        valid->threads != 4 || valid->mode != "instrumented" ||
        valid->output_dir != "traces") return 1;

    std::ofstream("scratch/duplicate.conf", std::ios::trunc)
        << "buffer_events=1\nbuffer_events=2\niterations=1\nthreads=1\n"
           "mode=baseline\noutput_dir=traces\n";
    if (eip::spike::LoadConfig("scratch/duplicate.conf")) return 2;

    std::ofstream("scratch/absolute.conf", std::ios::trunc)
        << "buffer_events=1\niterations=1\nthreads=1\nmode=baseline\n"
           "output_dir=/tmp/eip\n";
    if (eip::spike::LoadConfig("scratch/absolute.conf")) return 3;
    return 0;
}
```

- [ ] **Step 3: Add the build definition and verify the test fails**

Create a CMake project that writes all binaries under `build/`, enables CTest,
builds `eip_spike_config`, and sets the test working directory to the absolute
`sandbox/eip-phase0/test-work` path. Configure and run:

```bash
cmake -S sandbox/eip-phase0 -B sandbox/eip-phase0/build -DCMAKE_BUILD_TYPE=Release
cmake --build sandbox/eip-phase0/build --target eip_spike_config_test -j4
ctest --test-dir sandbox/eip-phase0/build -R eip_spike_config_test --output-on-failure
```

Expected: build or link failure because `LoadConfig` has no implementation.

- [ ] **Step 4: Implement the strict parser**

In `src/config.cpp`, parse exactly five unique keys, reject unknown/duplicate/
missing keys, reject numeric zero and numeric overflow, trim ASCII spaces/tabs,
and reject absolute or parent-traversing `output_dir`. Use
`std::from_chars` for numbers and this final validation:

```cpp
if (cfg.buffer_events == 0 || cfg.iterations == 0 || cfg.threads == 0 ||
    (cfg.mode != "baseline" && cfg.mode != "instrumented") ||
    cfg.output_dir.empty() || cfg.output_dir.is_absolute()) return std::nullopt;
for (const auto& part : cfg.output_dir) {
    if (part == "..") return std::nullopt;
}
return cfg;
```

Create `config/eip-spike.conf`:

```text
buffer_events=1048576
iterations=200000
threads=4
mode=instrumented
output_dir=traces
```

- [ ] **Step 5: Run the real test and commit**

```bash
cmake --build sandbox/eip-phase0/build --target eip_spike_config_test -j4
ctest --test-dir sandbox/eip-phase0/build -R eip_spike_config_test --output-on-failure
git -C sandbox/eip-phase0 add CMakeLists.txt README.md config include src tests
git -C sandbox/eip-phase0 commit -m "Build strict spike configuration"
```

Expected: test passes and the first nested-repository commit contains no build,
trace, or result artifacts.

---

### Task 2: Add the versioned trace codec and gap rejection

**Files:**
- Create: `sandbox/eip-phase0/include/eip/spike/trace.hpp`
- Create: `sandbox/eip-phase0/src/trace.cpp`
- Create: `sandbox/eip-phase0/tests/trace_test.cpp`
- Modify: `sandbox/eip-phase0/CMakeLists.txt`

**Interfaces:**
- Produces: `TraceHeader`, `TraceEvent`, `TraceFile`, `WriteTrace`, `ReadTrace`.
- Consumes: `Config::output_dir` from Task 1 only at call sites; the codec itself
  accepts an explicit relative path.

- [ ] **Step 1: Define the wire types and write the failing round-trip test**

Use this public contract:

```cpp
namespace eip::spike {
inline constexpr uint32_t kTraceMagic = 0x30504945; // "EIP0" little-endian
inline constexpr uint16_t kTraceVersion = 1;

enum class TraceStatus : uint16_t { kComplete = 0, kEvidenceGap = 1 };
struct TraceEvent { uint64_t sequence; uint32_t source; uint32_t target; };
struct TraceFile {
    uint64_t session_id;
    uint32_t thread_id;
    TraceStatus status;
    std::vector<TraceEvent> events;
};
bool WriteTrace(const std::filesystem::path& path, const TraceFile& trace);
std::optional<TraceFile> ReadTrace(const std::filesystem::path& path);
}
```

`tests/trace_test.cpp` must write `scratch/roundtrip.eip`, read it back, compare
every field, then create `scratch/truncated.eip` by copying all but the final
byte and prove `ReadTrace` returns `std::nullopt`. Add a second case with
sequences `{1, 3}` and prove the reader rejects the missing `2`.

- [ ] **Step 2: Run the test and verify it fails**

```bash
cmake --build sandbox/eip-phase0/build --target eip_spike_trace_test -j4
ctest --test-dir sandbox/eip-phase0/build -R eip_spike_trace_test --output-on-failure
```

Expected: link failure for `WriteTrace` and `ReadTrace`.

- [ ] **Step 3: Implement explicit little-endian serialization**

Write fields individually; never `write()` a C++ struct whose padding is ABI
dependent. The on-disk order is:

```text
u32 magic | u16 version | u16 status | u64 session_id |
u32 thread_id | u32 event_count |
event_count * (u64 sequence | u32 source | u32 target)
```

Reject wrong magic/version/status, event counts above `16,777,216`, any file
whose exact size differs from `24 + event_count * 16`, sequence zero, or a
non-consecutive sequence. Open with `std::ios::binary`; return `false`/
`std::nullopt` for every I/O failure.

- [ ] **Step 4: Run the codec tests and commit**

```bash
cmake --build sandbox/eip-phase0/build --target eip_spike_trace_test -j4
ctest --test-dir sandbox/eip-phase0/build -R eip_spike_trace_test --output-on-failure
git -C sandbox/eip-phase0 add CMakeLists.txt include/eip/spike/trace.hpp src/trace.cpp tests/trace_test.cpp
git -C sandbox/eip-phase0 commit -m "Add strict execution trace codec"
```

Expected: round trip passes; truncation and sequence-gap cases are rejected.

---

### Task 3: Record real SanitizerCoverage events per thread

**Files:**
- Create: `sandbox/eip-phase0/include/eip/spike/runtime.hpp`
- Create: `sandbox/eip-phase0/src/runtime.cpp`
- Create: `sandbox/eip-phase0/tests/runtime_test.cpp`
- Modify: `sandbox/eip-phase0/CMakeLists.txt`

**Interfaces:**
- Produces: `ConfigureRuntime`, `StartTrace`, `StopTrace`, `RuntimeEvidenceGap`,
  and the required `__sanitizer_cov_trace_pc_guard*` callbacks.
- Consumes: `Config` and `WriteTrace` from Tasks 1–2.

- [ ] **Step 1: Define the runtime interface and failing real-thread test**

```cpp
namespace eip::spike {
bool ConfigureRuntime(const Config& config, uint64_t session_id);
void StartTrace();
void StopTrace();
bool RuntimeEvidenceGap();
void FlushCurrentThread();
}
```

In `tests/runtime_test.cpp`, configure output `traces`, capacity `64`, create
the directory relative to CTest's working directory, call `StartTrace`, launch
two real `std::thread`s, and have each call a test-only
`eip::spike::RecordForTest(uint32_t block_id)` sequence `{10,11,12}`. Join,
record `{20,21}` on the main thread, stop/flush, enumerate real `.eip` files,
read each with `ReadTrace`, and assert there are exactly three distinct thread
IDs with consecutive sequences and no gap.

Expose `RecordForTest` only when the runtime library is compiled with
`EIP_SPIKE_TESTING=1`; production spike targets do not export it.

- [ ] **Step 2: Run the test and verify it fails**

```bash
cmake --build sandbox/eip-phase0/build --target eip_spike_runtime_test -j4
ctest --test-dir sandbox/eip-phase0/build -R eip_spike_runtime_test --output-on-failure
```

Expected: link failure for the runtime functions.

- [ ] **Step 3: Implement bounded per-thread recording**

Use process-wide immutable configuration after the first successful
`ConfigureRuntime`, an atomic thread ordinal, an atomic enabled flag, and this
thread-local state:

```cpp
struct ThreadBuffer {
    uint32_t id{};
    uint64_t next_sequence{1};
    uint32_t previous_block{};
    bool gap{};
    std::vector<TraceEvent> events;
    ~ThreadBuffer() { Flush(); }
    void Record(uint32_t block);
    void Flush();
};
```

`Record` returns immediately while tracing is disabled. On the first block it
records source `0`; afterward it records the previous block. Once capacity is
reached it sets `gap=true`, sets the process-wide gap flag, and records nothing
else. `Flush` writes one uniquely named
`<output_dir>/session-<session>-thread-<id>.eip` through `WriteTrace`, with
`kEvidenceGap` when overflow occurred. Mark the runtime implementation and
callbacks `__attribute__((no_sanitize("coverage")))` to prevent recursive
instrumentation.

Define the real compiler callbacks exactly:

```cpp
extern "C" void __sanitizer_cov_trace_pc_guard_init(uint32_t* start,
                                                     uint32_t* stop);
extern "C" void __sanitizer_cov_trace_pc_guard(uint32_t* guard);
```

Assign each previously-zero guard a nonzero process-unique ID with an atomic
counter. The callback passes `*guard` to the same `ThreadBuffer::Record` path;
it never symbolizes or exports a program counter.

- [ ] **Step 4: Add and run the overflow negative case**

Extend the test with capacity `2`, record three blocks in a fresh process by
adding a `--overflow-child` mode to the test executable and launching it with
`std::system` using the test executable's explicit path from CMake. Read its
real output file and assert `TraceStatus::kEvidenceGap` and exactly two events.
Do not synthesize a `TraceFile` in the parent.

```bash
cmake --build sandbox/eip-phase0/build --target eip_spike_runtime_test -j4
ctest --test-dir sandbox/eip-phase0/build -R eip_spike_runtime_test --output-on-failure
```

Expected: three-thread recording passes and overflow is reported as a gap.

- [ ] **Step 5: Commit the runtime**

```bash
git -C sandbox/eip-phase0 add CMakeLists.txt include/eip/spike/runtime.hpp src/runtime.cpp tests/runtime_test.cpp
git -C sandbox/eip-phase0 commit -m "Record bounded per-thread path evidence"
```

---

### Task 4: Build identical baseline and instrumented native fixtures

**Files:**
- Create: `sandbox/eip-phase0/apps/branch_fixture.cpp`
- Modify: `sandbox/eip-phase0/CMakeLists.txt`
- Modify: `sandbox/eip-phase0/config/eip-spike.conf`

**Interfaces:**
- Produces: `eip_branch_baseline`, `eip_branch_instrumented`, CSV timing output,
  and real instrumented `.eip` files.
- Consumes: runtime interface from Task 3; baseline uses compile-time no-op
  wrappers from `runtime.hpp` and links no trace runtime.

- [ ] **Step 1: Write the deterministic workload**

Create one source file with no duplicated workload. Implement:

```cpp
__attribute__((noinline)) uint64_t WorkItem(uint64_t x) {
    if ((x % 7) == 0) return x * 3 + 1;
    if ((x & 1) == 0) return x / 2 + 17;
    return x ^ 0x5a5a5a5aULL;
}

__attribute__((noinline)) uint64_t WorkRange(uint64_t begin, uint64_t count) {
    uint64_t acc = 0;
    for (uint64_t i = 0; i < count; ++i) acc ^= WorkItem(begin + i);
    return acc;
}
```

`main` loads the config passed by `--config`, creates only relative configured
directories, starts tracing immediately before the workload, stops immediately
after it, flushes, and writes:

```text
mode,round,nanoseconds,result
```

to the relative `--timings` path. Execute five warmup rounds without writing
timings, then 30 measured rounds. Split work deterministically across the
configured number of real `std::thread`s and combine results by thread index,
not completion order.

- [ ] **Step 2: Define two builds from the exact same source**

`eip_branch_baseline` compiles normally with `EIP_SPIKE_INSTRUMENTED=0`.
`eip_branch_instrumented` compiles and links with:

```text
-fsanitize-coverage=bb,no-prune,trace-pc-guard
```

and `EIP_SPIKE_INSTRUMENTED=1`, linking the real runtime. Both use Release
optimization and pthreads. Define
`set(EIP_FIXTURE_SOURCE apps/branch_fixture.cpp)` once and pass that exact CMake
variable to both `add_executable` calls; do not create a copied baseline source.

- [ ] **Step 3: Build and execute both variants for real**

```bash
cmake --build sandbox/eip-phase0/build --target eip_branch_baseline eip_branch_instrumented -j4
mkdir -p sandbox/eip-phase0/run-work/baseline sandbox/eip-phase0/run-work/instrumented
cd sandbox/eip-phase0/run-work/baseline
../../build/eip_branch_baseline --config ../../config/eip-spike.conf --timings baseline.csv
cd ../instrumented
../../build/eip_branch_instrumented --config ../../config/eip-spike.conf --timings instrumented.csv
```

Expected: both exit zero, all 30 measured `result` values match round-for-round,
baseline emits no `.eip` files, and instrumented mode emits one complete file
per worker thread plus the main thread only if it records instrumented blocks.

- [ ] **Step 4: Commit the fixture**

```bash
git -C sandbox/eip-phase0 add CMakeLists.txt config/eip-spike.conf apps/branch_fixture.cpp include/eip/spike/runtime.hpp
git -C sandbox/eip-phase0 commit -m "Add real baseline and instrumented workloads"
```

---

### Task 5: Learn valid edges and identify a real novel path

**Files:**
- Create: `sandbox/eip-phase0/apps/analyze_trace.cpp`
- Modify: `sandbox/eip-phase0/apps/branch_fixture.cpp`
- Modify: `sandbox/eip-phase0/CMakeLists.txt`

**Interfaces:**
- Produces CLI commands:
  - `eip_analyze inspect <trace-dir>`
  - `eip_analyze learn <trace-dir> <edge-set-path>`
  - `eip_analyze check <trace-dir> <edge-set-path>`
- Consumes: only valid `ReadTrace` output; malformed or gap traces make every
  command nonzero.

- [ ] **Step 1: Write the failing analyzer integration test in CTest**

Add a CTest script that:

1. runs the instrumented fixture with `--scenario common` into
   `test-work/analyzer/common`;
2. runs `eip_analyze learn` to produce `allowed.edges`;
3. runs `eip_analyze check` on the same trace and expects exit `0`;
4. runs the fixture with `--scenario rare` into `test-work/analyzer/rare`;
5. runs `check` against the common-only edge set and expects exit `10` plus
   `novel_edges` greater than zero;
6. reruns `learn` across both directories and expects the rare check to return
   `0`.

Run:

```bash
cmake --build sandbox/eip-phase0/build --target eip_analyze -j4
ctest --test-dir sandbox/eip-phase0/build -R eip_spike_analyzer --output-on-failure
```

Expected: build failure because the analyzer is absent.

- [ ] **Step 2: Implement canonical edge sets**

Represent an edge as `(uint32_t source, uint32_t target)`, ordered
lexicographically. `learn` reads every `.eip` file in sorted filename order,
rejects any invalid/gap trace, unions edges, and writes canonical lines:

```text
EIP-EDGESET 1
<source-decimal> <target-decimal>
```

`check` rejects malformed/duplicate/unsorted edge sets, counts trace edges not
present in the set, prints this exact machine-readable summary, and exits `10`
when the count is nonzero:

```text
files=INTEGER events=INTEGER learned_edges=INTEGER novel_edges=INTEGER gaps=INTEGER
```

- [ ] **Step 3: Add the real rare path**

`--scenario common` uses inputs that never satisfy a fourth branch.
`--scenario rare` injects exactly one input with the sentinel
`0x7fff000000000001ULL`; `WorkItem` handles it in a dedicated `noinline`
`RarePath` function that performs deterministic arithmetic and no I/O. Both are
legitimate program paths. This test demonstrates cold-start false positives,
not an exploit and not enforcement.

- [ ] **Step 4: Run the integration and commit**

```bash
cmake --build sandbox/eip-phase0/build --target eip_analyze eip_branch_instrumented -j4
ctest --test-dir sandbox/eip-phase0/build -R eip_spike_analyzer --output-on-failure
git -C sandbox/eip-phase0 add CMakeLists.txt apps/analyze_trace.cpp apps/branch_fixture.cpp
git -C sandbox/eip-phase0 commit -m "Detect novel runtime paths without hiding gaps"
```

Expected: common succeeds against its baseline; rare is novel until explicitly
included in the authorized learning set.

---

### Task 6: Measure completeness, event rate, and overhead

**Files:**
- Modify: `sandbox/eip-phase0/apps/analyze_trace.cpp`
- Create: `sandbox/eip-phase0/tests/measurement_test.cmake`
- Modify: `sandbox/eip-phase0/CMakeLists.txt`

**Interfaces:**
- Produces: `eip_analyze benchmark <baseline.csv> <instrumented.csv> <trace-dir>`
  with stable key/value output.
- Consumes: 30 baseline rows, 30 instrumented rows, complete trace files.

- [ ] **Step 1: Add a failing benchmark-analysis test**

Create fixed real CSV inputs during the CTest step by executing the two fixture
binaries with `iterations=10000`, `threads=2`, and capacity large enough not to
overflow. Invoke `benchmark` and require keys:

```text
rounds=30
result_mismatches=0
trace_files=INTEGER
events=INTEGER
gaps=0
baseline_p50_ns=INTEGER
baseline_p95_ns=INTEGER
instrumented_p50_ns=INTEGER
instrumented_p95_ns=INTEGER
p95_overhead_percent=DECIMAL
events_per_second=DECIMAL
```

Run and expect failure because `benchmark` is not implemented:

```bash
ctest --test-dir sandbox/eip-phase0/build -R eip_spike_measurement --output-on-failure
```

- [ ] **Step 2: Implement strict timing analysis**

Parse the header exactly, require unique rounds `0..29`, require positive
nanoseconds, require identical result per round, sort timing copies, define p50
as index `14` and p95 as index `28`, and calculate:

```text
p95_overhead_percent = 100 * (instrumented_p95 - baseline_p95) / baseline_p95
events_per_second = total_events / sum(instrumented_nanoseconds / 1e9)
```

Exit nonzero for mismatch, gap, malformed CSV, missing round, zero baseline, or
zero trace events. Print measurements even when the performance target is
missed; the report, not the analyzer, decides readiness.

- [ ] **Step 3: Run the full test suite and a release-scale measurement**

```bash
cmake --build sandbox/eip-phase0/build -j4
ctest --test-dir sandbox/eip-phase0/build --output-on-failure
mkdir -p sandbox/eip-phase0/results/release
cd sandbox/eip-phase0/run-work/baseline
../../build/eip_branch_baseline --config ../../config/eip-spike.conf --timings ../../results/release/baseline.csv
cd ../instrumented
../../build/eip_branch_instrumented --config ../../config/eip-spike.conf --timings ../../results/release/instrumented.csv
cd ../..
build/eip_analyze benchmark results/release/baseline.csv results/release/instrumented.csv run-work/instrumented/traces > results/release/summary.txt
```

Expected: every CTest passes, results match, gaps are zero, and the summary
contains measured values rather than a hardcoded readiness label.

- [ ] **Step 4: Commit the analyzer measurement support**

```bash
git -C sandbox/eip-phase0 add CMakeLists.txt apps/analyze_trace.cpp tests/measurement_test.cmake
git -C sandbox/eip-phase0 commit -m "Measure real path tracing cost and completeness"
```

---

### Task 7: Produce the evidence-backed Phase 0 decision

**Files:**
- Create: `docs/research/2026-08-23-execution-integrity-phase-0-results.md`
- Read: `sandbox/eip-phase0/results/release/summary.txt`
- Read: `sandbox/eip-phase0/.git/logs/HEAD`
- Read: `docs/superpowers/specs/2026-08-23-execution-integrity-platform-design.md`

**Interfaces:**
- Produces: the outer-repository evidence record and the `READY`,
  `READY WITH NON-BLOCKING LIMITATIONS`, or `BLOCKED` decision for Phase 1.
- Consumes: only measurements and test output generated by Tasks 1–6.

- [ ] **Step 1: Re-run all evidence from a clean spike build directory**

Move the old build directory to `sandbox/eip-phase0/build-previous` rather than
deleting it, then configure/build/test a fresh explicit target:

```bash
mv sandbox/eip-phase0/build sandbox/eip-phase0/build-previous
cmake -S sandbox/eip-phase0 -B sandbox/eip-phase0/build -DCMAKE_BUILD_TYPE=Release
cmake --build sandbox/eip-phase0/build -j4
ctest --test-dir sandbox/eip-phase0/build --output-on-failure
```

Expected: all tests pass from the clean build. If they do not, stop and report
`BLOCKED`; do not copy earlier passing output into the report.

- [ ] **Step 2: Write the result document with exact evidence**

Use these sections and populate every numeric field from the real summary:

```markdown
# Execution Integrity Phase 0 Results

Date: 2026-08-23
Host: Darwin 25.5.0 arm64
Compiler: Apple Clang 21.0.0

## Scope
## Commands executed
## Test results
## Trace completeness
## Common versus rare path result
## Performance measurements
## Observed limitations
## Phase 1 decision
```

The decision rules are fixed:

- `READY`: all clean-build tests pass, `result_mismatches=0`, `gaps=0`, all
  expected real threads produce traces, common/rare behavior matches Task 5,
  and release-scale p95 overhead is at or below 15%.
- `READY WITH NON-BLOCKING LIMITATIONS`: all correctness/completeness conditions
  pass but p95 overhead is above 15%; Phase 1 must begin with hot-path cost
  reduction before adding enforcement semantics.
- `BLOCKED`: any missing/malformed/gap trace, result mismatch, nondeterministic
  test, inability to reproduce from the clean build, or missing rare-path signal.

State explicitly that a passing result validates measurement feasibility only;
it does not validate security enforcement, ML efficacy, SaaS authority, Quark
integration, or attestation.

- [ ] **Step 3: Verify the evidence document and preserve worktree boundaries**

```bash
rg -n 'T[B]D|T[O]DO|F[I]XME|<[[:alnum:]_-]+>' docs/research/2026-08-23-execution-integrity-phase-0-results.md
git diff --check -- docs/research/2026-08-23-execution-integrity-phase-0-results.md
git -C sandbox/eip-phase0 status --short
git status --short
```

Expected: the placeholder scan prints nothing; outer status shows only the new
result document plus pre-existing user changes; the nested status contains only
ignored/untracked build and result artifacts, not uncommitted source changes.

- [ ] **Step 4: Commit only the outer evidence report**

```bash
git add -- docs/research/2026-08-23-execution-integrity-phase-0-results.md
git commit -m "Record execution integrity phase 0 evidence" -- docs/research/2026-08-23-execution-integrity-phase-0-results.md
```

Expected: the commit contains one new document and none of the user's existing
Quark changes.

## Plan self-review record

- Spec coverage: this plan covers only the spec's explicit Phase 0 measurement
  spike and preserves the repository, offline, claim-level, privacy, and real-OS
  constraints. Phase 1 native enforcement, Phase 2 Quark Linkload integration,
  Phase 3 SaaS, Phase 4 ML, and Phase 5 trusted-anchor work intentionally require
  separate plans after this evidence exists.
- Placeholder scan: task instructions contain no unresolved implementation
  placeholders; runtime-output examples name their expected value types rather
  than carrying fill-in tokens.
- Type consistency: `Config`, `TraceEvent`, `TraceFile`, runtime entry points,
  and analyzer command names are defined once and consumed under the same names.
- Security honesty: dynamically learned edges are labeled measurement behavior,
  not a production allowlist; callbacks and MAC-free traces are never called
  enforcement or attestation.
