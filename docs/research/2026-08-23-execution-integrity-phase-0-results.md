# Execution Integrity Phase 0 Results

Date: 2026-08-23

Host: Darwin 25.5.0 arm64

Compiler: Apple Clang 21.0.0 (`clang-2100.1.1.101`)

## Scope

This phase measured whether a disposable macOS ARM64 probe can record real
compiler-instrumented basic-block transitions, preserve workload results,
detect a legitimate but previously unseen path, reject incomplete evidence,
and quantify the cost of full-edge collection. It is an independent nested
repository under `sandbox/eip-phase0`; no probe or cloud component was added to
the offline Quark product.

The result validates measurement feasibility only. It does not validate
security enforcement, ML efficacy, SaaS authority, Quark integration, or
cryptographic attestation.

## Commands executed

The final evidence was regenerated after preserving the earlier build as
`sandbox/eip-phase0/build-previous`:

```text
cmake -S sandbox/eip-phase0 -B sandbox/eip-phase0/build -DCMAKE_BUILD_TYPE=Release
cmake --build sandbox/eip-phase0/build --parallel
ctest --test-dir sandbox/eip-phase0/build --output-on-failure
```

The release-scale common-path workloads were then run from their sandboxed
working directories with the checked-in `config/eip-spike.conf`:

```text
../../build/eip_branch_baseline --config ../../config/eip-spike.conf --timings baseline.csv --scenario common
../../build/eip_branch_instrumented --config ../../config/eip-spike.conf --timings instrumented.csv --scenario common
build/eip_analyze benchmark run-work/baseline/baseline.csv run-work/instrumented/instrumented.csv run-work/instrumented/traces
```

The clean-build rare-path evidence was re-read with:

```text
../../build/eip_analyze check rare/traces common.edges
```

## Test results

The clean Release build configured and compiled successfully. All six tests
passed from the fresh build directory:

| Test | Result | Real time |
|---|---:|---:|
| strict configuration parser | pass | 0.59 s |
| binary trace codec | pass | 0.35 s |
| bounded per-thread runtime and overflow gap | pass | 0.36 s |
| shared-source baseline/instrumented fixture | pass | 1.61 s |
| common/rare path analyzer | pass | 0.46 s |
| 30-round measurement analyzer | pass | 0.24 s |
| **Total** | **6/6 pass** | **3.61 s** |

Tests execute the real compiler instrumentation, filesystem, pthreads, and
process behavior. No mock OS or trace producer is used.

## Trace completeness

The release-scale run used 30 measured rounds and four worker threads. It
produced the expected 120 worker-thread files plus one main-thread file:

| Metric | Observed |
|---|---:|
| timing rounds | 30 |
| result mismatches | 0 |
| trace files | 121 |
| trace events | 35,148,171 |
| evidence gaps | 0 |
| sustained analyzed event rate | 51,126,517.69 events/s |

The runtime test also forces a two-event capacity and records a third event;
the resulting real trace is marked `kEvidenceGap`. The analyzer rejects such
evidence rather than treating a partial interval as complete.

## Common versus rare path result

A common-only run learned 84 unique edges. Checking the clean-build rare
scenario against that baseline produced:

```text
files=7 events=176122 learned_edges=84 novel_edges=7 gaps=0
```

The rare scenario therefore triggered the expected novel-path exit. Learning
over both legitimate scenarios subsequently accepted the rare trace. This is
also evidence of the cold-start problem: a valid but unrepresented path looks
novel until it is deliberately included in the authorized training corpus.

## Performance measurements

| Metric | Baseline | Instrumented |
|---|---:|---:|
| p50 round time | 103,125 ns | 21,740,834 ns |
| p95 round time | 120,250 ns | 31,128,167 ns |

- p50 overhead: 20,982.02%
- p95 overhead: 25,786.21%
- full-edge diagnostic target: at most 15% p95 overhead

The tested end-to-end implementation—per-basic-block callback, in-memory event
append, per-thread serialization, and synchronous trace-file write—exceeds the
target by several orders of magnitude. Worker thread teardown and trace writes
occurred inside each timed `RunRound`, so this number must not be attributed to
the callback alone. It is valid evidence that the combined design is not a
viable production hot path; Phase 1A must separate operation, finalize,
serialization, and write costs before selecting a replacement.

## Observed limitations

- Evidence is generated and stored by attacker-writable in-process code. It is
  measurement data, not a trusted attestation.
- Trace files and learned edge sets are deliberately unsigned in this spike.
- Edge membership alone loses calling context and cannot prove that every
  sequence composed from individually allowed edges is valid.
- A legitimate cold path produces a novel-path result until the build-specific
  corpus covers it; automatic promotion would create a poisoning boundary.
- Raw collection produced approximately 537 MiB for one release-scale run.
- The implementation is verified only on this Apple Silicon macOS host and
  uses Apple Clang SanitizerCoverage callbacks.
- The probe contains no ML, SaaS collector, policy signing, enforcement action,
  Quark Linkload integration, or trusted hardware/kernel evidence anchor.

## Phase 1 decision

**READY WITH NON-BLOCKING LIMITATIONS**

All fixed correctness and completeness conditions pass: the clean build is
reproducible, results match, all expected threads produce traces, gaps are
zero, overflow fails closed, and the common/rare signal is present. The p95
overhead is above 15%, so Phase 1 must begin with hot-path cost reduction before
adding enforcement semantics.

The next experiment should compare critical-region-only instrumentation,
per-thread transition aggregation, and OS/hardware trace ingestion. It should
retain deterministic local policy as authority, treat cloud/ML output only as
risk evidence inside the structurally allowed set, and reserve an attestation
claim for a design with a trusted anchor outside writable process memory.
