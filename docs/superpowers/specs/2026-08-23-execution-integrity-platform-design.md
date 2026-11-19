# Embeddable Execution Integrity Platform

> Superseded for future implementation by
> `2026-08-23-execution-integrity-platform-v2-design.md`. This file remains the
> approved v1 architecture and the authority for the completed Phase 0 spike.

Status: architecture approved by the user ("evet soru sorma goalin belirlendi").
This document defines a new product, not a server component inside Quark.
Date: 2026-08-23

## Executive decision

Build an independent, multi-tenant security platform that developers add to
native programs through a build integration and a small runtime SDK. The
platform observes the program's actual control-flow path, enforces deterministic
local rules, learns normal-but-valid path distributions in the cloud, and
returns signed policy bundles to the runtime.

The product is deliberately **not** "an ML model that decides whether arbitrary
assembly is safe." The authority order is fixed:

1. The final binary and its build manifest define which control-flow edges are
   structurally possible.
2. The local deterministic policy decides which structurally possible edges
   are allowed for a protected region and context.
3. ML assigns risk only inside that allowed set. It can never turn a forbidden
   edge into an allowed edge.
4. A hard cryptographic attestation claim is made only when the report is
   accumulated in a trusted anchor outside attacker-writable process memory.

Quark is the first reference integration. Quark's offline core remains offline:
`quark_core`, `quark_c_api`, and the unlock path gain no SaaS dependency and no
network calls. The optional product adapter consumes a signed local policy
bundle and can operate with export disabled. Cloud connectivity belongs to the
independent product's collector, not to Quark's licensing authority.

## Why this architecture exists

Code signing proves which bytes were loaded. CFI, PAC, BTI, CFG, and shadow
stacks restrict several ways to redirect execution. Neither tells a developer
which legitimate path the program actually took, and neither alone catches a
security-critical variable being corrupted so that the program follows a
valid-but-unauthorized branch.

Control-flow attestation research shows the useful primitive:

- C-FLAT constructs a cumulative measurement of the executed control-flow path
  and protects the measurement with ARM TrustZone. It also documents the
  combinatorial difficulty of complex paths and the boundary around pure
  data-oriented attacks.
- ScaRR splits complex executions into partial reports bounded by checkpoints,
  validates them remotely, and explicitly assumes a trusted anchor plus
  standard W^X/DEP/ASLR-style mitigations. It reports an average verification
  rate of two million control-flow events per second in its SPEC CPU 2017
  evaluation, but also documents incomplete CFG extraction, syscall/context
  switch cost, and valid-path data attacks as limitations.
- LLVM already provides real compiler insertion points at function, basic-block,
  edge, comparison, and indirect-call granularity. These are suitable for a
  prototype and measurement spike. Production enforcement needs a dedicated
  pass because coverage instrumentation can prune points and its guard state is
  intentionally mutable.

The product opportunity is to turn those primitives into an integration that a
normal software team can operate: build identity, policy lifecycle, privacy-safe
telemetry, conservative anomaly learning, incident evidence, and real native-OS
validation.

## Product boundary

### Product surfaces

| Surface | Customer role | Responsibility |
|---|---|---|
| Build SDK and CLI | Developer/CI | Instrument a build, emit the final build manifest, sign/publish it |
| Runtime SDK | Protected program | Enforce local policy, record ordered path evidence, fail closed on deterministic corruption |
| Local collector | Host operator | Drain runtime buffers, batch/authenticate evidence, apply redaction, export optionally |
| SaaS control plane | Security/development team | Manage tenants, projects, builds, policies, rollouts, incidents, and keys |
| ML plane | Security team | Train and evaluate build-specific anomaly models; produce candidate risk policy |
| Policy signer/distributor | Runtime fleet | Issue versioned, rollback-resistant signed bundles |
| Trusted-anchor adapters | High-assurance deployments | Accumulate evidence outside attacker-writable process memory |

### Repository boundary

The platform implementation belongs in its own repository and release
lifecycle. This Quark repository may contain:

- this architecture and its Quark-specific integration contract;
- a small optional adapter after the independent SDK exists;
- real Quark reference tests that run entirely under `sandbox/`.

It must not contain the SaaS control plane, model-training services, tenant
database, or a general telemetry backend. Adding those here would contradict
Quark's explicit "no server component, offline and hardware-bound" mission and
turn the native cryptographic core into a product-infrastructure dumping ground.

## Threat model and claim levels

### MVP assumptions

The MVP assumes:

- the final build pipeline and manifest-signing key are trusted;
- the OS kernel, loader, and executable-page protections are trusted;
- the attacker begins in user space, typically after a memory-safety bug;
- W^X/DEP, platform code signing where available, ASLR, stack protection, and
  available CFI/PAC/CET/BTI protections are enabled and measured;
- JIT/self-modifying code is outside the generic MVP path;
- physical, kernel, hypervisor, administrator-controlled debugger, and malicious
  build-server attacks are outside the MVP guarantee.

### Three explicit claim levels

| Level | Evidence source | Honest claim |
|---|---|---|
| Monitor | In-process SDK | Detects modeled deviations and anomalies; evidence is not unforgeable after arbitrary process compromise |
| Enforce | Instrumented SDK + OS/hardware CFI mitigations | Blocks deterministic policy violations before a protected successor body executes, subject to instrumentation and platform guarantees |
| Attest | Trusted kernel/TEE/hypervisor/hardware-trace adapter | Produces challenge-bound path evidence that compromised application code cannot forge |

No marketing or API may call Monitor or Enforce output "cryptographic remote
attestation." An in-process hash/MAC chain is only tamper-evident while its key
and update routine remain outside the attacker's control. If both live in the
compromised address space, arbitrary read/write/control-flow capability can steal
the key, suppress events, or call the update routine on a fabricated path.

### Inherent non-guarantees

- A valid CFG path can still be semantically malicious if security-relevant data
  was corrupted. Critical-state commitments narrow this class but cannot infer
  the full semantics of arbitrary C/C++ automatically.
- Pure data-oriented attacks that change a pointer or output without changing
  control flow are not detected by path evidence alone.
- Dropped events invalidate a strong attestation interval. The system must emit
  an explicit gap and stop calling that interval verified; it must never fill in
  a plausible path.
- ML is vulnerable to evasion, poisoning, and privacy attacks. Training data is
  therefore treated as untrusted input, not as automatic ground truth.
- A hostile kernel or administrator can tamper with a normal user-space SDK and
  collector. Stronger deployments require a platform-specific trusted anchor.

## Architectural approaches considered

### Approach A: local deterministic enforcement plus cloud ML — selected

The runtime checks the signed manifest and local policy, records path evidence,
and responds immediately to deterministic violations. The cloud learns frequency,
context, and sequence anomalies among paths that remain structurally valid.

Advantages:

- no network round trip is needed to protect a critical transition;
- offline operation is real, including the Quark reference integration;
- ML false positives do not weaken deterministic security;
- telemetry can be reduced to build-scoped IDs, counters, and digests;
- customers can begin in Monitor mode and promote measured rules.

Cost: a dedicated compiler integration and runtime are still required, and the
MVP evidence is not unforgeable without a trusted anchor.

### Approach B: stream every transition to a cloud verifier — rejected as primary

This resembles a direct hosted ScaRR-style verifier. It gives centralized
visibility but makes availability and latency part of every protected program's
correctness. It creates high event volume, exposes more behavioral metadata, and
cannot stop damage that occurs before the remote response. It remains useful as
an opt-in high-observability mode, not the default enforcement architecture.

### Approach C: ship an ML-only local sequence model — rejected

This is easy to demo but creates the exact dishonest product claim the design is
meant to avoid. A model can miss a novel attack, reject a rare valid path, or be
poisoned. It has no independent authority over code identity or allowed edges.
It may be used as one scorer inside the selected architecture, never as the root
of trust.

## System architecture

```text
developer source
      |
      v
instrumenting compiler/pass -----> build metadata
      |                                  |
      v                                  v
 final linked binary ----------> signed BuildManifest
      |                                  |
      +------------------+---------------+
                         v
                  protected runtime
                  +------------------+
                  | local policy     |
execution edges ->| per-thread trace |--> optional local collector
critical state -->| deterministic    |             |
                  | verifier         |             v
                  +------------------+       SaaS ingestion
                         |                         |
                         v                         v
                continue/restrict/abort   feature + model plane
                                                  |
                                                  v
                                         signed PolicyBundle
```

### 1. Build instrumentation and manifest generation

The first implementation targets native C/C++ compiled with Clang/LLVM. Rust
through LLVM, Go, JVM bytecode, and binary rewriting are later integrations,
not MVP requirements.

The pipeline is ordered:

1. A compiler pass inserts two-sided transition instrumentation in selected
   protected regions: a source-edge check immediately before control transfer
   and a target-entry confirmation before the successor body.
2. The linker produces the final binary normally.
3. A post-link tool resolves final section/function/block identities, code
   hashes, call/return metadata, dynamic-module declarations, and required
   platform hardening flags.
4. CI signs the immutable `BuildManifest` and associates it with the digest of
   the exact final binary.
5. Packaging may encrypt/seal the already-instrumented binary. Decryption must
   restore the same signed build identity.

LLVM SanitizerCoverage with `bb,no-prune,trace-pc-guard` is acceptable for a
throwaway feasibility probe because it inserts real basic-block/edge callbacks.
It is not the production enforcement mechanism: guard variables can be disabled,
coverage callbacks are not an unskippable security boundary, and the framework
permits instrumentation pruning unless configured otherwise.

### 2. BuildManifest

The canonical, versioned manifest contains:

```text
manifest_version
tenant_id, project_id, build_id
binary_digest, target_triple, compiler_identity
instrumentation_version
modules[]
basic_blocks[] { block_id, module_id, function_id, code_digest, flags }
edges[] { source_id, target_id, kind, context_rule }
protected_regions[] { region_id, entry_ids, exit_ids, action }
critical_state_schema[] { field_id, capture_kind, privacy_rule }
required_hardening[]
signing_key_id, signature
```

`block_id` and `edge_id` are scoped to an immutable `build_id`; IDs are never
assumed stable across optimization or software versions. The SaaS must not blend
paths from different builds unless an explicit developer-signed mapping says the
semantic identity is preserved.

### 3. Runtime SDK

The runtime exposes a small C ABI so C++, Rust, Go/cgo, Python native extensions,
and JNI hosts can use the same implementation. Language-specific wrappers do not
reimplement security logic.

Responsibilities:

- verify the manifest and policy signatures against provisioned tenant roots;
- verify that the running binary/module identity matches the manifest;
- maintain per-thread sequence numbers and call/return context;
- record compact transition IDs into fixed-capacity per-thread buffers;
- check forbidden edges and protected-region rules locally;
- compute declared critical-state commitments through typed callbacks;
- expose explicit `verified`, `monitor_only`, `evidence_gap`, `policy_stale`, and
  `unavailable` states;
- apply a configured response: observe, restrict a capability, terminate the
  protected operation, or fail-deadly.

The SDK never manufactures a valid report after overflow, initialization
failure, unsupported dynamic code, manifest mismatch, or a missing trusted
anchor requested by policy.

### 4. Path evidence

Events are not individually signed. The hot path appends compact records:

```text
thread_id | sequence | source_block | target_block | event_kind | state_ref
```

The collector closes bounded chunks and commits to their order:

```text
chunk_digest[i] = H(
    protocol_domain || build_id || session_nonce || thread_id ||
    first_sequence || last_sequence || previous_chunk_digest || encoded_events
)
```

Monitor/Enforce mode authenticates exported chunks at the collector boundary.
Attest mode performs accumulation/authentication inside the trusted-anchor
adapter. Standard, reviewed primitives are used; the product does not invent a
new signature or MAC algorithm.

Thread order is represented honestly. Per-thread order is total. Cross-thread
relationships are added only at observed synchronization events (thread create/
join, mutex/condition/atomic annotations, IPC boundaries). Wall-clock timestamps
are diagnostic metadata, never the authority for path order.

### 5. Critical-state commitments

Control flow alone cannot distinguish `authenticated=true` produced legitimately
from the same value produced by corruption. Developers can declare a small set of
security-relevant state transitions through typed SDK annotations/callbacks.

The runtime records a domain-separated digest of the declared value, provenance
label, and transition context. Raw secrets, customer input, pointers, memory
addresses, and whole object dumps are forbidden from telemetry. Values are either
represented by a low-cardinality label or a tenant-keyed commitment.

This feature is deliberately explicit. Automatically hashing arbitrary writable
memory would be expensive, privacy-hostile, nondeterministic, and still unable to
prove that the selected memory represented the program's real authorization
semantics.

### 6. Local policy engine

`PolicyBundle` is signed, versioned, bound to compatible build IDs, and carries
an anti-rollback sequence. It contains:

- forbidden and required edges/regions;
- call/return and indirect-target constraints;
- required platform hardening and trusted-anchor level;
- evidence-buffer and gap behavior;
- critical-state commitment rules;
- ML score thresholds and allowed responses;
- expiry for policy freshness, used only for policy lifecycle, not Quark license
  expiry or Lamport authority;
- the previous accepted policy sequence and signer identity.

Decision precedence is fixed:

| Observation | Default action |
|---|---|
| Binary/manifest/signature mismatch | Fail protected initialization |
| Edge impossible or forbidden by deterministic policy | Stop before successor body; emit violation if possible |
| Required event missing or buffer gap | Mark interval unverifiable; enforce configured fail-closed region rule |
| Structurally valid path with high ML risk | Restrict/challenge in opt-in policy; observe by default |
| ML unavailable, stale, or uncertain | Preserve deterministic rules; never synthesize a low-risk result |

### 7. Local collector

The collector is a separate process where the OS permits it. It is optional in
offline deployments and mandatory for SaaS export. It:

- drains bounded shared-memory buffers;
- detects sequence gaps and process restarts;
- batches and compresses evidence;
- performs allowlist-based redaction and data minimization;
- attaches build/project/session identity without raw code addresses;
- exports through an authenticated TLS connection;
- spools bounded data under an explicit retention policy when offline.

OpenTelemetry may be used to correlate product incidents with customer traces,
but execution evidence uses its own typed protocol. Generic log pipelines allow
processors to rewrite/drop events and do not provide the ordering, gap, build
binding, or attestation semantics required here.

### 8. SaaS control plane and PaaS API

Core entities are `Tenant`, `Project`, `Build`, `Manifest`, `Policy`, `Session`,
`EvidenceChunk`, `ModelCandidate`, `ModelRelease`, and `Incident`.

The PaaS exposes authenticated APIs for:

- CI build registration and manifest publication;
- evidence ingestion with idempotent chunk identity;
- session and incident queries;
- model training/evaluation jobs;
- signed policy rollout, canary, rollback, and revocation;
- export to customer SIEM/OTel pipelines.

Multi-tenant authority is enforced server-side on every object relationship.
Tenant signing keys and service encryption keys are distinct. Training jobs read
only the tenant/project/build partitions explicitly assigned to the job. Raw
binary uploads are not required by the protocol.

### 9. ML plane

The ML problem is build-conditioned sequence anomaly detection, not malware
classification and not natural-language generation.

Initial features:

- edge and short edge-n-gram frequencies;
- call/return context and indirect-target distributions;
- loop-count distributions within checkpoint-bounded regions;
- syscall/library boundary categories;
- synchronization-aware per-thread path fragments;
- declared critical-state labels/commitments;
- evidence gaps and hardening capability state.

Model progression is evidence-driven:

1. deterministic CFG/policy validation;
2. count, n-gram, Markov, and robust quantile baselines;
3. a compact sequence model only if it improves held-out attack detection at
   the same or lower false-positive rate and operational cost;
4. no LLM in the runtime decision path.

Training authority is conservative:

- CI traces enter the trusted baseline only when produced by an authorized,
  signed build/test job;
- production traces initially enter an untrusted candidate pool;
- the platform never automatically labels repeated production behavior benign;
- candidate releases must pass held-out valid-path, injected-attack, poisoning,
  cross-version, and calibration gates;
- every model release records dataset identities, code/version, metrics,
  thresholds, and signer approval;
- rollback returns to the last signed deterministic policy plus last accepted
  model, never to an unsigned implicit default.

### 10. Trusted-anchor interface

The architecture defines, but the MVP does not pretend to implement, a portable
interface for strong evidence:

```text
BeginSession(build_id, challenge) -> session_handle
Extend(thread_id, sequence, transition) -> status
CloseChunk(session_handle) -> signed_measurement
EndSession(session_handle) -> signed_summary
DescribeCapabilities() -> typed capability set
```

Possible backends include a kernel monitor, TEE/hypervisor component, or a
hardware branch-trace consumer protected from the target process. Intel PT can
reconstruct detailed control flow with low perturbation, but it is a tracing
facility rather than an attestation root by itself; collection, completeness,
buffer-overflow handling, key protection, and verifier freshness remain separate
problems. Each backend receives its own real-OS specification and validation.
Unsupported platforms return `unavailable`, never a software-generated
"hardware attested" result.

## Quark reference integration

### Integration choice

The first reference uses `quark_linkload`, not `quark_codecipher`:

- Linkload seals a whole, normally compiled Mach-O image, so the platform's
  Clang instrumentation and manifest are produced before Quark sealing.
- Unlock restores the exact instrumented binary and `dyld` loads it normally.
- Codecipher materializes relocated executable bytes in `MAP_JIT` memory and
  therefore needs a separate dynamic-code registration and final-page identity
  design. That is a later integration, not an MVP shortcut.

### Offline authority boundary

The adapter flow is:

```text
Quark HWID + Lamport + witnesses
             |
             v
      content_key / Unseal
             |
             v
 instrumented signed module + local signed PolicyBundle
             |
             v
 local execution integrity (network optional and outside quark_core)
```

No cloud result grants, extends, renews, or proves a Quark license. ML risk
cannot create `content_key`, modify Lamport depth, or override a witness failure.
At most, an opt-in customer policy can refuse to run an already-valid protected
operation because its local execution-integrity prerequisites are unavailable.

### First real demonstration

Use the existing complex `HWID_Extractor` Linkload fixture as the protected
program. Produce an instrumented build, seal the whole binary, unlock/load it
through the real Quark path, and compare its output with a normally executed
instrumented control. Then exercise real controlled deviations in a separate
fixture; do not mutate the production HWID implementation merely to create an
attack.

All compilation, fixtures, trace files, local collector state, and tests remain
under `sandbox/` as required by this repository. No mock OS, crypto, loader,
network, or execution source is acceptable.

## MVP scope

### Included

- separate product repository/package boundary;
- Clang/LLVM C/C++ instrumentation on macOS ARM64;
- final-build manifest and Ed25519-signed policy lifecycle;
- C ABI runtime with per-thread buffers and deterministic local edge policy;
- local collector with export disabled by default;
- minimal multi-tenant ingestion, build/session/incident APIs;
- per-build n-gram/Markov baseline and calibrated risk score;
- signed model/policy promotion with poisoning-resistant training gates;
- Quark Linkload reference integration in offline mode;
- real exploit/valid-path/performance evaluation under `sandbox/`.

### Explicitly excluded

- claiming Monitor/Enforce evidence is hardware attestation;
- kernel modules, TEE, hypervisor, or Intel PT authority in the MVP;
- automatic ML hard blocking;
- JIT/self-modifying code and Quark Codecipher registration;
- Windows/Linux runtime support before native-runner implementations pass;
- Go/JVM/Rust-specific instrumentation before the C ABI/native path is proven;
- source-level automatic discovery of business authorization semantics;
- raw source, binary, pointers, secrets, customer payloads, or memory dumps in
  SaaS telemetry;
- packaging, signing, deployment, or production SaaS operation from this Quark
  repository's current compile-only authority.

## Failure semantics

Failures are typed by capability and evidence status, not collapsed into a fake
success:

- `manifest_invalid`
- `binary_identity_mismatch`
- `policy_invalid`
- `policy_rollback`
- `instrumentation_incomplete`
- `evidence_gap`
- `forbidden_transition`
- `critical_state_violation`
- `collector_unavailable`
- `cloud_unavailable`
- `model_unavailable`
- `trusted_anchor_unavailable`

The runtime's outward consequence is policy-controlled, but the evidence record
always preserves the precise typed cause locally. Sensitive values, addresses,
keys, or remediation hints are not included in customer-facing crash text.

## Security and privacy invariants

1. ML cannot allow an edge forbidden by the signed deterministic policy.
2. A missing event is a gap, never an inferred benign transition.
3. A policy/model is accepted only when signature, build compatibility, sequence,
   and freshness rules pass.
4. Production observations never become trusted training data automatically.
5. Raw code addresses, inputs, secrets, and arbitrary memory are not exported.
6. Quark license authority remains exclusively inside its offline HWID/Lamport/
   witness cryptographic path.
7. Every attestation claim names the evidence source and claim level.
8. Unsupported platform capabilities return `unavailable`.
9. The SaaS cannot silently weaken an already-installed deterministic policy.
10. A model rollout is reversible without changing the protected binary.

## Real validation strategy

### Correctness

- compile a real branching/multithreaded C++ fixture with the dedicated pass;
- prove manifest IDs match the final linked binary;
- execute every declared valid edge and verify no false deterministic violation;
- produce a real illegal indirect transition and return mismatch and verify the
  successor protected body does not execute;
- overflow an evidence buffer and prove the interval becomes `evidence_gap`;
- replay, reorder, delete, and duplicate chunks and prove rejection;
- attempt policy downgrade/rollback and wrong-build policy use.

### Adversarial cases

- real stack return-address corruption fixture;
- real function-pointer/vtable corruption fixture;
- real injected-code attempt against non-executable memory;
- valid-path authentication-flag corruption fixture;
- pure data-pointer corruption fixture, expected to demonstrate the documented
  control-flow-only limitation unless the pointer/state is explicitly committed;
- SDK callback suppression attempt, expected to demonstrate why Monitor mode is
  not Attest mode;
- candidate-training poisoning and evasion attempts.

These fixtures are contained, non-networking programs whose only payload is a
test marker under their sandbox working directory. They do not attack external
processes or customer systems.

### ML evaluation

Split by session and build provenance, never by individual event rows. Maintain:

- authorized baseline traces;
- held-out valid rare paths;
- held-out mutations of loop counts and call order;
- real controlled exploit traces;
- poisoned candidate traces;
- a separate later-build transfer set.

Report precision, recall, false-positive rate per session, detection latency,
calibration error, and coverage by attack class. Do not summarize the result as
"accuracy" alone. The launch gate for default Monitor mode is no ML-caused hard
blocks, a measured per-session false-alert rate at or below 0.5% on the held-out
valid set, and complete publication of known blind spots. Opt-in ML blocking is
not an MVP feature.

### Performance gates

Measure native baseline versus instrumented runs on the same hardware:

- default critical-region mode: p95 CPU overhead target <= 5%;
- full-edge diagnostic mode: p95 CPU overhead target <= 15%;
- local deterministic decision occurs before the protected successor body;
- collector backpressure never silently drops evidence;
- offline mode performs zero network calls;
- cloud unavailability does not weaken or stall deterministic local enforcement.

These are acceptance targets, not current results. Missing a gate blocks the
corresponding mode from being called production-ready; it does not justify
changing the number after the test.

### Cross-platform lifecycle

After the real macOS ARM64 MVP:

1. Linux implementation and execution on a real Linux kernel, with its own CFI,
   loader, collector, and optional hardware-trace evaluation.
2. Windows implementation and execution on a real Windows runner, with CFG/CET,
   loader, service/collector, and signing behavior verified.
3. Only then publish a cross-platform support claim.

Cross-compilation without execution is not acceptance evidence.

## Delivery phases

### Phase 0 — independent repository and measurement spike

Create the product boundary, protocol schemas, threat-claim registry, and a
throwaway SanitizerCoverage-based overhead/trace-completeness probe. The probe
answers whether the event volume and callback design are viable; none of its
instrumentation is promoted as security enforcement.

### Phase 1 — deterministic native core

Build the dedicated LLVM pass, final manifest generator, C ABI runtime, local
policy engine, per-thread evidence buffers, local collector, signed policy
lifecycle, and real adversarial fixtures. Exit criterion: deterministic behavior
and performance gates pass on macOS ARM64.

### Phase 2 — Quark offline reference

Instrument and seal the real Linkload `HWID_Extractor` fixture, load it through
the real Quark unlock path, prove output equivalence, and run local policy with
all network/export disabled. Exit criterion: Quark authority remains unchanged
and no cloud component is required for unlock or execution.

### Phase 3 — minimal SaaS/PaaS

Implement tenant/project/build/session/incident authority, idempotent evidence
ingestion, signed policy distribution, bounded retention, audit logging, and
OTel/SIEM export. Exit criterion: multi-tenant authorization and replay/rollback
tests pass with real services.

### Phase 4 — conservative ML

Implement the deterministic statistical baseline, candidate/trusted dataset
separation, evaluation registry, poisoning gates, model signing, shadow rollout,
and incident explanations. A more complex sequence model is added only if it
beats the baseline under the fixed held-out protocol.

### Phase 5 — strong attestation research

Specify one platform backend at a time. A backend ships only after it proves
freshness, event completeness, key isolation, gap handling, and native-OS
performance. Product claim levels remain platform-specific.

## Sources informing the design

- C-FLAT, *Control-Flow Attestation for Embedded Systems Software*:
  https://download.hrz.tu-darmstadt.de/media/FB20/Dekanat/Publikationen/TRUST/c-flat-ccs-2016.pdf
- ScaRR, *Scalable Runtime Remote Attestation for Complex Systems*:
  https://www.usenix.org/system/files/raid2019-toffalini.pdf
- LLVM SanitizerCoverage:
  https://clang.llvm.org/docs/SanitizerCoverage.html
- LLVM XRay:
  https://llvm.org/docs/XRay.html
- Clang Control Flow Integrity:
  https://clang.llvm.org/docs/ControlFlowIntegrity.html
- Clang Pointer Authentication:
  https://clang.llvm.org/docs/PointerAuthentication.html
- Intel Processor Trace overview:
  https://www.intel.com/content/www/us/en/support/articles/000059254/processors/intel-xeon-processors.html
- NIST AI 100-2e2025, *Adversarial Machine Learning: A Taxonomy and
  Terminology of Attacks and Mitigations*:
  https://www.nist.gov/publications/adversarial-machine-learning-taxonomy-and-terminology-attacks-and-mitigations-0
- OpenTelemetry logs data model and sensitive-data guidance:
  https://opentelemetry.io/docs/specs/otel/logs/data-model/
  https://opentelemetry.io/docs/security/handling-sensitive-data/

## Final readiness rule

The design is ready for implementation planning when every task preserves the
repository boundary, claim levels, deterministic-over-ML authority order,
offline Quark boundary, and real-OS/no-mock verification requirements above.
Any implementation that replaces one of those with "the model will learn it"
is a different and weaker product and must be rejected.
