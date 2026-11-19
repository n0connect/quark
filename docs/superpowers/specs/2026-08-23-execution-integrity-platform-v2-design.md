# Embeddable Execution Integrity Platform — Revision 2.1

Status: approved direction derived from the completed Phase 0 evidence and the
user's request to improve the plan across engineering, security, ML, platform,
SaaS, operations, and product concerns.

Date: 2026-08-23

## Executive decision

Build a separate native execution-integrity product, but do not build a generic
"record every instruction and ask ML whether it is valid" system. The product
combines four different controls because they answer four different questions:

1. Platform hardening and compiler CFI constrain where control may transfer.
2. Developer-signed security transition automata constrain which valid program
   states and operations may follow one another in protected workflows.
3. Bounded path evidence describes what happened without becoming the runtime's
   root of trust.
4. Cloud ML ranks anomalies inside the deterministically permitted set and has
   no authority to allow, unlock, or attest execution.

The whole program's exact path tree is not enumerated. Loops, recursion,
concurrency, exceptions, callbacks, dynamic loading, and input-dependent state
make that representation combinatorial and often unbounded. The platform uses
the narrowest sound representation for each layer: CFG/CFI for target validity,
a visibly-pushdown call/return model where available, finite automata for
security workflows, and statistics for remaining variability.

Quark remains offline and hardware-bound. Its optional reference adapter can
consume local signed artifacts, but no network, SaaS response, or ML result is
allowed to grant a Quark license, produce `content_key`, change Lamport depth,
or suppress a witness failure.

## What Phase 0 actually proved

Phase 0 proved that real Apple Clang instrumentation, ordered per-thread traces,
gap rejection, common-path learning, and rare-path detection can be exercised
without mocks on macOS ARM64. It recorded 35,148,171 events with zero result
mismatches and zero gaps, and found seven novel edges in the rare scenario.

It did not isolate the cost of the callback itself. Short-lived worker threads
serialized their trace files during thread teardown inside each timed round, so
the measured 25,786.21% p95 overhead combines instrumentation, vector growth,
serialization, filesystem writes, and thread lifecycle. The conclusion is
therefore precise: the tested end-to-end per-basic-block recording design is
unusable in production. A second measurement phase must separate those costs
before selecting a production evidence mechanism.

Additional Phase 0 limitations that become explicit requirements:

- guard IDs were assigned at process initialization and are not stable build
  identities across DSO load order or a clean rebuild;
- consecutive guard callbacks are observations, not linker-proven CFG edges;
- edge membership loses call/return context and admits impossible sequences
  assembled from individually valid edges;
- mutable in-process callbacks can be suppressed after compromise;
- the microbenchmark is too small to represent a real long-lived service;
- no crash tail, signal, exception, `fork`, `dlopen`, or collector backpressure
  behavior was measured.

## Security model

### Attacker classes

Every claim names the strongest attacker it covers:

| Class | Capability | Covered by |
|---|---|---|
| A0 | Malformed input without memory corruption | application checks and automata |
| A1 | Limited user-space corruption before an arbitrary read/write/control primitive exists | CFI/PAC/CET plus mediated automata |
| A2 | Arbitrary read/write in target process | platform hardening may limit redirection; Monitor evidence is forgeable |
| A3 | Arbitrary target-process code execution | only a trusted external anchor can prove stronger evidence; an ordinary collector preserves only what it received |
| A4 | Administrator or hostile kernel | outside normal SDK claims; needs TEE/hypervisor/hardware-specific design |
| A5 | Compromised CI/signing authority | supply-chain controls, provenance, revocation; runtime cannot repair trust |
| A6 | Compromised SaaS/model pipeline | artifact authority separation prevents deterministic policy weakening |

### Product claim levels

| Level | Mandatory evidence | Honest claim |
|---|---|---|
| Harden | Verified binary identity and available platform CFI/PAC/CET/W^X settings | Reports and requires supported exploit mitigations |
| Monitor | Harden plus bounded in-process observations | Detects modeled anomalies; evidence is not unforgeable after A2/A3 |
| Enforce | Harden plus developer-signed automata and build-verified mediated effects | Stops declared invalid transitions under A0/A1 only for effects listed in the mediation report |
| Attest | Enforce plus challenge-bound external evidence anchor | Makes only the platform-specific claim proven by that anchor |

`Harden`, `Monitor`, `Enforce`, and `Attest` are typed capabilities, not a single
boolean. Unsupported requirements return `unavailable`. Marketing and APIs may
not rename Monitor evidence as attestation.

### Non-guarantees

- CFI does not prove business authorization.
- A path-valid data-only attack is invisible unless the relevant state is
  explicitly represented in a transition automaton or protected commitment.
- An in-process MAC does not survive arbitrary process compromise when its key
  and update function are available to the attacker.
- A TPM quote can authenticate a key and platform measurement, but it does not
  by itself prove the completeness of an application path trace.
- No learned model can establish that unseen behavior is impossible.

## Revised system architecture

```text
trusted CI/build authority
  |-- final signed binary digest + build provenance
  |-- signed BuildManifest
  `-- signed EnforcementPolicy
                |
                v
      +-------------------------+
      | Native runtime          |
      | hardening verifier      |
      | transition automata     |---- stop/restrict protected operation
      | bounded evidence plane  |
      +-------------------------+
                |
                v
       optional local collector ---- optional export ---- SaaS ingestion
                                                            |
                                           untrusted candidate evidence
                                                            |
                                                            v
                                                   ML shadow evaluation
                                                            |
                                                            v
                                         incidents + signed cloud profile
                                         (no MVP runtime decision input)
```

The runtime has two deliberately separate data paths:

- The decision path is allocation-free, lock-free or thread-local, contains no
  filesystem/network operation, and evaluates only deterministic artifacts.
- The evidence path is lossy only when it says so explicitly. Backpressure,
  overflow, crash tails, and unavailable collectors create typed gaps; they do
  not alter deterministic decisions unless the signed enforcement policy
  explicitly requires complete evidence for that protected operation.

## Artifact and key separation

One monolithic `PolicyBundle` is rejected because an online model signer must
not be able to weaken deterministic enforcement. Three artifact schemas plus
independent TUF repository metadata are parsed by authority-specific verifiers:

### BuildManifest

Produced after the final executable is linked and code-signed. It is detached
from the binary to avoid a self-hash/signature cycle.

```text
schema_version
tenant_id, project_id, build_id
artifact_digest, loadable_segments_digest, code_directory_hash
target_triple, compiler_identity, linker_identity
module_digests[], code_signature_identity
instrumentation_schema, stable_site_table_digest
protected_effect_table_digest, mediation_report_digest
required_hardening[]
builder_identity, provenance_digest
```

An embedded site ID cannot be derived from the final binary digest: embedding
that value would change the digest and create a self-hash cycle, while macOS
code signing changes the final file again. Instead, `site_local_id` is assigned
before the final link from an explicit developer effect/transition ID, compiler
module namespace, and deterministic collision-checked ordinal. The canonical
post-link table binds those IDs to final offsets and mediation classes.
`build_id` is then derived from a domain-separated digest of the target,
loadable-segment digest, entitlement/requirement digest, and final site-table
digest; it is not embedded back into the executable. Runtime and evidence
identity is the pair `(build_id, site_local_id)`. Runtime registration order and
raw addresses are never identity, and a changed build gets a changed build ID
rather than silently reusing another build's policy scope.

Hashing the executable's filesystem path does not prove the identity of pages
already mapped by the loader and creates a path/TOCTOU ambiguity. On macOS the
runtime binds the manifest to the loaded Mach-O image address/slide, UUID,
CodeDirectory hash, Team ID, designated requirement, registered module table,
and the final artifact digest recorded by CI. A Mach-O UUID is only a module
locator, never security proof. File digest remains supply-chain evidence;
loaded-image trust comes from verified OS loader/code-signing capability and
code-page validation. Unknown,
unsigned, or late-loaded executable modules make a protected operation
`dynamic_module_unregistered` unless the signed manifest explicitly allows the
module digest and load class.

### EnforcementPolicy

Signed only by the customer's release/security authority:

```text
schema_version, policy_id, policy_epoch
compatible_build_ids[]
required_capabilities[]
automata[], protected_effects[]
gap_actions[], unavailable_actions[]
```

The policy contains no model weights and no server-provided allow edges.

### DetectionProfile

Signed by a narrowly delegated online model-release key:

```text
schema_version, profile_id, profile_epoch
compatible_build_ids[]
feature_schema_digest, model_digest
thresholds[], explanation_schema
training_snapshot_ids[], evaluation_report_digest
```

The MVP runtime does not parse DetectionProfile at all. The cloud detection
worker uses it for shadow scoring and incident explanation. A future local
detector requires a new schema and threat review; it cannot be smuggled into the
runtime through a DetectionProfile field. ML cannot return allow for a
deterministic denial.

### Distribution metadata and wire encoding

Do not invent a custom updater. BuildManifest, EnforcementPolicy, and
DetectionProfile bodies use RFC 8949 deterministic CBOR with a checked-in CDDL
schema, no floating-point values, no duplicate keys, no indefinite lengths, and
strict rejection of non-deterministic encodings. Artifact signatures use
COSE_Sign1 (RFC 9052) with external AAD binding the product domain, artifact
type, schema version, tenant, project, and build scope. The macOS MVP accepts
exactly COSE `ES256` with a P-256 key and rejects every other `alg`, curve, and
key-use combination before signature verification. Ed25519 or another profile
requires a separately versioned capability and interoperability plan; shipping
two signature stacks initially adds attack surface without an MVP requirement.
Signing-key ID and algorithm live in the protected COSE header; signature bytes
and signing-key identity are not duplicated inside the signed body, eliminating
two potentially contradictory authorities.

Artifact distribution adopts a tenant-scoped TUF repository rather than a
home-grown `DistributionMetadata`: offline threshold root, delegated target
roles, snapshot, timestamp, consistent snapshots, and a documented POUF. The
enforcement target role is delegated only for `enforcement/`; a model-release
role delegated only for `models/` cannot sign or replace an enforcement target.
Online SaaS snapshot/timestamp keys can publish freshness metadata but cannot
authorize a new EnforcementPolicy.

TUF metadata uses TUF's normative metadata encoding, signatures, hash/length,
version, expiry, and client update workflow. It is not re-encoded as CBOR or
wrapped in COSE. COSE authenticates the typed artifact target itself; TUF
authenticates repository role, delegation, version, and delivery metadata.

Distribution freshness and local rollback resistance remain separate. The
runtime stores the highest accepted root, targets, snapshot, and enforcement
epochs in platform-protected state. If that state is unavailable, it returns
`rollback_protection_unavailable`; it never claims rollback protection from a
version stored beside the replaceable policy file.

Root keys are offline and use a threshold role. Build, enforcement,
model-release, snapshot, and timestamp keys
are different roles with different rotation and compromise procedures. SaaS
workers never receive the customer root or enforcement private key.

The first trusted TUF root is provisioned out of band with the SDK/project
configuration. Root rotation follows TUF's threshold and version rules; a root
downloaded from the same untrusted repository is never accepted as its own
trust bootstrap.

Wall-clock expiry is not rollback authority when the host lacks trusted time.
Such a host reports `freshness_time_untrusted` and relies only on its protected
highest-seen epochs under the declared A0/A1 threat model. Full-disk or whole-VM
snapshot rollback and offline revocation without newly delivered metadata are
documented ceilings, not silently claimed as solved.

## Deterministic execution model

### Layer 1: platform hardening

The build records and the runtime verifies applicable features:

- macOS ARM64: Hardened Runtime, every weakening entitlement, library
  validation, W^X, code-signing identity, stack protection, and pointer
  authentication capability only where the emitted ABI and load commands prove
  its use—not merely because the CPU supports PAC;
- Linux: W^X/NX, PIE/RELRO, Clang CFI or KCFI where compatible, and later
  hardware trace through `perf` AUX only as a measured optional capability;
- Windows: DEP, ASLR, Control Flow Guard, and hardware-enforced stack protection
  where supported.

These platforms do not expose identical guarantees. The capability report is a
matrix and support claims remain per OS/architecture/toolchain.

Clang CFI requires LTO for its normal userspace schemes and hidden visibility
for important C++ modes; cross-DSO support is experimental. Phase 1B must first
compile, link, load, and corrupt a real protected Mach-O configuration and emit
`cfi_unavailable` if Apple Clang/linker/DSO constraints prevent the promised
scheme. Hardened Runtime or PAC presence is not relabeled as Clang CFI.

### Layer 2: security transition automata

Developers declare a small number of security boundaries, not every branch:

```text
automaton_id = "invoice-release"
states = [created, authorized, signed, transmitted]
transition = (authorized -> signed)
site = build-scoped checkpoint ID
guard = role_label == approver
on_violation = stop_protected_operation
```

The compiler emits a checkpoint immediately before a protected effect. The
runtime advances a per-operation automaton only when the current state,
checkpoint, context label, and call are permitted. Direct basic-block edges are
not redundantly checked. Indirect calls use the strongest supported compiler/OS
CFI; return integrity uses PAC/shadow-stack capability where available.

Transition arguments are low-cardinality labels or tenant-keyed commitments.
Raw secrets, pointers, addresses, customer inputs, and object dumps are
forbidden. Because the checkpoint is still in-process, Enforce does not claim
resistance to A3 unless an external anchor also controls the protected effect.

### Layer 2b: mediated protected effects

A checkpoint that returns a boolean is not enforcement. An attacker may skip
the check, call a type-compatible effect directly, corrupt the boolean, or jump
to code after the branch. Every effect claimed as Enforce therefore has an
explicit mediation class:

| Class | Construction | Claim ceiling |
|---|---|---|
| observed | checkpoint records intent; effect remains directly callable | Monitor only |
| guarded | hidden effect symbol is reachable only through a generated wrapper; build verifier rejects other references | Enforce for A0/A1, not A2/A3 |
| interlocked | one-use operation-bound permit is consumed as data required by the protected computation, not only an `if` result | stronger A1 resistance; still not A2/A3 in one address space |
| isolated | separate broker/privilege boundary validates the permit and owns the protected resource | backend-specific stronger claim after real validation |

For the macOS MVP, guarded/interlocked code lives in one hidden-visibility
ThinLTO protected module. The only exported entry is the generated wrapper.
Cross-DSO CFI is not assumed: Clang documents it as experimental with an
unstable ABI. The post-link verifier emits `MediationReport` containing every
protected effect, wrapper, remaining reference, visibility, LTO/CFI capability,
and whether the data dependency survived optimization. Any unmediated reference
downgrades that effect to Monitor or fails the signed policy.

An `ei_permit_t` is opaque, single-use, bound to build, policy epoch, operation,
effect, transition, and generation. Copy/replay, cross-operation use, and use
after end fail. This prevents accidental/limited misuse; because the permit and
consumer share process memory, it is not described as unforgeable under A2/A3.

Operations are thread-confined by default. Cross-thread continuation requires
an explicit `ei_operation_handoff` that consumes the source generation and
creates a destination generation. Concurrent use without handoff is a typed
violation, not a last-writer-wins automaton update.

### Layer 3: bounded evidence

The selected evidence mechanism must be chosen by measurement. Candidates are:

1. automaton-only checkpoints for deterministic decision cost;
2. automaton plus bounded per-thread summary for default Monitor evidence;
3. ordered checkpoint ring for laboratory diagnosis and incident detail;
4. SanitizerCoverage inline counters plus PC tables for unordered coverage;
5. gated callbacks restricted to short diagnostic windows;
6. a minimal compiler-emitted function-boundary candidate if ordered function
   evidence is still needed after the checkpoint result;
7. platform hardware trace as an optional later adapter.

LLVM XRay/FDR is not a macOS candidate: current LLVM documentation lists its
runtime support on Linux AArch64 and selected BSD/x86 targets, not Darwin. Phase
1A records that capability as `unavailable`; XRay may be evaluated later on a
real supported Linux runner rather than being treated as a portable shortcut.

Hot-path invariants:

- no heap allocation after initialization;
- no mutex, syscall, filesystem write, network call, symbolization, signature,
  or general cryptographic operation per event;
- bounded thread-local storage;
- explicit sequence/generation and overflow state;
- flushing occurs outside the measured protected operation;
- process exit, thread exit, crash, signal, exception, and collector death have
  defined evidence semantics.

Per-thread order is authoritative. Cross-thread order exists only at observed
synchronization/checkpoint relationships, never from wall-clock guesses.

## Native SDK contract

The stable C ABI returns typed status and never throws or terminates the host by
default:

```c
ei_status_t ei_runtime_create(const ei_runtime_options_t*, ei_runtime_t**);
ei_status_t ei_operation_begin(ei_runtime_t*, uint64_t automaton_id,
                               ei_operation_t**);
ei_status_t ei_transition_observe(ei_operation_t*, uint64_t site_id,
                                  const ei_label_t*, size_t label_count);
ei_status_t ei_transition_prepare(ei_operation_t*, uint64_t site_id,
                                  uint64_t effect_id, const ei_label_t*,
                                  size_t label_count, ei_permit_t**);
ei_status_t ei_operation_handoff(ei_operation_t*, uint32_t destination_slot,
                                 ei_operation_t** destination_generation);
ei_status_t ei_operation_end(ei_operation_t*, ei_operation_result_t*);
ei_status_t ei_runtime_capabilities(ei_runtime_t*, ei_capability_report_t*);
void ei_permit_destroy(ei_permit_t*);
void ei_operation_destroy(ei_operation_t*);
void ei_runtime_destroy(ei_runtime_t*);
```

ABI rules:

- every public struct begins with `struct_size` and `abi_version`;
- ownership, thread safety, reentrancy, `fork`, unload, and signal behavior are
  documented per function;
- the library allocates only during create/begin; transition permits come from a
  bounded per-operation pool provisioned at begin and exhaustion is typed;
- generated guarded/interlocked wrappers call an internal hidden permit-consume
  entry point; ordinary host code is not given a public "mark permit valid" API;
- `terminate_process` is an opt-in signed policy action; the default failure
  stops the protected operation and returns a typed fault;
- initialization cannot silently downgrade a requested capability.

## Collector and evidence protocol

The collector is a separate least-privileged process. Shared memory transport
uses generation-tagged bounded rings and authenticated control messages. The
collector cannot change an enforcement result.

Evidence chunks bind:

```text
protocol_domain, schema_version
tenant_id, project_id, build_id
session_nonce, process_instance_id
thread_id, generation, first_sequence, last_sequence
previous_chunk_digest, payload_digest
capability_report_digest, gap_bitmap
collector_key_id, authentication
```

Replay, duplicate, reordering, cross-build substitution, truncated crash tails,
and process restart are distinct outcomes. Compression occurs before transport
authentication only in a fixed reviewed encoding; decompression has explicit
size and ratio limits.

For Monitor, the collector authentication key detects transport/storage
corruption and cross-session substitution before process compromise. Because an
A2/A3 attacker in the runtime address space may reach key material or the
producer, this MAC is never promoted to Attest evidence.

Offline spooling is bounded by bytes and age. Exhaustion follows an explicit
drop-oldest, stop-export, or fail-protected-operation policy. It never fills the
disk without a configured bound.

## SaaS/PaaS design

### Authority boundary

The SaaS is an evidence and lifecycle service, not the execution oracle. Local
deterministic enforcement continues during cloud outage. The control plane may
distribute customer-authorized EnforcementPolicy artifacts but cannot create
one with a model-service key.

### Tenancy and data model

Every stored object carries immutable `tenant_id`, `project_id`, and where
applicable `build_id`. Authorization validates the full parent chain, not just
an artifact ID. Core entities are:

```text
Tenant, Principal, ServiceIdentity, Project, Environment
Build, BuildProvenance, Manifest, EnforcementPolicy
DetectionProfile, DatasetSnapshot, ModelEvaluation
Session, EvidenceChunk, GapRecord, Incident
SigningRole, KeyVersion, DistributionSnapshot
RetentionPolicy, ExportSink, AuditEvent
```

Ingestion requires a tenant-scoped service identity, idempotency key, content
digest, declared uncompressed size, and build registration. Per-tenant quotas
cover requests, bytes, sessions, retained evidence, training compute, and
exports. A noisy tenant cannot consume another tenant's queue or model capacity.
Human principals use federated OIDC plus tenant-scoped roles; collectors use
short-lived workload credentials bound to tenant/project/build and mTLS where
the deployment supports it. Long-lived global ingestion keys are forbidden.

### Data protection

- TLS is mandatory in transit; envelope encryption uses tenant/project data
  keys with auditable KMS rotation.
- Evidence IDs are pseudonymous, not called anonymous. Path fragments can be
  behavioral fingerprints.
- Raw code addresses, source, binaries, secrets, payloads, and arbitrary memory
  are rejected by schema and content-size policy.
- Retention, regional placement, legal hold, export, and deletion are explicit
  tenant settings with verifiable deletion jobs.
- Operator access is just-in-time, reason-bound, and audited.

### Reliability

Control-plane availability is not runtime safety. Initial service objectives:

- policy/build reads: 99.9% monthly availability;
- accepted ingestion: 99.9% monthly availability;
- no acknowledged chunk loss;
- p95 ingestion acknowledgement below 500 ms in the deployment region;
- recovery-point objective below 15 minutes for control metadata;
- recovery-time objective below 4 hours for regional control-plane recovery.

These are pre-production targets and require load, backup-restore, and regional
failure evidence before being advertised.

### Product packaging and FinOps

The managed product sells build/policy lifecycle, ingestion, retention, export,
and incident analytics—not an unverifiable promise to block every exploit.
Usage meters count only durably acknowledged bytes/sessions with idempotent
reconciliation. Per-tenant budgets expose projected storage and training cost;
hard quota actions stop or sample cloud ingestion according to policy but never
relax local deterministic enforcement. Subscription or billing failure can
disable future cloud service after a declared grace policy; it cannot revoke a
previously valid offline Quark license or turn a local denial into allow.

MVP deployment is a managed regional control plane with export off by default.
Private-region or customer-operated ingestion is a later deployment profile
with its own key custody, upgrade, support, backup, and SLO evidence—not a
configuration checkbox on the managed service.

## ML and MLOps design

ML begins only after stable build IDs, feature schemas, provenance, and an
operational shadow dataset exist. The first model is an interpretable exact
baseline, not a neural sequence model.

MVP inference runs asynchronously in the tenant-partitioned cloud detection
worker. It creates incidents but sends no allow/deny result into a live protected
operation. This makes model outage, latency, and rollback operational concerns
rather than local safety dependencies.

### Dataset authority

- authorized CI/test sessions form the trusted-valid candidate set;
- production sessions are untrusted observations and never auto-promote;
- exploit fixtures are labeled by attack class and precondition;
- splits are by session, build provenance, scenario family, and time, never by
  individual event row;
- every dataset snapshot is immutable and records source identities, filters,
  feature code digest, and exclusions;
- deletion and consent changes propagate to future snapshots and models.
- minimum training size is determined by a recorded power/uncertainty analysis
  for the tenant/build alert-rate target; a convenient row count is not treated
  as statistical sufficiency.

### Evaluation ladder

1. exact transition and n-gram counts for protected automata;
2. robust quantiles and Markov baselines for bounded region summaries;
3. a compact sequence model only when it improves a locked comparison protocol;
4. no LLM in the decision path.

Metrics include per-session false-alert rate, alerts per 1,000 sessions,
precision/recall by attack class, detection latency, AUCPR under real class
imbalance, calibration error/Brier score, abstention rate, coverage, model size,
and inference cost. Every reported metric includes a confidence interval and
the exact evaluation snapshot.

Evaluation also includes temporal holdout, leave-one-scenario-family-out,
leave-one-attack-family-out, cold-start builds, and later-build transfer. Event
rows from the same session, generated input seed, machine, or derived mutation
cannot cross a split boundary.

Promotion requires:

- zero ML-caused hard blocks because blocking is outside the MVP;
- false alerts at or below 5 per 1,000 held-out valid sessions;
- no regression in any declared critical attack class versus the accepted
  baseline;
- successful poisoning, evasion, replay, cross-build, and cross-version tests;
- shadow and canary observation with signed approval;
- instant rollback to the last accepted DetectionProfile.

Drift creates `model_stale` or `model_unavailable`; it does not retrain or
relax thresholds automatically.

ML has an explicit kill rule: if the exact statistical baseline already meets
the incident-value target, or a learned model cannot improve the locked primary
metric by a predeclared practically significant margin without worsening any
critical attack class or the alert budget, the product ships deterministic
analytics only. "Uses AI" is not an acceptance criterion.

## Product and developer experience

The MVP customer journey must be possible without reverse-engineering the SDK:

1. `ei init` creates a project-local config and trust-root reference.
2. `ei build` instruments selected modules and produces a manifest plus a
   machine-readable capability report.
3. `ei validate` runs local policy, ABI, hardening, and privacy checks.
4. `ei test` executes valid/invalid workflow fixtures and creates a local report.
5. `ei publish` is optional and publishes only explicitly selected artifacts.

Default export is off. Default ML mode is shadow. Default deterministic
violation action stops the protected operation, not the whole process.
Integrating one protected workflow into the reference application should take
less than one engineer-day after prerequisites are installed; this is measured
in a clean-room usability exercise before beta.

Version support is a matrix of OS, architecture, compiler, linker, binary
format, runtime ABI, instrumentation schema, and claim level. "Cross-platform"
is not a single badge.

## Verification program

### Native correctness and security

- real C/C++ workloads with direct/indirect calls, recursion, exceptions,
  signals, tail calls, `setjmp`/`longjmp`, threads, `fork`, and dynamic modules;
- real stack return, function pointer, vtable, valid-path flag, and data-pointer
  corruption fixtures whose payload is only a sandbox marker;
- malformed/fuzzed manifest, policy, profile, and evidence parsers;
- ASan, UBSan, and TSan runs in addition to optimized release tests;
- deterministic site-table generation for identical compile/link inputs,
  changed-build separation, ASLR, post-sign manifest binding, and DSO load-order
  tests;
- crash, process kill, collector kill, quota exhaustion, disk-full boundary,
  replay, reordering, and rollback tests;
- binary size, RSS, startup, p50/p95/p99 latency, event volume, and sustained
  throughput measurements with confidence intervals.

No mock OS, loader, crypto, filesystem, network service, or trace producer is
accepted as release evidence. Real service dependencies may run in sandboxed
containers on their native OS.

### Supply chain

- pinned compiler/toolchain and dependency manifests;
- build provenance bound to final artifact digest;
- isolated CI signing roles and short-lived credentials;
- SBOM and vulnerability scan gates;
- reproducible-build comparison where supported;
- root/build/enforcement/model key rotation and compromise drills;
- artifact revocation and client recovery from an expired or compromised role.

### SaaS and operations

- full tenant-boundary matrix for every API and background job;
- real PostgreSQL/object-store/queue/KMS-compatible integration tests;
- backup and restore, retention deletion, regional failure, and audit-log tests;
- load tests with one abusive tenant and verified fair-use isolation;
- cost-per-million-sessions and bytes-per-session budgets;
- incident runbooks for signing compromise, ingestion loss, model poisoning,
  privacy request, and false-positive surge.

## Performance measurement contract

Measurements interleave randomized baseline and candidate runs on the same
host. A baseline calibration fixes each workload near 50 ms per round before any
candidate is measured; sub-millisecond rounds are rejected because scheduler and
timer noise dominate their percentage ratios. Each candidate uses at least ten
fresh processes and 50 measured rounds per workload after warmup.

Confidence intervals use a hierarchical bootstrap: resample process clusters,
then rounds within each selected process. Treating 500 rounds from ten processes
as 500 independent machines is pseudoreplication and is rejected. Report raw
machine-readable samples, process-level distributions, and bootstrap 95%
intervals. Do not silently discard outliers.

Before the matrix, record host model, OS/toolchain, power source, load average,
available memory, and baseline coefficient of variation. If the predeclared
environmental stability gate fails, return `environment_unstable`; do not rerun
until a favorable sample appears. macOS chip temperature is not claimed unless
a privileged measured source is actually available.

Costs are measured separately:

1. build-time and binary-size cost;
2. automaton-only decision cost;
3. decision plus bounded summary cost;
4. ordered raw-ring diagnostic cost;
5. drain/copy cost;
6. serialization/compression/authentication cost;
7. collector and export cost.

Workloads include branch-heavy CPU, call/return-heavy CPU, allocation-heavy,
long-lived multithreaded, short-lived-thread stress, and the real Quark fixture.
Disk I/O and thread teardown are outside the protected-operation timer unless
that specific cost is being measured.

Gates use the upper bound of the bootstrap 95% confidence interval, not only the
point estimate:

- default automaton-only and automaton-plus-summary modes: each p95 overhead <=
  5%, p99 <= 8%;
- function-boundary diagnostic mode: p95 overhead <= 10%;
- full-edge laboratory diagnostic mode: p95 overhead <= 15%;
- default-mode binary growth <= 10%;
- default-mode post-warmup RSS growth <= 16 MiB per process plus configured
  bounded buffers, measured with Mach task information; lifetime peak RSS is
  reported separately and is not relabeled as steady state;
- zero silent gaps and zero workload result mismatch;
- initialization p95 <= 25 ms excluding customer-controlled signature I/O;
- no hot-path allocation, syscall, lock, disk, network, or per-event crypto.

Missing a gate blocks that mode; it does not change the threshold.

## Delivery roadmap with independent gates

### Phase 1A — cost-model selection

Measure automaton-only, automaton-plus-summary, ordered-ring, inline-counter,
and gated-callback modes and—if still justified—a minimal function-boundary pass
with separated costs and realistic workloads. Record XRay/FDR as unavailable on
macOS rather than simulating it. Phase 1C stays blocked until the automaton
decision path passes the 5%/8% gates; Phase 1D stays blocked until the bounded
automaton-plus-summary evidence mode passes the 5%/8% default gate and its
completeness semantics are reproducible. An ordered laboratory ring cannot
substitute for that default. Phase 1B's artifact-only work may proceed during one bounded
optimization iteration when the automaton p95/p99 upper bounds are at most
7%/10% and all correctness conditions pass.

### Phase 1B — artifact and trust contracts

Implement canonical schemas, deterministic build-local site IDs and final
post-link tables, detached build identity,
artifact signatures, key roles, tenant-scoped TUF metadata, rollback capability
reporting, and parser fuzzing. Exit when clean-build, wrong-build, malformed,
replay, rotation, and rollback tests pass.

### Phase 1C — deterministic native enforcement

Implement the C ABI runtime, platform hardening report, protected-operation
automata, generated mediated-effect wrappers, post-link MediationReport, and
typed failures on macOS ARM64. Exit when valid workflows pass, controlled
violations stop before protected effects, every claimed effect has no remaining
unmediated reference, and performance/sanitizer gates pass.

### Phase 1D — local collector

Implement the Phase 1A-selected default bounded summary, bounded shared-memory
drain, chunk chaining, crash/gap semantics,
compression limits, authenticated local spool, and export-off mode. Exit when
kill, overflow, disk-bound, replay, and sustained-load tests pass.

### Phase 1E — adversarial release candidate

Run the complete corruption, valid-path, data-only, callback-suppression,
dynamic-module, and usability suites. Publish the exact claim matrix and blind
spots. No SaaS or Quark integration starts before this gate.

### Phase 2 — Quark offline reference

Instrument a real Linkload whole-module fixture, create signed local artifacts,
seal/unseal/load it through Quark, prove output equivalence, and verify with all
network/export disabled. Quark Codecipher remains excluded until dynamic code
identity has its own design.

### Phase 3A — SaaS authority foundation

Build tenant/project/build identity, service authentication, artifact registry,
key-role integration, audit, retention, quotas, and idempotent ingestion with
real services. No ML is present.

### Phase 3B — operations and PaaS

Add session/incident queries, signed distribution, canary/rollback, SIEM export,
backup/restore, regional deployment, SLO evidence, SDK onboarding, and usage
metering. Runtime enforcement remains independent of service availability.

### Phase 4 — conservative ML

Build immutable dataset lineage, exact statistical baseline, locked evaluation,
shadow deployment, explanations, poisoning/evasion gates, and signed
DetectionProfile release. More complex models require measured superiority.

### Phase 5 — platform expansion

Port and execute the native stack on real Linux, then real Windows. Each port
has its own hardening, loader, collector, signing, and performance acceptance.

### Phase 6 — strong attestation research

Specify one trusted backend per platform. Ship only after challenge freshness,
key isolation, trace completeness, gap behavior, replay resistance, verifier
semantics, and native performance are proven. Claim levels remain backend- and
platform-specific.

## Stop rules

Stop and redesign rather than advance when any of these is true:

- no automaton decision mechanism meets the 5%/8% p95/p99 gates for Phase 1C,
  or at least falls inside the single-iteration 7%/10% optimization band that
  permits only Phase 1B artifact work;
- the post-sign manifest cannot bind the loaded build, or identical compile/link
  inputs produce an unexplained site-table change;
- a deterministic violation can reach the protected effect before rejection;
- a protected effect remains callable through an unmediated symbol/reference
  while carrying an Enforce claim;
- rollback protection is claimed without protected local state;
- an online/model key can alter deterministic enforcement;
- a gap is represented as a valid path;
- production observations become trusted training data automatically;
- a tenant-boundary test or signing-compromise drill fails;
- Quark unlock or licensing depends on cloud availability;
- Monitor or Enforce evidence is marketed as Attest.

## Sources

- Phase 0 evidence: `docs/research/2026-08-23-execution-integrity-phase-0-results.md`
- LLVM SanitizerCoverage: https://clang.llvm.org/docs/SanitizerCoverage.html
- LLVM XRay and FDR: https://llvm.org/docs/XRay.html
- Clang CFI: https://clang.llvm.org/docs/ControlFlowIntegrity.html
- Apple Hardened Runtime: https://developer.apple.com/documentation/security/hardened-runtime
- Apple pointer authentication: https://developer.apple.com/documentation/Apple-Silicon/improving-control-flow-integrity-with-pointer-authentication
- Microsoft Control Flow Guard: https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard
- Linux perf AUX ring buffer: https://www.kernel.org/doc/html/latest/userspace-api/perf_ring_buffer.html
- C-FLAT: https://download.hrz.tu-darmstadt.de/media/FB20/Dekanat/Publikationen/TRUST/c-flat-ccs-2016.pdf
- ScaRR: https://www.usenix.org/system/files/raid2019-toffalini.pdf
- NIST AI 100-2e2025: https://doi.org/10.6028/NIST.AI.100-2e2025
- NIST SSDF 1.1: https://doi.org/10.6028/NIST.SP.800-218
- SLSA build provenance: https://slsa.dev/spec/v1.2/build-requirements
- RFC 8949 deterministic CBOR: https://www.rfc-editor.org/rfc/rfc8949.html
- RFC 9052 COSE: https://www.rfc-editor.org/rfc/rfc9052.html
- The Update Framework 1.0.36: https://theupdateframework.github.io/specification/latest/
- LLVM benchmarking guidance: https://llvm.org/docs/Benchmarking.html
- OpenTelemetry sensitive-data guidance: https://opentelemetry.io/docs/security/handling-sensitive-data/
