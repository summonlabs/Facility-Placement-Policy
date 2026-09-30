# Facility Placement Policy

Deterministic evaluation of allowable physical placement for DCCP Tranche 6
(Facility Policy, Tenancy, and Entitlement). It answers one question, and answers
it reproducibly:

> Given a proposed physical placement and the exact generation-bound evidence
> about the facility, the tenant, the service class, the failure domains and
> maintenance exposure, is that placement **allowed** by the canonical policy -
> and if not, which requirement refused it?

Version 1.0.0. Portable C++20, CMake, no third-party dependencies, no telemetry.

## What this runtime is

A policy authority. It owns a canonical policy revision and decides eligibility.
It does not plan, rank, reserve or execute anything.

The runtime is three things:

* a **policy model** - typed requirements over jurisdiction, facility metadata,
  failure domains, occupancy, co-tenancy and maintenance exposure, with a
  canonical digest that identifies one revision;
* a **pure evaluator** - a function from (policy revision, evidence, instant) to
  one verdict per candidate, with an explanation that names the rule, the
  constraint and the compared values;
* a **durable authority** - the active revision, the authority epoch that fences
  it, the override ledger and the anti-rollback watermarks, together with the
  locking, atomic publication and recovery rules that make those claims true.

### The exact owned boundary

Owned here:

* the policy document model, its validation, canonical order and digest;
* deterministic evaluation of typed constraints over candidate placements;
* generation-bound verdicts, their explanation and their fencing rules;
* the override envelope model, grant issuance, usage accounting and the fixed
  set of hard interlocks that no override can reach;
* the canonical policy revision, authority epoch, override ledger, watermarks
  and the durable state that holds them.

Explicitly not owned here:

| Concern | Owner |
| --- | --- |
| Choosing the "best" candidate, ranking or ordering allowed candidates | Facility Placement Planner |
| Reserving rack units, power, cooling or space | Facility Capacity Reservation |
| Executing a placement, installing or commissioning an asset | Facility Change Orchestrator, Commissioning Fabric |
| Scheduling workloads onto placed assets | Agent Scheduler, Collective Scheduler |
| Routing, path selection, traffic engineering | Path Planner, Route Fabric |
| Facility structure and failure-domain membership | Facility Topology, Failure Domain Registry |
| Tenant, service-class, incident and maintenance records | Tenant Registry, Service Class Registry, Maintenance Coordinator, Facility State Ledger |

No external effect is simulated here. Where an adjacent authority owns a fact,
this runtime consumes a generation-bound snapshot of it and binds the decision to
that generation. There is no code path in this repository that reserves,
installs, schedules or routes anything.

## The core question, precisely

An evaluation takes:

* one **policy snapshot**: a canonical policy revision, an authority epoch, a
  store sequence and two watermarks;
* one **request**: tenant, service class, evaluation instant, the generation of
  every authority whose facts are used, facility records, candidate placements,
  occupancy evidence and maintenance evidence;
* optionally one **grant** per facility, which exercises an override envelope.

It produces, for every candidate, **eligible** or **ineligible**, plus the list
of rules that applied, the list that did not, and every violation with a stable
code and the values that were compared.

There are only two decisions. Anything else - stale evidence, an unknown
envelope, an expired grant, a corrupt store, an unmeasurable dimension - is a
**refusal**: an Error with its own stable code, never a quiet "yes".

## Principal invariants

1. **A policy can only narrow placement.** Rules are conjunctions of
   requirements. There is no rule form that permits, exempts or ranks. Two rules
   that demand incompatible things make every affected candidate ineligible.
2. **Absence is never agreement.** A facility with no published jurisdiction does
   not satisfy a jurisdiction requirement. A placement whose rack is unknown
   cannot be shown to be in a different rack. No occupancy evidence is not the
   same as no neighbours. No maintenance evidence is not the same as no
   maintenance.
3. **Every decision binds everything it depended on**: the policy identity,
   revision and digest, the authority epoch, the topology, failure-domain, tenant,
   service-class, occupancy and maintenance generations, the digest of the
   candidate-scoped evidence, and the evaluation instant.
4. **Evaluation is pure.** The same snapshot and the same request produce
   byte-identical verdicts, on any machine, in any order, at any time. The
   library never reads a clock: every instant comes from the caller.
5. **A batch is a set of independent evaluations.** Each candidate is evaluated
   against the same immutable evidence. No candidate is "placed" before the next
   is considered, so permuting the candidates cannot change any verdict, and the
   result is indexed by candidate identity rather than by position.
6. **No authority without a revision.** A store that has no active policy refuses
   every evaluation instead of allowing by default.
7. **Override uses are counted durably and cannot exceed the envelope.** A lost
   response is answered with the grant that was already issued rather than
   consuming a second use.
8. **Hard interlocks cannot be waived**, by any authority, under any policy, at
   any level. A policy that tries to make one overridable is rejected when it is
   loaded.
9. **Durable state is exactly one verified generation, or a refusal.** Nothing is
   repaired by guessing, merged, or silently started empty.
10. **A new authority epoch fences old authority atomically** with the
    publication that makes the new revision active.

## Rule and constraint semantics

A **rule** has an identity, an optional selector, an optional description and at
least one constraint. The rule applies when every field the selector states
agrees with the candidate; a field the selector omits is not a restriction. A
rule whose selector is empty applies to everything, which is the safe direction
for a rule and is refused for an override envelope.

A **constraint** is one of seven typed kinds:

| Kind | Means | Refuses |
| --- | --- | --- |
| jurisdiction | The facility's jurisdiction is in the allow set and not in the deny set | unknown jurisdiction, a denied jurisdiction, a jurisdiction outside the allow set |
| facility-attribute | A typed facility attribute compares as required (equal, not-equal, at-least, at-most, present, absent) | an attribute the facility does not publish, a value that fails the comparison |
| separation | The candidate's identity in one dimension is in the allow set and not in the deny set | an identity the rule denies or does not allow, a dimension the candidate does not declare |
| anti-affinity | At most N existing in-scope placements share the candidate's identity in a dimension | too many sharing, an in-scope placement whose identity in that dimension is unknown |
| redundancy | The in-scope placements plus the candidate span at least N distinct identities in a dimension | too little spread, an in-scope placement whose identity is unknown |
| co-tenancy | At most N placements of named tenants or service classes share the candidate's dimension identity | too many sharing, a forbidden placement whose identity is unknown |
| maintenance-exposure | No exposure at or above a severity threshold overlaps the lookahead horizon | a blackout or degraded window that applies, an exposure scoped somewhere the candidate does not declare, absent maintenance evidence |

An attribute key is not a free-form string: adding one is a code change with a
value type attached, which is what keeps jurisdiction and facility metadata from
degrading into name matching. A dimension identity is typed too: a rack identity
can never be compared against a room identity, even when the two spell the same.

### What is refused at load time, not evaluation time

* a policy with no rules, or a rule with no constraints;
* two rules, or two envelopes, with the same identity;
* a rule that can never be satisfied: a jurisdiction both allowed and denied, an
  attribute interval with nothing inside it, a single permitted value that is
  also excluded, two different required values for one enum attribute, a rule
  that requires an attribute to be both present and absent, or two allow-lists
  for one dimension that share no identity;
* an override envelope that reaches everything, names no principal, waives
  nothing, waives a hard interlock, or carries a use limit or a validity outside
  the permitted range;
* any unknown keyword, key, enum token or constraint kind.

Nothing is ignored: a silently ignored line in a policy is a silently weakened
policy.

## Authority, generations and fencing

**Policy revision and digest.** A store governs exactly one policy lineage.
Revisions advance by exactly one; the digest is computed from the canonical
encoding of every field, so two documents that differ only in authoring order
have the same identity.

**Authority epoch.** Activating a revision advances the epoch inside the same
manifest publication that makes the revision active. Every grant and every
verdict carries the epoch it was issued under, so a revision change fences all
outstanding authority at once.

**Watermarks.** The store remembers the newest topology and failure-domain
generation it has already accepted. A request that binds an older one is refused
with STALE_TOPOLOGY_GENERATION or STALE_FAILURE_DOMAIN_GENERATION, which is what
stops an old snapshot of the world from being replayed into a fresh decision.

**Per-verdict binding.** Tenant, service-class, occupancy and maintenance
generations have no global watermark because they are scoped facts; they are
bound into the verdict and checked by verify_verdict against the current state.
A verdict whose policy, epoch or any generation has moved is **fenced**: it is
history, and the report names every field that moved and in which direction.

## Lifecycle and state model

```text
init            store exists, sequence 1, epoch 1, no active policy
                evaluations are refused with NO_ACTIVE_POLICY
activate rev 1  sequence + 1, epoch 2, revision 1 active and retained
activate rev n  sequence + 1, epoch n + 1, revision n active
                beyond 16 revisions the oldest is dropped from the retention set
authorize       sequence + 1, one use consumed, one usage record retained
                (the most recent 512 are kept; the counter is never reduced)
record          sequence + 1, one verdict set retained as an immutable record
                (the most recent 64 are indexed), watermarks advanced
compact         sequence + 1, the ledger rewritten, unreferenced records removed
```

## Persistence and recovery model

```text
<store>/manifest.fpp          the head: published last, replaced atomically
<store>/manifest.fpp.bak      the state that was authoritative immediately before
<store>/lock.fpp              the single-writer lock
<store>/policies/             immutable, content-addressed policy records
<store>/ledger/               immutable, content-addressed ledger snapshots
<store>/evaluations/          immutable, content-addressed recorded verdicts
```

Every file is a framed record:

```text
magic           u64   little endian, per record kind ("FPP1MANI", "FPP1POLI", ...)
format_version  u32   currently 1
kind            u32   reserved: must be zero
reserved        u32   reserved: must be zero
payload_bytes   u64   at most kMaxRecordBytes
payload         payload_bytes bytes
crc32c          u32   over the payload only
digest          u8[32] SHA-256 over every byte above
```

The length must match exactly, and a record whose checksum or digest does not
verify is a corruption, not a formatting difference. A record's identity is the
digest that its own trailer carries, so it never covers itself.

**The atomic commit point is the replacement of manifest.fpp.** A commit stages
every record the new head will reference, flushes it to the device, reads it
back, verifies it byte for byte and by digest, and decodes it, and only then
publishes the head. The previous head is preserved as manifest.fpp.bak before the
new head is written, so both files a reader may choose between always reference
records that still exist.

**Recovery chooses exactly one generation or fails closed.** On open the head and
its predecessor are both read and verified:

* both verify and agree: the head governs;
* both verify and disagree: the higher sequence governs, and a head that is
  *older* than its predecessor is reported as a rollback and superseded;
* only one verifies: it governs, and the store reports which one was recovered;
* neither verifies while durable state exists: RECOVERY_REQUIRED, and nothing is
  guessed.

Then the whole referenced chain is verified: the active policy record against the
binding in the head, every retained revision, the ledger, every retained grant
digest, and every recorded evaluation payload. A store whose state cannot be
verified is refused rather than repaired.

**Rollback protection.** The sequence is monotonic and a head older than its
predecessor is refused. A threat model that includes an adversary who can rewrite
*both* manifest.fpp and manifest.fpp.bak consistently would need an external
monotonic counter, which this runtime does not have; it defends against
corruption, truncation and a stale copy, and it says so rather than implying
more.

**Single writer.** The store takes an exclusive operating-system file lock for
its lifetime in read-write mode, and a shared lock when opened read-only. The
lock is non-blocking, so a second writer is told STORE_LOCKED immediately instead
of waiting, and the kernel releases it when the process dies - including when it
is killed, which the crash suite exercises. A writer excludes readers: the lock is
one lock, not a reader-writer lock.

**Compaction** rewrites the ledger through the ordinary commit path and removes
records that neither the head nor its predecessor references. It cannot create a
state the ordinary reader would refuse, because the ordinary reader's
verification runs against the staged files before publication. Interrupted
publications leave temporary files; they are inert, they are counted in the store
status, and compaction removes them.

## Concurrency model

* One std::shared_mutex guards the in-memory state of a store.
* Read paths take it shared; the commit path takes it exclusive from the start.
  **No lock is ever upgraded in place**, which is the mistake that deadlocks.
* **No callback, sink or observer is invoked while a lock is held**, because the
  library has none: there is no logging hook, no progress callback and no event
  sink anywhere in the public surface.
* **File operations happen outside the lock** wherever the result can be computed
  first; the directory inspection that the status report needs is done after the
  state has been copied out.
* The library **starts no threads** and joins none.
* Cross-process exclusion is the operating-system lock alone. Ordering is fixed:
  the in-process lock is taken first, and the file lock is taken at open, before
  any record is read.

Two threads may therefore share one Store safely. Two processes may not both hold
it for writing.

## Errors, refusals and precedence

Every failure is an Error with a stable code, a category (ARGUMENT, STRUCTURE,
AUTHORITY, PERSISTENCE, LIFECYCLE, LIMIT, CANCELLED, INTERNAL), a bounded subject
and optional secondary detail. Codes are appended to, never renumbered, because
callers and operators match on them.

Where several failures coexist, the first one in this order is reported:

1. document shape, encoding, bounds and identifiers;
2. policy structure and the contradiction checks;
3. the generation floor (stale topology or failure-domain evidence);
4. grant shape and digest;
5. the envelope exists;
6. the envelope digest still matches the grant;
7. the grant names the active policy revision and digest;
8. the grant names the active authority epoch;
9. the grant's tenant, service class and facility scope;
10. the authorised principal and the envelope window;
11. the constraint evaluation itself, in canonical rule and constraint order.

A refusal is never a decision: evaluate returns either a verdict set or an error,
and an ineligible verdict is a successful evaluation of a negative answer.

## Command line

```text
fppctl selftest
fppctl version | format | help
fppctl policy validate <file> [--json]
fppctl policy canonicalize <file>
fppctl policy digest <file>
fppctl policy activate <dir> <file> --at <instant>
fppctl store init <dir> --store-id <id> --at <instant>
fppctl store status <dir> [--json]
fppctl store verify <dir> [--json]
fppctl store compact <dir> --at <instant>
fppctl store policy <dir> [--revision <n>]
fppctl override status <dir> [--envelope <id>] [--json]
fppctl override authorize <dir> --envelope <id> --principal <id> --usage <id>
       --tenant <id> --service-class <id> --facility <id> --at <instant> [--out <file>]
fppctl evaluate <request> [<grant>...] --store <dir> [--record --at <instant>] [--json]
fppctl record <dir> --request <id> [--json]
fppctl verify <verdict> --candidate <id> --store <dir>
       --generations topology=<n>,failure-domain=<n>,tenant=<n>,service-class=<n>
       [--occupancy-generation <n>] [--maintenance-generation <n>]
```

Exit codes are part of the contract: **0** the command succeeded and every
candidate is eligible, **1** the command line is wrong, **2** the runtime refused,
**3** the command succeeded and at least one candidate is ineligible. So
`fppctl evaluate ... ; echo $?` answers "is this placement allowed?" in one step.

`fppctl verify` requires the current state of all four global generations and
refuses to guess them, because a verify that assumed them would report a stale
verdict as valid.

### A worked example

```text
$ cat policy.txt
fpp-document policy
format 1
policy-id grid-a
revision 1
rule spread {
  description "no two placements of one tenant share a rack"
  require anti-affinity scope=tenant dimension=rack max-shared=0
}
rule legal {
  require jurisdiction allow=jurisdiction:eu-de,jurisdiction:eu-fr deny=
}
envelope emergency {
  scope facilities=facility:dc1
  allow-kinds anti-affinity
  principals principal:sre-lead
  max-uses 2
  grant-validity 15m
}

$ fppctl policy validate policy.txt
valid policy grid-a revision 1 digest sha256:704d9b67... rules 2 envelopes 1

$ fppctl store init store --store-id store:main --at 2026-02-14T09:00:00Z
$ fppctl policy activate store policy.txt --at 2026-02-14T09:05:00Z
active policy grid-a revision 1 digest sha256:704d9b67... epoch 2

$ fppctl evaluate request.txt --store store ; echo $?
candidate cand-free   { decision eligible ... }
candidate cand-shared { decision ineligible
  violation rule=spread kind=anti-affinity index=0 code=anti-affinity-exceeded
  detail="1 in-scope placement(s) already share rack:rack:07 (limit 0)" }
3
```

The same decision, with the documented exception exercised and still visible in
the explanation:

```text
$ fppctl override authorize store --envelope emergency --principal principal:sre-lead --usage change-4711 \
    --tenant tenant:acme --service-class service-class:gold --facility facility:dc1 \
    --at 2026-02-14T09:30:00Z --out grant.txt
$ fppctl evaluate request.txt grant.txt --store store ; echo $?
candidate cand-shared { decision eligible
  violation ... code=anti-affinity-exceeded waived-by=emergency }
0
```

### Text document format

A document starts with `fpp-document <kind>` and `format 1`. Every line is blank,
a `#` comment, a `keyword key=value ...` statement, a `keyword value ... {`
section opening or a `}` close. Sections nest one level. Values are bare tokens or
double-quoted strings, and a named field may carry a quoted value
(`detail="a value with spaces"`). Parsing is strict: unknown keywords, unknown
fields, a repeated field, a missing required field, a wrongly typed value, an
unexpected section and a stray brace are all errors. The emitters produce
canonical text - statements in a fixed order, sets sorted, one entry per line -
and parsing canonical text and re-emitting it is idempotent.

## Library integration

```cpp
#include <dccp/facility_placement_policy/facility_placement_policy.hpp>

using namespace dccp::facility_placement_policy;

auto policy = parse_policy_document(text);            // Result<PolicyDocument>
auto snapshot = make_policy_snapshot(std::move(policy.value()),
                                     AuthorityEpoch::from_value(2).value(),
                                     StoreSequence::from_value(2).value(),
                                     TopologyGeneration{}, FailureDomainGeneration{});

auto request = parse_request_document(request_text);  // Result<PlacementRequest>
EvaluationInput input;
input.request = std::move(request.value());

auto verdicts = evaluate(snapshot.value(), input);    // Result<PlacementVerdictSet>
if (!verdicts.has_value()) {
  // A refusal: stale evidence, an unbound generation, a bad grant.
  return verdicts.error().to_string();
}
for (const CandidateVerdict& candidate : verdicts.value().candidates) {
  // candidate.decision, candidate.violations, candidate.verdict_digest
}
```

The durable side is one small class:

```cpp
auto store = Store::open("path/to/store", StoreOpenMode::ReadWrite);  // Result<Store>
store.value().activate_policy(document, instant);
auto snapshot = store.value().snapshot();                             // Result<PolicySnapshot>
auto grant = store.value().authorize_override(envelope, principal, usage, tenant,
                                              service_class, facility, instant);
auto verdicts = store.value().evaluate_recorded(input, instant);      // records, replays
```

Errors are values, not exceptions; the only exception the library can throw is
std::bad_alloc, and calling value() on a failed result is a programming error.

## Build, install and find_package

```text
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix <prefix>
```

Options: `FACILITY_PLACEMENT_POLICY_BUILD_SHARED` (default OFF),
`FACILITY_PLACEMENT_POLICY_BUILD_TESTS`, `FACILITY_PLACEMENT_POLICY_BUILD_CLI`,
`FACILITY_PLACEMENT_POLICY_BUILD_EXAMPLES`,
`FACILITY_PLACEMENT_POLICY_BUILD_BENCHMARKS`,
`FACILITY_PLACEMENT_POLICY_WARNINGS_AS_ERRORS` (default ON),
`FACILITY_PLACEMENT_POLICY_ENABLE_ASAN`.

A downstream project uses the namespaced imported target:

```cmake
find_package(facility_placement_policy CONFIG REQUIRED)
target_link_libraries(app PRIVATE dccp::facility_placement_policy)
```

The installed package is `lib/cmake/facility_placement_policy` and exports
exactly one target. The warning policy, the sanitizer instrumentation and the
test support are build-tree only and are never exported.

## Validation performed

Everything below was run on the machine described in the platform section,
against this commit, with the exact commands shown.

**Builds.** Release and Debug, Ninja, x64, with `/W4 /WX /permissive- /utf-8
/Zc:__cplusplus`. Zero warnings in both.

**Tests.** 129 tests in 17 suites, run both as one process and as one ctest entry
per suite:

```text
Release, one process:      129 test(s) ran, 0 failure(s)
Release, ctest:            18/18 passed
Debug, ctest:              18/18 passed (26.5 s wall, including the process suites)
```

The suites are: result, digest, time, text_util, policy, canonical, evaluate,
override, verdict, store, recovery, property, adversarial, concurrency,
multiprocess, crash, cli.

**Property and adversarial testing.** Canonical identity is checked to be
independent of authoring order over 40 seeded reorderings; batch permutation
invariance is checked over 25 seeds and 4 permutations each; a seeded state
machine drives 60 store operations and re-checks its invariants after every
action; every strict prefix of an encoded request is checked to fail to decode;
and every single-byte mutation of an encoded request is checked either to fail
cleanly or to decode to something that re-encodes to exactly those bytes.

**Corruption and truncation sweeps.** A corrupt head, a truncated head, a head
with an appended byte, a corrupt predecessor, both corrupt, a missing referenced
policy record, a missing ledger, a corrupt retained revision, a corrupt ledger,
orphan records with no head, and a stale head. Each either recovers to exactly one
verified generation or fails closed with a named code.

**Real processes.** Writer-lock exclusion between independent processes, reader
coexistence, only one of two competing writers succeeding, a store written by one
process being read by another, and 12 abrupt terminations of a real writer
(6 delays x 2 workloads) with the store opened and verified afterwards each time.

**Sanitizers.** AddressSanitizer is **not available** in this environment and was
not used. The probe is exact: the toolchain accepts `/fsanitize=address` and
compiles with it, but the x64 runtime is not installed, and linking fails with
`LINK : fatal error LNK1104: cannot open file
'clang_rt.asan_dynamic_runtime_thunk-x86_64.lib'`. The x86 runtime files exist;
the x64 ones do not (0 files matching `clang_rt.asan*` in
`VC/Tools/MSVC/14.44.35207/lib/x64` and 0 matching `*asan*` in
`bin/Hostx64/x64`). No sanitizer claim is made anywhere in this document. The
strongest real alternative available was used instead: the Debug configuration
with the checked iterators and runtime checks a Debug MSVC build enables, plus the
corruption, truncation and byte-mutation sweeps above. Its limits are real - it
cannot see across a free, and it does not instrument the standard library's
allocator - so an environment that does have the x64 runtime should run
`-DFACILITY_PLACEMENT_POLICY_ENABLE_ASAN=ON` before trusting this code with
hostile input.

**Static analysis.** `clang-tidy` (the version bundled with Visual Studio 2022)
over every translation unit with `bugprone-*`, `performance-*` and `portability-*`.
Its findings were triaged and the real ones fixed: constant expressions that
widened after multiplying, identities passed by value where a reference costs
nothing, `std::move` applied to trivially copyable values, and functions marked
`noexcept` that allocate. The findings deliberately not changed are recorded here
rather than hidden: `performance-enum-size` on `ErrorCode` (it is `uint16_t` on
purpose, to leave room for a vocabulary that only grows), and
`bugprone-branch-clone` on switches whose distinct enumerators map to the same
answer.

**Concurrency audit.** Performed by inspection, not only by test: no lock
upgrade, no callback under a lock, no nested acquisition, no join while holding
state, no blocking I/O under the in-process lock where it could be avoided, and no
asynchronous completion that could outlive an authority change. The library
creates no threads.

**Packaging and downstream.** A staged install, an independent out-of-tree
consumer that uses `find_package(facility_placement_policy CONFIG REQUIRED)`
against the installed prefix only and exercises the public API, the installed
`fppctl`, and a fresh clone of the release commit configured, built, tested and
consumed from scratch.

### Hardening defects found and fixed

These were found by the validation above rather than by reading the code, and each
has a regression test that fails without the fix:

1. **Record identity covered its own trailer**, so every commit failed its
   read-back check. Found by the first end-to-end run.
2. **A decoded policy carried an uninitialised digest** instead of deriving it,
   so a policy read back from disk could not validate. Found by the store
   activation path.
3. **Instants before 1970 rendered one day late**, because the day was derived
   with truncating division instead of floor division. Found by the time suite;
   the calendar self-check now walks the pre-epoch range and back across the
   epoch.
4. **The smallest representable duration could not round trip**, because the
   component magnitude of `INT64_MIN` is one greater than `INT64_MAX`. Found by
   the time suite.
5. **Canonicalisation folded duplicate rule identities**, silently merging two
   rules with the same identity instead of rejecting them, and bounds were
   enforced after that folding. Found by the policy suite and the adversarial
   suite.
6. **An unset instant accepted a non-zero payload and discarded it**, so a decode
   was not always the inverse of an encode. Found by the byte-mutation property.
7. **A quoted value after `key=` was not attached to its key**, so a violation
   detail parsed as empty and a verdict read back from text no longer verified.
   Found by the verdict text round trip.
8. **Prepared grants held pointers into a destroyed local**, so an override waiver
   could never be applied: every grant lookup compared an empty identity. Found
   by the override suite and independently by a downstream consumer of the
   library.
9. **A reader opened files with `FILE_SHARE_READ` only**, so a concurrent commit's
   atomic replace failed with access denied. Found by the concurrency suite.
10. **Recursive removal did not recurse**, so anything holding a subdirectory
    could not be cleaned up. Found by test scratch-directory teardown.
11. **The test child process dropped its capture pipe when moved**, so captured
    output was unreachable. Found by the CLI suites.
12. **A store could be initialised at a `.` or `..` path**, which would have put
    durable state somewhere other than where the operator pointed. Found by the
    adversarial suite.

## Benchmarks

Measured with the command shown, on the development host, by
`facility_placement_policy_benchmarks`. Every row times a **completed** operation:
the timer starts after the input is built and stops when the operation has
returned. Nothing here is enqueue, submission or scheduling latency, because this
library has no queue.

* Host: AMD Ryzen 7 9800X3D, 16 logical processors, Windows 11 Pro, x64.
* Build: Release, MSVC 19.44 (Visual Studio 2022 17.14), Ninja.
* Method: `std::chrono::steady_clock`, the iteration counts in the table, the
  mean over all iterations of one run. Single host, single run, with the
  workloads generated in-process by the benchmark itself. These are not a claim
  about any other machine.

| Operation | Iterations | Total ns | Mean ns | Provenance |
| --- | ---: | ---: | ---: | --- |
| SHA-256 canonical policy digest, 256 rules (canonicalize_policy) | 200 | 115028500 | 575142.5 | SYNTHETIC |
| evaluate: 512 candidates against one PolicySnapshot | 50 | 264264600 | 5285292.0 | SYNTHETIC |
| Store::activate_policy: publish a 32-rule revision | 64 | 1129348000 | 17646062.5 | REAL |
| Store::evaluate_recorded: record 32 candidates | 64 | 1120172000 | 17502687.5 | REAL |

The two REAL rows run against a real store directory and include the whole
durable path - staging, flushing, reading back, verifying and publishing the
manifest - because that path is what the durability guarantee is about. The two
SYNTHETIC rows are pure computation over in-memory documents. No physical hardware
behaviour is claimed anywhere: this runtime issues no device calls, and these
numbers say nothing about disks or networks beyond the filesystem calls they
make.

## Platform support

Validated: Windows 11 x64 with MSVC 19.44 (Visual Studio 2022 17.14) and Ninja,
Release and Debug. That is the only configuration that has been built, tested and
measured here.

Written but **not compiled or executed** in this environment: the POSIX branch of
the operating-system layer in `src/file_ops.cpp` and `tests/child_process.cpp`
(`open`/`read`/`write`/`fsync`/`rename`/`flock`/`fork`/`execvp`/`waitpid`). It is
present so the runtime is not Windows-only by construction, but no claim is made
that it builds or works, because it has not been built or run. Treat it as
unvalidated until a POSIX toolchain has run the suite.

Not claimed: any behaviour on 32-bit targets, any sanitizer instrumentation, and
any hardware-level property - this runtime touches no hardware.

## Version and compatibility

`facility_placement_policy` 1.0.0. The CMake project version, the compiled-in
`kVersionString` and the test suite are checked against each other on every run,
so they cannot drift apart silently. The durable format is version 1 and a reader
refuses any other version rather than guessing; the text format is version 1 and
behaves the same way.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
