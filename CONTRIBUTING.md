# Contributing to Facility Placement Policy

Facility Placement Policy is part of Data Center Control Plane (DCCP), Tranche 6
(Facility Policy, Tenancy, and Entitlement), and is maintained by Summon Software
Labs.

## Licensing of contributions

This project is licensed under the Apache License, Version 2.0 (see `LICENSE`).

By submitting a contribution you agree that it is licensed under the terms of
that license, as described in section 5 of the license text. There is **no
Contributor License Agreement** to sign, and no copyright assignment is
required: you keep the copyright in your contribution and grant the project the
license described in `LICENSE`.

Please do not add co-author trailers or attribution lines that name tools,
assistants or intermediate processes; commit authorship is the responsibility of
the human contributor.

## What belongs in this repository

Facility Placement Policy owns the deterministic decision of whether a proposed
physical placement is *allowed*:

* the typed policy model and its canonical revision and digest;
* typed constraints and predicates over candidate sites, rooms, rows, racks,
  failure domains and typed facility metadata;
* generation-bound placement verdicts with explanations, and the fencing rules
  that retire prior placement authority;
* an explicit, attributable, scoped and expiring override model that can never
  bypass a hard interlock;
* the durable policy lifecycle, authority epoch and override ledger.

It deliberately does **not** own:

* rank ordering of allowed candidates (Facility Placement Planner);
* capacity reservation (Facility Capacity Reservation);
* execution of a placement (Facility Change Orchestrator, Commissioning Fabric);
* workload scheduling (Agent Scheduler, Collective Scheduler);
* traffic routing or path selection (Path Planner, Route Fabric);
* facility topology and failure-domain membership (Facility Topology, Failure
  Domain Registry);
* tenant, service-class, incident and maintenance records (Tenant Registry,
  Service Class Registry, Maintenance Coordinator, Facility State Ledger).

If a change makes this repository simulate one of those authorities instead of
consuming its published, generation-bound evidence, the change is out of scope.

## Building and testing

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

The build enables a strict first-party warning policy by default
(`/W4 /WX /permissive-` on MSVC, `-Wall -Wextra -Wpedantic -Werror`
elsewhere). Warnings are never silenced to make a build pass; fix the cause.

Tests run to completion and are never wrapped in a timeout. A hanging test is a
defect to diagnose.

## Code quality expectations

* C++20, no third-party runtime dependencies.
* Deterministic behaviour for equivalent authoritative inputs. Anything that
  affects a decision must be bound, digested and explainable.
* Missing, unknown, stale or unmeasured data must never silently become
  eligible, healthy or safe.
* No placeholder handlers, dead code, debug output, secrets or absolute paths.
* Public behaviour changes need a test that fails before the change and passes
  after it. Prefer a test that would have caught the defect over a test that
  merely restates the implementation.
* New public API needs documentation in `README.md` or `docs/`.

## Reporting a defect

Open an issue with the smallest reproduction you can manage: the policy
document, the request document, the exact command, the observed output and the
expected output. Deterministic reproductions matter more here than in most
projects, because this runtime refuses to guess.
