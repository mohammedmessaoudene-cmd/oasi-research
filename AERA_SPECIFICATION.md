# AERA specification

**AERA** is the stable project identifier for the bounded commit-time
authority-revalidation mechanism specified here. Beginning with the v0.2.2
terminology correction, AERA has no normative long-form expansion. The two
incompatible expansions preserved in v0.2.1 are historical wording, not
alternate definitions; see `AERA_TERMINOLOGY_ERRATUM.md`.

## Normative scope

The **AERA core predicate** revalidates an authority envelope immediately
before a protected effect. The envelope binds body identity, epoch,
generation, certificate, principal, resource, action, and validity conditions.

This file specifies the finite public Rust reference profile. The
article-level architectural predicate additionally names policy, body-state,
evidence, revocation, quarantine, and effect-digest bindings. Those additional
terms remain architectural requirements unless a referenced implementation and
test explicitly exercise them; they are not silently attributed to the finite
Rust predicate shipped in this preview.

The **AERA reference runtime** combines that predicate with a prepare/commit
lifecycle, strict framed protocol handling, fail-closed child management, an
evidence ledger, and bounded rollback or quarantine behavior. Properties of
the reference runtime support the predicate but are not themselves additional
conjuncts of the core decision function.

## Safety relation

`perception != attestation != authorization`

Observing an event does not attest its integrity. Attesting data does not authorize an effect. Authorization is valid only for a bounded tuple and must be revalidated at commit.

## Required properties

### AERA-01 — Canonical authority

Scope: core predicate.

An authority snapshot binds body identity, epoch, generation, certificate, principal, resource, action, and validity conditions. Missing or non-canonical fields fail closed.

### AERA-02 — Prepare/commit separation

Scope: core predicate and transaction lifecycle.

Preparation may compute a candidate effect but cannot make it durable. Commit repeats authority validation against the current state.

### AERA-03 — Epoch and generation invalidation

Scope: core predicate.

Rotation of epoch, generation, or certificate invalidates stale prepared work.

### AERA-04 — Replay resistance

Scope: reference-runtime protocol support.

Protocol frames carry a transaction sequence and checksum. Duplicate, stale, malformed, or mismatched acknowledgements are rejected. Numeric values in tests are synthetic and are not operational authorization artifacts.

### AERA-05 — Bounded effects

Scope: core predicate.

The requested action and resource must equal the authorized action and resource. A valid authority for one domain does not authorize another.

### AERA-06 — Fail-closed child lifecycle

Scope: reference-runtime process support.

Unexpected output, truncated frames, timeouts, protocol errors, or authority drift terminate or reap the child and prevent commit.

### AERA-07 — Ledger integrity

Scope: reference-runtime evidence support.

Committed or rejected transitions are represented by canonical, verifiable ledger entries. The ledger supports detection of truncation, mutation, reordering, and inconsistent authority.

### AERA-08 — Rollback and quarantine

Scope: reference-runtime recovery support.

When commit cannot be authorized, the runtime records the rejection and follows a bounded rollback or quarantine path. Rollback is not evidence that arbitrary external side effects can always be reversed.

## Conformance scope

The public tests cover the finite implementation shipped here. Passing them means conformance to these exercised cases only; it is not a universal security proof.

AERA does not claim atomic commit between the local decision, evidence ledger,
and an arbitrary external effect. It does not claim cryptographic or
hardware-rooted attestation, exactly-once delivery, real-time guarantees,
production certification, or independently replicated assurance.
