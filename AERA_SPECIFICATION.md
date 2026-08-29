# AERA specification

AERA means **Attested Epoch-bound Runtime Authority** in this research preview.

## Safety relation

`perception != attestation != authorization`

Observing an event does not attest its integrity. Attesting data does not authorize an effect. Authorization is valid only for a bounded tuple and must be revalidated at commit.

## Required properties

### AERA-01 — Canonical authority

An authority snapshot binds body identity, epoch, generation, certificate, principal, resource, action, and validity conditions. Missing or non-canonical fields fail closed.

### AERA-02 — Prepare/commit separation

Preparation may compute a candidate effect but cannot make it durable. Commit repeats authority validation against the current state.

### AERA-03 — Epoch and generation invalidation

Rotation of epoch, generation, or certificate invalidates stale prepared work.

### AERA-04 — Replay resistance

Protocol frames carry a transaction sequence and checksum. Duplicate, stale, malformed, or mismatched acknowledgements are rejected. Numeric values in tests are synthetic and are not operational authorization artifacts.

### AERA-05 — Bounded effects

The requested action and resource must equal the authorized action and resource. A valid authority for one domain does not authorize another.

### AERA-06 — Fail-closed child lifecycle

Unexpected output, truncated frames, timeouts, protocol errors, or authority drift terminate or reap the child and prevent commit.

### AERA-07 — Ledger integrity

Committed or rejected transitions are represented by canonical, verifiable ledger entries. The ledger supports detection of truncation, mutation, reordering, and inconsistent authority.

### AERA-08 — Rollback and quarantine

When commit cannot be authorized, the runtime records the rejection and follows a bounded rollback or quarantine path. Rollback is not evidence that arbitrary external side effects can always be reversed.

## Conformance scope

The public tests cover the finite implementation shipped here. Passing them means conformance to these exercised cases only; it is not a universal security proof.
