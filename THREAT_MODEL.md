# Current v0.3.0 scope

This source/data candidate adds the bounded host service and passive oracle documented in [RELEASE_NOTES_V0_3.md](RELEASE_NOTES_V0_3.md). No new scientific advantage, production readiness or external peer review is asserted. The inherited text below applies to the v0.2.2 base, not an unqualified extension to every new module. For the new module use [its scoped documentation](experimental/bounded_service/README.md).

---

# Threat model

## Protected properties

- a prepared effect cannot commit under stale or mismatched authority;
- malformed or replayed protocol frames fail closed;
- ledger mutation, truncation, or reordering is detectable in exercised cases;
- child-process failure does not silently authorize an effect.

## Considered adversaries

- malformed, duplicated, reordered, truncated, or checksum-invalid frames;
- stale epoch/generation/certificate snapshots;
- mismatched principal, resource, or action;
- child exit, timeout, broken pipe, unexpected output, and replayed acknowledgement;
- local artifact mutation detected by manifests.

## Outside the boundary

- a malicious host kernel, hypervisor, compiler, firmware, or physical attacker;
- side channels, denial of service, real-time scheduling, and distributed Byzantine faults;
- arbitrary irreversible external effects;
- supply-chain compromise outside the pinned toolchain and shipped source;
- proof of complete memory safety or absence of all logic errors.

The runtime provides evidence for bounded fail-closed mechanisms, not a production threat-model closure.
