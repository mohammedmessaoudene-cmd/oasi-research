# OASI — Operational Artificial System Intelligence

## v0.3.0-research-preview — bounded service and portable evidence

**Experimental source/data release candidate. Not production ready. Complete OASI and an OASI-specific scientific advantage remain unproven.** No institutional endorsement is claimed.

OASI investigates whether operation, artificial embodiment, memory, cognition, authority and development can form one coherent system. This philosophy remains a research objective, not a description of a completed artificial organism.

This version adds the [bounded local service](experimental/bounded_service/README.md): file analysis, explicit submit/status/resume commands and a persistent cumulative workspace budget. It also adds a passive verifier whose operation does not depend on the author's filesystem.

```sh
python -B experimental/bounded_service/verify_portable.py experimental/bounded_service/BOUNDED_SERVICE_PUBLIC_EVIDENCE.zip
```

Use an existing Python 3.11+. No dependencies, network, worker, QEMU, privileged operation or native build is needed for this command. It checks the published derivative's archived budget and results, not present-day service operation.

### What changed, and what did not
- Added: experimental CLI source, cumulative-cap correction, sanitized derived evidence and portable budget/result oracle.
- Historical local evidence: 16 reservations/start markers, 15 correct unique results, one controlled interrupted start, 168 snapshots.
- Preserved: v0.2.2 Rust core, S5/S6 code/data, article v0.4.1 and their negative/diagnostic scientific conclusions.
- Not established: scientific superiority, broad utility, power-cut durability, Linux PID1 isolation of this service, independent reproduction or a complete OASI system.

See [current findings and limitations](RELEASE_NOTES_V0_3.md), [reproduction instructions](experimental/bounded_service/README.md), [claims](CLAIMS_AND_EVIDENCE.md) and [licensing](LICENSING.md).

The native executable is intentionally not distributed. This is source plus auditable archived data, not a qualified turnkey installer. Only the passive checker is offered as an immediately runnable portable entry point.

### Version provenance
Base: Git commit `2cf5460d084cc76df1f8888a40727664c90f5b42`, tag `v0.2.2-research-preview`.
Previous software: [10.5281/zenodo.22266419](https://doi.org/10.5281/zenodo.22266419).
Unchanged article v0.4.1: [10.5281/zenodo.22266401](https://doi.org/10.5281/zenodo.22266401).
No DOI is assigned to this new candidate. See PUBLICATION_STATUS.md. The article is not being republished merely to announce engineering progress.
