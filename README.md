# OASI / AERA research preview

> RESEARCH PROTOTYPE  
> OASI COMPLETE SYSTEM: NOT DEMONSTRATED  
> T4 SCIENTIFIC RESULT: NEGATIVE / CONSTRUCT-VALIDITY LIMITED  
> AERA: BOUNDED USER-SPACE REFERENCE CONTRIBUTION  
> NOT PRODUCTION READY  
> NO GENERAL SUPERIORITY CLAIM  
> NO DARPA, IEEE, UNIVERSITY, OR OTHER INSTITUTIONAL ENDORSEMENT

OASI is a research program exploring the thesis that operating-system activity, embodiment, system organization, and intelligence may form one developmental causal history: `OS = AI = continuous activity of one artificial organism`.

This `v0.1.0-research-preview` does **not** demonstrate that complete vision. It publishes the narrower and more mature AERA contribution: a user-space reference design in which authority is bound to a body identity, epoch, generation, certificate, principal, resource, action, and expiration, then revalidated when an effect commits.

## What is included

- a bounded Rust reference runtime and its public tests;
- the AERA specification and threat model;
- the v0.3 preprint, source, bibliography, and vector figures;
- an exact claims-to-evidence ledger;
- the negative T4 result and construct-validity diagnosis;
- reproducibility, licensing, security, and supply-chain documentation;
- public evidence summaries and hashes for larger private evidence.

The Rust crate retains the historical package name `osia-core-r1`; the public research program and architecture are named OASI/AERA.

## Persistent identifiers

- Scientific preprint: [doi:10.5281/zenodo.22151556](https://doi.org/10.5281/zenodo.22151556)
- Software research preview: [doi:10.5281/zenodo.22151560](https://doi.org/10.5281/zenodo.22151560)
- Source repository: <https://github.com/mohammedmessaoudene-cmd/oasi-research>

The two Zenodo records are separate because the preprint is licensed CC BY 4.0
while the software archive uses the path-specific license map described below.

## Quick verification

Full-suite requirements: Linux, Rust/Cargo 1.97.1, and Python 3.11 or later. A bounded Windows/GNU subset is provided separately because several assurance tests intentionally inspect Linux `/proc` and `/bin` behavior.

```text
cargo test --locked --all-targets
python -I -B tools/verify_release.py .
```

On Windows, run `powershell -File tools/run_tests.ps1` for the portable subset and public verifier; that result must not be reported as the full Linux suite. The verifier checks the manifest, claim schema, allowlist, license inventory, SBOM coverage, article files, and forbidden public-data patterns. It distinguishes symbolic protocol fields such as `nonce` from leaked operational authorization values.

## Scope

The implementation exercises a finite user-space model and tests fail-closed behavior, bound authority, ledgers, protocol parsing, rollback, child isolation, and wake-safety equivalence. It is not a kernel, hypervisor, complete operating system, production safety case, formal proof of universal security, or evidence of consciousness.

See [Claims and evidence](CLAIMS_AND_EVIDENCE.md), [limitations](KNOWN_LIMITATIONS.md), [negative results](NEGATIVE_RESULTS.md), and the [French overview](README_FR.md).

## Publication and provenance status

The owner supplied an explicit rights and provenance representation for this sanitized release. A contradiction search over the allowlisted tree found no other named human contributor, grant or contract identifier, vendored third-party source, incompatible notice, or private laboratory material. The acceptance is bounded to this release and is not a judicial or institutional determination. See [publication status](PUBLICATION_STATUS.md) and the [owner declaration](OWNER_RIGHTS_AND_PROVENANCE_DECLARATION.md).

## Licensing

The release preserves the historical source declaration:

- standalone Rust code: `Apache-2.0 OR MIT`;
- original documentation, specifications, paper, and public evidence: `CC-BY-4.0`;
- OASI name and any future logo: trademark rights reserved; no registration is claimed.

AGPL is not applied retroactively to v0.1. A future clean-slate runtime may consider it only after a new chain-of-title and compatibility audit. No third-party source tree is vendored. See [LICENSING.md](LICENSING.md).
