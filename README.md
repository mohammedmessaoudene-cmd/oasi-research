# OASI — Operational Artificial System Intelligence / AERA research preview

> RESEARCH PROTOTYPE  
> OASI COMPLETE SYSTEM: NOT DEMONSTRATED  
> T4 SCIENTIFIC RESULT: NEGATIVE / CONSTRUCT-VALIDITY LIMITED  
> AERA: BOUNDED USER-SPACE REFERENCE CONTRIBUTION  
> NOT PRODUCTION READY  
> NO GENERAL SUPERIORITY CLAIM  
> NO DARPA, IEEE, UNIVERSITY, OR OTHER INSTITUTIONAL ENDORSEMENT

**Operational Artificial System Intelligence (OASI)** is the canonical name of
the research paradigm documented by this project. It investigates a system-level
architecture in which operation, artificial embodiment, memory, cognition,
authority, and development are coordinated through one versioned causal history
and constitutionally mediated effects. Its technical thesis remains:
`OS = AI = continuous activity of one artificial organism`.

In this name, **operational** refers to system operation, not production
readiness. **System intelligence** names a research target; it does not claim
achieved general or superintelligence, consciousness, organismic unity,
deployment, external validation, or superiority.

This `v0.2.1-research-preview` does **not** demonstrate that complete vision. It publishes the bounded AERA reference contribution and adds two local deterministic effect-boundary simulations. Their combined conclusion is negative or diagnostic: S5 does not establish an advantage over a cooperative idempotent receiver, and S6 exposes a retry-versus-omission tradeoff without isolating an OASI-specific advantage.

## What is included

- a bounded Rust reference runtime and its public tests;
- the AERA specification and threat model;
- the v0.4 preprint, source, bibliography, and vector figures;
- the sealed S5/S6 raw records, runners relocatable on Linux/WSL and qualified
  on WSL1 x86_64, detached aggregate checkers,
  tests, protocols, environment record, and data dictionary;
- an exact claims-to-evidence ledger;
- the negative T4 result and construct-validity diagnosis;
- reproducibility, licensing, security, and supply-chain documentation;
- public evidence summaries and hashes for larger private evidence.

The Rust crate retains the historical package name `osia-core-r1` and crate
version `0.1.0-research-preview` because its code is unchanged. Version `v0.2`
identifies the aggregate research release that adds the S5/S6 evidence and
article v0.4. OASI names the Operational Artificial System Intelligence research
paradigm; organismic computing describes its architectural hypothesis; AERA is
the bounded assurance mechanism implemented by this preview.

## Current persistent identifiers (v0.2/v0.4)

- Scientific preprint v0.4: [doi:10.5281/zenodo.22262138](https://doi.org/10.5281/zenodo.22262138)
- Aggregate software/data preview v0.2: [doi:10.5281/zenodo.22262143](https://doi.org/10.5281/zenodo.22262143)

These distinct version-specific DOI values were reserved before the final
artifact build. Each resolves through Zenodo once its corresponding record is
public; the software and article records remain separate because their
licensing scopes differ.

## Historical persistent identifiers (v0.1)

- Prior scientific preprint v0.3: [doi:10.5281/zenodo.22151556](https://doi.org/10.5281/zenodo.22151556)
- Prior software research preview v0.1: [doi:10.5281/zenodo.22151560](https://doi.org/10.5281/zenodo.22151560)
- Source repository: <https://github.com/mohammedmessaoudene-cmd/oasi-research>

These two historical Zenodo records remain identifiers for v0.1 materials and
do not identify this v0.2/v0.4 release.

## Quick verification

The qualified full-suite wrapper requires Linux x86_64, the exact Rust/Cargo
1.97.1 builds recorded in `TOOLCHAIN_PROVENANCE.json`, and exactly CPython
3.12.3, PyYAML 6.0.1, cryptography 41.0.7, and SQLite 3.45.1. A bounded
Windows/GNU subset uses the separately pinned publication environment because
several assurance tests intentionally inspect Linux `/proc` and `/bin`
behavior. Other Python 3.11+ environments may be useful for exploratory manual
reproduction, but they are outside the qualified wrapper surface.

```text
sh tools/run_tests.sh post-doi
```

The `post-doi` phase requires the final, distinct software and article DOI
records above. On Windows, run
`powershell -File tools/run_tests.ps1 post-doi` for the bounded Rust subset and
read-only S5/S6 data checks; that result must not be reported as the full Linux
suite or as S5/S6 execution qualification. The verifier checks the manifest,
claim schema, allowlist, license inventory, SBOM coverage, article files, and
forbidden public-data patterns. It distinguishes symbolic protocol fields such
as `nonce` from leaked operational authorization values.

## Scope

The implementation exercises a finite user-space model and tests fail-closed behavior, bound authority, ledgers, protocol parsing, rollback, child isolation, and wake-safety equivalence. It is not a kernel, hypervisor, complete operating system, production safety case, formal proof of universal security, or evidence of consciousness.

See [Claims and evidence](CLAIMS_AND_EVIDENCE.md), [limitations](KNOWN_LIMITATIONS.md), [negative results](NEGATIVE_RESULTS.md), and the [French overview](README_FR.md).

## S5/S6 scientific update

The release contains 2,700 retained deterministic records across 90 cells.
The 30 repetitions per cell are implementation-stability traces, not
independent population samples. The fault labels are simulated control-flow
traces, not physical power loss, killed processes, severed sockets, or storage
tears. No inferential probability, exactly-once, production, performance,
external-replication, or general-superiority claim is made. See
[S5/S6 results and boundary](SCIENTIFIC_RESULTS_S5_S6.md).

## Publication and provenance status

The owner supplied an explicit rights and provenance representation for this sanitized release. A contradiction search over the allowlisted tree found no other named human contributor, grant or contract identifier, vendored third-party source, incompatible notice, or private laboratory material. The acceptance is bounded to this release and is not a judicial or institutional determination. See [publication status](PUBLICATION_STATUS.md) and the [owner declaration](OWNER_RIGHTS_AND_PROVENANCE_DECLARATION.md).

## Licensing

The release preserves the historical source declaration:

- standalone Rust code: `Apache-2.0 OR MIT`;
- original documentation, specifications, paper, and public evidence: `CC-BY-4.0`;
- OASI name and any future logo: trademark rights reserved; no registration is claimed.

AGPL is not applied retroactively. A future clean-slate runtime may consider it only after a new chain-of-title and compatibility audit. No third-party source tree is vendored. See [LICENSING.md](LICENSING.md).
