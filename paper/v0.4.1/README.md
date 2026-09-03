# OASI: Operational Artificial System Intelligence — Corrective Preprint v0.4.1

## Status

This directory contains the locally built pre-DOI candidate for a
terminology-only correction of the published v0.4 preprint. Its v0.4.1 PDF,
source manifest, receipt, and deterministic twin-build evidence are complete
locally. No v0.4.1 DOI or external release is claimed here.

- Published v0.4 preprint: [10.5281/zenodo.22262138](https://doi.org/10.5281/zenodo.22262138)
- Companion v0.2.1 software/data preview: [10.5281/zenodo.22262143](https://doi.org/10.5281/zenodo.22262143)
- Earlier v0.3 preprint: [10.5281/zenodo.22151556](https://doi.org/10.5281/zenodo.22151556)

The v0.3 and v0.4 directories are historical records and remain unchanged.

## Corrected terminology

**AERA** is a stable project identifier, not an acronym with a normative long
form. In the manuscript it denotes a bounded commit-time
authority-revalidation predicate. The **AERA reference runtime** is the larger
implementation profile that combines this predicate with prepare/commit,
protocol, child-lifecycle, ledger, and rollback/quarantine support.

The manuscript's architectural predicate includes more bindings than the
finite public Rust predicate. The additional policy, body-state, evidence,
revocation, quarantine, and effect-digest terms remain architectural
requirements unless separately identified as implemented and tested.

See:

- `CORRIGENDUM_V0_4_1.md` for the exact correction and impact assessment;
- `../../AERA_TERMINOLOGY_ERRATUM.md` for the repository-level terminology
  rule;
- `CLAIMS_AND_EVIDENCE_V0_4_1.md` for the unchanged claim boundaries.

## Content

- `source/main.tex`
- `source/references.bib`
- `source/figures/*.tex`
- freshly rebuilt PDF/SVG figure renderings under `source/figures/`
- `OASI_SCIENTIFIC_ARTICLE_PREPRINT_V0_4_1.pdf`
- `ARTICLE_SOURCE_MANIFEST.sha256`
- `BUILD_RECEIPT.json`
- `ABSTRACT_FR.md`
- `CORRIGENDUM_V0_4_1.md`
- `CLAIMS_AND_EVIDENCE_V0_4_1.md`
- `LICENSE.md`

## Scientific status

The correction does not change the experiments or their interpretation. S5
remains a negative result against a cooperative idempotent receiver. S6
remains a diagnostic safety--availability tradeoff without an isolated
OASI-specific advantage. The evidence remains internal, deterministic,
fixture-only, and outside production claims.

## Build and publication boundary

The existing v0.4 PDF and build receipts were not reused as evidence for the
v0.4.1 PDF. Separately versioned tooling produced fresh manifests and receipts
and demonstrated deterministic twin output. DOI reservation, final DOI-bound
rebuild, external release, and publication remain incomplete.
