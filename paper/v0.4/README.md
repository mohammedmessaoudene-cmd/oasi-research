# OASI Scientific Article Preprint v0.4

## Main deliverable

- `OASI_SCIENTIFIC_ARTICLE_PREPRINT_V0_4.pdf`
- Current preprint DOI: [10.5281/zenodo.22262138](https://doi.org/10.5281/zenodo.22262138)
- Current companion software DOI: [10.5281/zenodo.22262143](https://doi.org/10.5281/zenodo.22262143)
- Prior preprint version: [10.5281/zenodo.22151556](https://doi.org/10.5281/zenodo.22151556)
- Prior software version: [10.5281/zenodo.22151560](https://doi.org/10.5281/zenodo.22151560)

The current version-specific DOI values were reserved before this final build.
They resolve through Zenodo when the corresponding records are public.

## Source

- `source/main.tex`
- `source/references.bib`
- `source/figures/*.tex`
- `source/figures/*.pdf`
- `source/figures/*.svg`

## Audit material

- `CLAIMS_AND_EVIDENCE_V0_4.md`
- `INTERNAL_ADVERSARIAL_REVIEW_V0_4.md`
- `RESPONSE_TO_INTERNAL_ADVERSARIAL_REVIEW_V0_4.md`
- `ABSTRACT_FR.md`

## Manuscript status

v0.4 adds the S5 and S6 local deterministic trace simulations and their
adversarial reanalysis. S5 is a negative result against a cooperative
idempotent receiver. S6 diagnoses a safety--availability tradeoff but does not
establish an OASI-specific advantage.

It does **not** claim a completed operating system, consciousness, production
readiness, general superiority, or endorsement by IEEE, DARPA, OpenAI, or the
author's university.

## Build

Use `tools/build_article.ps1` or `tools/build_article.sh` from the repository
root. The build uses a fixed source epoch and is accepted only when two clean
builds produce the same PDF hash.

The v0.3 README listed audit documents absent from its published archive. v0.4
corrects that list without altering the v0.3 record.
