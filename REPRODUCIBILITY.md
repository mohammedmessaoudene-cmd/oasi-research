# Reproducibility

## Toolchain

- Linux x86_64 for the full assurance suite;
- Rust `1.97.1 (8bab26f4f 2026-07-14)` and Cargo `1.97.1 (c980f4866 2026-06-30)`;
- CPython `3.12.3`;
- PyYAML `6.0.1`;
- cryptography `41.0.7`;
- SQLite `3.45.1`;
- Git for fresh-clone checks.

The Rust crate has no external Cargo dependencies. `Cargo.lock` is shipped and `--locked` is required.

The current article source is under `paper/v0.4.1/source/`. Its clean build uses
`pdflatex`, `biber`, and `SOURCE_DATE_EPOCH=1788393600`, corresponding to
2026-09-03T00:00:00Z. The release process compares two clean PDF builds before
accepting the PDF.

## Test

```text
sh tools/run_tests.sh post-doi 10.5281/zenodo.22266419 10.5281/zenodo.22266401
```

PowerShell and Linux-shell helper scripts are provided in `tools/`. Tests create only temporary user-space files and child processes.

The phase argument is mandatory: use `pre-doi` before DOI reservation and
`post-doi SOFTWARE_DOI ARTICLE_DOI` only after inserting the distinct final
software and article DOI records. For v0.2.2/v0.4.1, the external expected pins
are software `10.5281/zenodo.22266419` and article
`10.5281/zenodo.22266401`; they must match every active record exactly. DOI
reservation does not itself publish either Zenodo draft. The Linux-shell helper
requires Linux with Rust/Cargo 1.97.1 available. The PowerShell
helper runs only the bounded Rust subset using the Windows GNU
toolchain plus read-only validation of the sealed S5/S6 data, and labels that
result `PARTIAL`. It does not execute the S5/S6 unit or mutant tests. Those
tests require Linux directory `fsync` semantics and were qualified under the
recorded WSL/Linux environment. The full verdict requires the Linux-shell helper on
Linux because other assurance tests also intentionally invoke
`/usr/bin/python3`, `/proc`, `/bin/true`, and `/bin/kill`.

## Deterministic source archive

Never point the ZIP builder at a working Git clone: it deliberately rejects
`.git`, `target`, cache, bytecode, reparse, and every unlisted object. First
export the exact reviewed commit or tag into an empty directory outside the
clone, then build from that clean export. One POSIX procedure is:

```text
release_ref=v0.2.2-research-preview
export_root=$(mktemp -d)
mkdir "$export_root/source"
git archive --format=tar "$release_ref" | tar -xf - -C "$export_root/source"
python3 -I -B "$export_root/source/tools/build_deterministic_zip.py" \
  --allowlist /absolute/path/SOFTWARE_ARCHIVE_ALLOWLIST.txt \
  "$export_root/source" "$export_root/OASI_AERA_A.zip"
python3 -I -B "$export_root/source/tools/build_deterministic_zip.py" \
  --allowlist /absolute/path/SOFTWARE_ARCHIVE_ALLOWLIST.txt \
  "$export_root/source" "$export_root/OASI_AERA_B.zip"
python3 -I -B "$export_root/source/tools/verify_archive.py" \
  --allowlist /absolute/path/SOFTWARE_ARCHIVE_ALLOWLIST.txt \
  --source "$export_root/source" \
  "$export_root/OASI_AERA_A.zip" "$export_root/OASI_AERA_B.zip"
```

The two archives must have the same SHA-256. Extract one into another empty
directory and run `verify_experiments.py` plus `verify_release.py
--archive-mode` there with the explicit DOI phase and, after reservation, both
external expected DOI pins.

The builder requires an out-of-tree, project-reviewed allowlist containing the
lowercase SHA-256, byte size, and NFC POSIX path of every source member. It
requires output outside the source tree, rejects any missing or unlisted file,
sorts ordinal paths, rejects VCS/build/cache/reparse content, fixes timestamps,
and normalizes archive mode metadata. The release receipt records the exact
allowlist used. Build twice to distinct external output paths and compare
SHA-256. This prevents an earlier archive or a non-reviewed source file from
contaminating a later build.

The legacy ReportLab paper builder is not used for the v0.4.1 preprint. Build
the v0.4.1 source with `tools/build_article_v0_4_1.sh` (or the PowerShell
wrapper) and verify its fonts, metadata, references, and rendered pages before
accepting the packaged PDF. Historical v0.4 files remain immutable.

## S5/S6 campaigns

The `results/` directories are sealed historical outputs. Do not run each
campaign's aggregate checker directly against those directories because it
rewrites the checker-result JSON. Use the read-only global experiment verifier,
or verify a fresh extraction or temporary copy. The public
runners are relocatable within a Linux/WSL extraction and were qualified on
WSL1 x86_64. They replace one private
absolute module path with `../common`; all
experiment branches, seeds, metrics, mechanisms, and fault labels are
unchanged. `experiments/EXECUTED_SOURCE_PINS.json` records the executed hashes.
The publication-level reinterpretation of stronger wording retained in the
sealed historical reports is recorded in
`experiments/INTERPRETATION_NOTICE.md`.

To regenerate data, choose empty output and scratch directories and supply the
bundled locked protocol. Regenerated categorical outcomes should match; host
timing and memory values are not expected to be byte-identical. The campaigns
perform fixture-only NOOP writes and require no network. Running them directly
with native Windows Python is outside the qualified surface because the ledger
deliberately fsyncs directories and the unit tests exercise Linux SQLite/file
handle behavior.

Example regeneration from the repository root on Linux/WSL:

```text
work=$(mktemp -d)
python3 -I -B experiments/s5/experiment.py --output "$work/s5-out" --scratch "$work/s5-scratch" --preregistration experiments/s5/results/PREREGISTRATION_LOCKED.md
python3 -I -B experiments/s6/experiment.py --output "$work/s6-out" --scratch "$work/s6-scratch" --preregistration experiments/s6/results/PREREGISTRATION_LOCKED.md
python3 -I -B tools/compare_experiment_categories.py experiments/s5/results/RAW_RUNS.jsonl "$work/s5-out/RAW_RUNS.jsonl"
python3 -I -B tools/compare_experiment_categories.py experiments/s6/results/RAW_RUNS.jsonl "$work/s6-out/RAW_RUNS.jsonl"
```

## Evidence boundary

The public package can reproduce the shipped Rust test suite and public verifier. It cannot independently reconstruct the full historical 1 GB campaign or the omitted T4 traces. Those omissions are explicit and linked by content hashes in `public_evidence/`.

For a bounded 4–8 hour independent replication task, required report fields,
and rules for preserving failures, see `INDEPENDENT_REPRODUCTION.md`.
