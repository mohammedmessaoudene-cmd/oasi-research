# Reproducibility

## Toolchain

- Linux for the full assurance suite;
- Rust/Cargo `1.97.1`;
- Python `3.11` or later;
- Git for fresh-clone checks.

The Rust crate has no external Cargo dependencies. `Cargo.lock` is shipped and `--locked` is required.

The article source is under `paper/v0.3/source/`. Its clean build uses `pdflatex`, `biber`, and a fixed `SOURCE_DATE_EPOCH`; the release process compares two independent PDF builds before accepting the PDF.

## Test

```text
cargo test --locked --all-targets
python -I -B tools/verify_release.py .
```

PowerShell and POSIX helper scripts are provided in `tools/`. Tests create only temporary user-space files and child processes.

The PowerShell helper runs only the portable Rust subset using the Windows GNU toolchain and labels that result `PARTIAL`. The full verdict requires the POSIX helper on Linux because some tests intentionally invoke `/usr/bin/python3`, `/proc`, `/bin/true`, and `/bin/kill`.

## Deterministic source archive

```text
python -I -B tools/build_deterministic_zip.py . ../oasi-aera-v0.1.0-research-preview.zip
```

The builder requires output outside the source tree, sorts POSIX relative path strings, excludes `.git`, `target`, and caches, fixes timestamps, and normalizes archive mode metadata. Build twice to distinct external output paths and compare SHA-256. This prevents an earlier archive from contaminating a later build.

The legacy ReportLab paper builder is not used for the v0.3 preprint. Build the v0.3 source with the documented LaTeX toolchain and verify its fonts, metadata, references, and rendered pages before replacing the packaged PDF.

## Evidence boundary

The public package can reproduce the shipped Rust test suite and public verifier. It cannot independently reconstruct the full historical 1 GB campaign or the omitted T4 traces. Those omissions are explicit and linked by content hashes in `public_evidence/`.
