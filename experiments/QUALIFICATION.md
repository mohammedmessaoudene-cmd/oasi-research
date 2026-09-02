# Public-runner qualification

Qualification date: 2026-09-02  
Qualified surface: Linux/WSL1 x86_64, fixture-only, offline

The public runners replace private absolute paths with repository-relative
paths. They were executed from the publication staging tree under WSL1 x86_64,
with bytecode disabled and fresh output/scratch directories on the Linux
filesystem.

| Check | Result |
|---|---|
| S5 unit tests | 6/6 PASS |
| S6 unit tests | 7/7 PASS |
| S5 mutant | rejected as expected |
| S6 mutant | rejected as expected |
| Rust full Linux suite | 33/33 PASS (`--offline --locked --all-targets`) |
| S5 fresh campaign | 1,200 records; detached checker PASS |
| S6 fresh campaign | 1,500 records; detached checker PASS |
| S5 categorical comparison to sealed records | 0 missing, 0 extra, 0 mismatches |
| S6 categorical comparison to sealed records | 0 missing, 0 extra, 0 mismatches |

The final fresh raw-file hashes were
`5193886c704a4e4a70638b6f38459c1d2b500a06d7b20f60c802556c532b3204`
for S5 and
`8e6f5b50cb733c8c5c3235aeb4d18359fc6294120256193c7989d5fc7c99a44b`
for S6. They are not expected to match the sealed raw files because timing,
memory, and CPU micro-measurements vary by execution. The categorical
comparison excludes those host-dependent measurements and compares every
`(mechanism, case, repetition)` tuple over the safety/disposition fields.
`QUALIFICATION_RECEIPT.json` records the environment, exact comparator field
set, toolchain checksum, exit codes, and limitations in machine-readable form.
The ephemeral rerun files are not shipped, so this is a project-controlled
qualification receipt, not an independently auditable reproduction certificate.

Native Windows Python is not part of this qualification. The broker uses
directory `fsync`, and the tests rely on Linux SQLite/file-handle behavior.
The Windows helper therefore validates the sealed data without executing these
campaign tests.
