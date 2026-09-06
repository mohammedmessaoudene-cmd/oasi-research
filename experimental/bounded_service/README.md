# Bounded local service — experimental source and passive evidence

This module adds a local CLI (init, submit, run, status, resume), a persistent workspace budget and a bounded file-analysis task. HASH_COUNT_LOCAL computes SHA-256 plus literal ERROR/WARN, NUL, newline and line counts. It does not understand logs semantically.

## One-command verification (no installation, no service execution)
From the repository root, with an existing CPython 3.11 or newer:

```sh
python -B experimental/bounded_service/verify_portable.py experimental/bounded_service/BOUNDED_SERVICE_PUBLIC_EVIDENCE.zip
```

From any directory, pass the paths to the script and ZIP. The checker uses only the standard library, reads one archive, opens no recorded paths, imports no candidate module, starts no worker and writes no files. The passive oracle was also run under the existing Ubuntu/WSL environment; see the acceptance record for exact interpreter versions. This is a second local environment, not an independent machine or a qualification of the live service on Linux.

Test the verifier itself:
```sh
python -B -m unittest discover -s experimental/bounded_service -p test_portable.py -v
```

These are passive archive checks and adversarial tests of a new tool, NOT additional executions of the historical service campaign. Rehashing the archive does not attest that the producer or machine was honest.

## Archived findings
The historical campaign recorded 168 snapshots, 16 permanent reservations, 16 launch claims, 16 work-start markers, and 15 correct unique HASH_COUNT_LOCAL results. One started interruption required another reservation to resume; its first slot was not refunded. The archive contains 70 CLI receipts, not 70 workloads. There were 28 decision/feedback events; the portable verifier counts them but does NOT validate the complete learning or AERA algorithms.

The public ZIP is a sanitized DERIVATIVE. PUBLIC_PROJECTION.json inside it states all transformations and maps original/public member hashes. Private host paths become opaque fixture identities. Reservation hashes and snapshot links are recomputed for these identities. Fixtures are byte-identical; result values and reservation ordering are preserved. AERA resource IDs and learning hashes remain historical opaque correlators, outside this oracle's semantic verification. Locally, the same oracle checked the original pinned archive and the derivative and returned the same scoped results. Without the private original, the public mapping alone is not independent proof of provenance.

## Source availability, not an installer claim
`source/service.py` and the selected runtime sources are byte-identical to the frozen candidate. No native binary is included. The original Windows-only `source/candidate/build_native.py` is included for inspection and manual rebuilding with the already installed pinned Rust toolchain; it is NOT a portable build installer. It creates a new local binary and pointer and must not be confused with historical execution or permission to replay an archived workspace. Native compilation has not been performed for this release preparation.

Before experimenting with the CLI, build the adapter in an isolated fresh copy using the documented source script and its installed toolchain requirements. Use new synthetic inputs and a new workspace. Such execution is a NEW, unqualified campaign, not continuation of the sealed one. The default command above intentionally does not build or run the service. Missing native/CURRENT.json or a missing binary fails closed; there is no Python fallback presented as Rust execution.

The selected source includes identity-referenced legacy modules so code_identity can be inspected. Diagnostic/guardian task branches are not qualified entry points: the workspace budget accepts only SHA256 and HASH_COUNT_LOCAL; only the latter was actually submitted in this campaign. This is the AERA user-space decision adapter, NOT the Linux PID1 guardian or an OS sandbox.

## Explicit limits
- Cooperative local host; cap per workspace, not across copied/reset workspaces or a hostile administrator.
- Controlled interruption only, not power loss, arbitrary kills or all thread schedules.
- Standalone SHA256 mode was not separately qualified.
- No new service-runtime portability, performance, security certification or independent reproduction claim.
- Pro review is another AI assistant's analysis, not external scientific peer review.
- Scientific novelty, comparative usefulness and advantage: NOT_ESTABLISHED. Complete OASI: NOT_DEMONSTRATED.
