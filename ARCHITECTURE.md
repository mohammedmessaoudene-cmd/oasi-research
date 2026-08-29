# Architecture

## Reference boundary

The public implementation is a user-space Rust crate. It models a trusted coordinator, a confined child, framed requests/acknowledgements, an append-only ledger, authority snapshots, and effect commit checks.

```text
perception / request
        |
        v
candidate policy or reflex
        |
        v
AERA prepare: bind body + epoch + generation + certificate
        |
        v
confined execution / framed acknowledgement
        |
        v
commit-time revalidation ---- mismatch/expiry ----> reject + rollback/quarantine
        |
        v
append-only evidence ledger
```

## Authority tuple

The implementation represents authority using:

- body identity;
- epoch;
- generation;
- certificate;
- principal;
- resource;
- action;
- validity/expiration conditions.

The same bound snapshot must remain valid at the commit boundary. Parsing is canonical and rejects malformed, replayed, mismatched, or checksum-invalid frames.

## What this architecture excludes

No code in this repository modifies firmware, the host kernel, drivers, voltages, fans, boot configuration, or personal files. No QEMU source, Linux source, Buildroot tree, disk image, or privileged deployment artifact is included.

The reference runtime does not establish real-time guarantees, kernel mediation, resistance to a malicious host, distributed consensus, or production certification.
