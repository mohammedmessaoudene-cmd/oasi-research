# AERA terminology erratum

## Status

This is a versioned terminology correction for the release following
`v0.2.1-research-preview`. It does not amend or replace the bytes of the
published v0.2.1 tag, its archives, or its article PDFs.

## Corrected definition

**AERA** is a stable project identifier with no normative long-form expansion.
It denotes the bounded commit-time authority-revalidation predicate defined in
`AERA_SPECIFICATION.md` and, when explicitly qualified as the **AERA reference
runtime**, the supporting prepare/commit, protocol, child-lifecycle, ledger,
and rollback/quarantine mechanisms.

The core predicate revalidates an authority envelope immediately before a
protected effect. The envelope binds body identity, epoch, generation,
certificate, principal, resource, action, and validity conditions. A previous
successful check cannot substitute for commit-time revalidation.

## Historical inconsistency

The immutable v0.2.1 record contains two incompatible long forms:

- `AERA_SPECIFICATION.md` states **“Attested Epoch-bound Runtime Authority.”**
- The v0.3 and v0.4 article text states **“Atomic Embodiment Runtime Assurance.”**

Those phrases are quoted here only to identify the affected historical text.
Neither is a normative expansion in the corrected terminology.

## Why neither historical long form is retained

The public reference protocol explicitly states that its deterministic
checksum is not a MAC, signature, identity proof, or cryptographic or hardware
attestation. Using attestation terminology as the mechanism name would
therefore overstate the implemented trust basis.

The reference mechanism revalidates authority before an effect, but it does
not establish an atomic transaction spanning the local decision, evidence
ledger, and an arbitrary external receiver. The published S5/S6 evidence also
preserves the retry-versus-omission boundary instead of claiming universal
exactly-once behavior. Using atomicity terminology as the mechanism name could
therefore be read as a guarantee outside the demonstrated scope.

## Impact assessment

This correction changes terminology and scope partitioning only. It does not:

- change the AERA predicate, Rust implementation, protocol, tests, or evidence;
- change any S5, S6, or T4 result or its interpretation;
- promote internal evidence to independent validation;
- claim external-effect atomicity, hardware attestation, production readiness,
  or general OASI superiority;
- authorize modification of a historical tag, DOI payload, or frozen artifact.

Future normative documents should use **AERA core predicate**, **AERA
commit-time authority revalidation**, or **AERA reference runtime**, according
to the intended scope. Historical wording may appear only in an explicit
quotation accompanied by this correction.
