# Corrigendum — OASI scientific preprint v0.4.1

## Affected record

This corrigendum applies to the published OASI preprint v0.4 at
[10.5281/zenodo.22262138](https://doi.org/10.5281/zenodo.22262138) and to the
corresponding manuscript preserved in the immutable
`v0.2.1-research-preview` repository tag. It does not replace or silently
rewrite that historical record.

## Correction

The v0.4 manuscript expands AERA as **“Atomic Embodiment Runtime Assurance.”**
The companion root specification in the same release instead expands AERA as
**“Attested Epoch-bound Runtime Authority.”** These phrases are quoted only to
identify the conflicting historical wording.

Beginning with this corrective manuscript, **AERA has no normative long-form
expansion**. AERA is the stable identifier for a bounded commit-time
authority-revalidation predicate. The predicate revalidates, immediately
before a protected effect, an authority envelope bound to body identity,
epoch, generation, certificate, principal, resource, action, policy,
body-state and evidence digests, revocation and quarantine state, and
expiration.

The term **AERA reference runtime** denotes the broader implementation profile
that supports the core predicate with prepare/commit state, strict framed
protocol handling, fail-closed child management, an evidence ledger, and
bounded rollback or quarantine paths.

The article-level predicate contains bindings that are not all present in the
finite public Rust predicate. Policy, body-state, evidence, revocation,
quarantine, and effect-digest terms remain architectural requirements unless a
specific implementation and test are cited for them. The terminology
correction does not promote those terms to implemented status.

## Reason

The word associated with atomicity could be read as claiming an indivisible
transaction across local authorization, the evidence ledger, and an arbitrary
external effect. The current artifact does not establish that guarantee; the
S5/S6 results retain the retry-versus-omission boundary.

The word associated with attestation could be read as claiming a
cryptographic or hardware-rooted trust basis. The public Rust protocol states
that its checksum is not a MAC, signature, identity proof, or cryptographic or
hardware attestation.

The corrected descriptive definition follows the implemented and formalized
semantics without promoting either unsupported property.

## Exact manuscript changes

- The abstract describes AERA as a bounded commit-time
  authority-revalidation predicate.
- The contribution list and section heading use commit-time authority
  revalidation rather than a long-form acronym expansion.
- The formal predicate, lease tuple, invariants, proposition, evidence tables,
  experimental results, references, and conclusion remain substantively
  unchanged.
- The French abstract applies the same terminology correction.

## No change in scientific status

This corrigendum does not:

- change source code, tests, fixtures, raw records, or experimental results;
- establish external-effect atomicity or exactly-once delivery;
- establish cryptographic or hardware attestation;
- convert internal checks into independent replication;
- establish production readiness, a complete OASI organism, or general
  superiority;
- authorize modification of the v0.3 or v0.4 directories, prior tags, DOI
  payloads, or sealed archives.

The claim statuses in `CLAIMS_AND_EVIDENCE_V0_4_1.md` remain bounded by the
same evidence as v0.4.
