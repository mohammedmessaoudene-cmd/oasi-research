# OASI v0.4.1 — claims and evidence matrix

| ID | Claim | Status | Evidence | Boundary |
|---|---|---|---|---|
| T-01 | AERA denotes bounded commit-time authority revalidation, with implementation profiles stated separately | SUPPORTED-AS-TERMINOLOGY | `AERA_SPECIFICATION.md`, `AERA_TERMINOLOGY_ERRATUM.md`, formal predicate in `source/main.tex` | The article-level predicate is broader than the finite public Rust profile; this naming correction adds no implementation or assurance evidence |
| C-01 | Operational monism is specified | SUPPORTED-AS-SPECIFICATION | State model, organ projections, authority asymmetry | Specification is not utility or implementation evidence |
| C-02 | The AERA core predicate performs body-bound commit checks in the reference model | INTERNALLY SUPPORTED | Differential paths, focused mutants, public Rust tests | No independently developed runtime, production executor, external-effect atomicity, or cryptographic attestation |
| C-03 | Shared canonical state improved T4 decisions | NEGATIVE | Frozen paired T4 result | Comparator did not construct-validly test developmental closure |
| C-04 | S5 established an OASI advantage over cooperative B3 | NEGATIVE | 1,200 sealed deterministic records; B3 matched safety and recovered more deliveries | Local trace simulator only |
| C-05 | S6 observed duplicate/omission divergence between redispatch and no-redispatch | DIAGNOSTIC | 1,500 sealed deterministic records and aggregate checker | No policy-matched at-most-once baseline; not OASI-specific |
| C-06 | S5/S6 estimate real fault probabilities | NOT SUPPORTED | Outcomes are invariant within deterministic cells | No independent population sampling or inferential interval claim |
| C-07 | S5/S6 exercised real crash, transport loss, or storage tear | NOT SUPPORTED | Script inspection shows control-flow traces and post-close corruption | Requires process, transport, and storage fault injection |
| C-08 | OASI guarantees exactly-once external effects | EXCLUDED | OASI avoids modeled redispatch after consume | At-most-once can omit; opaque sinks prevent outcome knowledge |
| C-09 | OASI is generally superior or production-ready | EXCLUDED | No supporting evidence | No real sink, deployment, adversarial host, or external replication |
| C-10 | A complete OASI organism exists | NOT DEMONSTRATED | No longitudinal organismic experiment | Remains an open research program |

The labels `INDEPENDENT_VERIFY_RESULT.json` inside the sealed S5/S6 result sets
are historical filenames. They denote outputs of a detached aggregate checker,
not independent-team replication.

The v0.4.1 terminology correction does not alter any claim status, evidence
object, experimental count, or causal interpretation inherited from v0.4.
