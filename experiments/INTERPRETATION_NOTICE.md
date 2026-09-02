# Publication-level interpretation notice

The files under `s5/results/` and `s6/results/` are sealed historical outputs
and are preserved byte-for-byte. Preservation does not make every sentence in
their original reports the final v0.2 scientific conclusion.

The internal S5 and S6 reports retain wording that the publication-level audit
does not adopt. S5 calls its bundled checker "independent," reports Wilson
intervals over deterministic repeated rows, and states a broader OASI
resolution claim than its cooperative-receiver comparison supports. S6 retains the verdict
`BOUNDED_SAFETY_ADVANTAGE_ESTABLISHED_NON_COOPERATIVE_FIXTURE_WITH_AVAILABILITY_TRADEOFF`,
Wilson intervals computed over repeated rows, and the phrase "independent
verifier." A subsequent publication-level adversarial source and methods audit
superseded those interpretations:

- S6 has no policy-matched durable at-most-once baseline. B2 and B3-U execute
  the same redispatch path. The observed difference therefore cannot be
  attributed specifically to OASI.
- All categorical outcomes are invariant within each deterministic cell. The
  repeated rows are not independent population samples, so the Wilson
  intervals are not used for inferential claims.
- Crash, disconnect, and torn-write cases are scripted control-flow traces,
  not physical faults.
- The bundled checker is detached from the generator and recomputes aggregates,
  but it is not an external-team replication and cannot inspect deleted per-run
  databases.
- The same checker and sampling limits apply to S5. Its defensible conclusion
  is only that no OASI mechanism advantage was established against the
  cooperative idempotent B3 receiver in the tested fixture. The S5 report's
  broader sentence about resolving non-cooperative double effects is not
  supported by S5 and is superseded here.

The controlling v0.2 verdict is:

`MECHANISM_SPECIFIC_ADVANTAGE_NOT_ESTABLISHED; BOUNDED_SAFETY_AVAILABILITY_TRADEOFF_OBSERVED`

See `../SCIENTIFIC_RESULTS_S5_S6.md` and
`../paper/v0.4/INTERNAL_ADVERSARIAL_REVIEW_V0_4.md` for the complete boundary.
