# Internal adversarial review — preprint v0.4

Status: `MAJOR_REVISION_COMPLETED`

This is an internal contradictory review, not external peer review, independent
replication, or an ACM artifact badge.

## Material findings

1. S6's B2 and `B3_IDEMPOTENT_UNAVAILABLE` routes are the same redispatch
   implementation. Without a policy-matched durable at-most-once baseline, the
   duplicate contrast is not attributable specifically to OASI.
2. Categorical outcomes are invariant within each deterministic cell. Treating
   the 30 rows as independent Bernoulli samples would be pseudoreplication.
3. Crash, disconnect, and torn-write labels are scripted traces. No process is
   killed, transport severed, or physical partial write injected.
4. The aggregate checker does not inspect the per-run databases, which the
   generator removes. It is independent of the generator implementation only
   at the record-aggregation layer.
5. The 90 S6 pre-effect omissions combine 30 clean PREPARED aborts and 60
   post-CONSUMED blocks; they require separate causal descriptions.
6. Host timing, CPU, RSS, and heap measurements are exploratory and too
   quantized or sparse for a performance claim.

## Reviewer verdict

The sealed S5 and S6 artifacts are mechanically consistent and should be
published as negative and diagnostic evidence. A positive OASI-specific S6
claim is blocked pending a policy-matched baseline, real boundary faults,
preserved per-run evidence, and external replication.

