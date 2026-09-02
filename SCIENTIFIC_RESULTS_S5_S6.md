# OASI S5--S6: local fixture results and claim boundary

## Publication-level verdict

`MECHANISM_SPECIFIC_ADVANTAGE_NOT_ESTABLISHED; BOUNDED_SAFETY_AVAILABILITY_TRADEOFF_OBSERVED`

S5 and S6 jointly show that the outcome depends on receiver cooperation and on
the recovery policy chosen at an ambiguous effect boundary. This is useful
evidence about the design space, but it does not establish general OASI
superiority.

## S5: cooperative receiver

S5 executed 1,200 measured runs: five mechanisms, eight cases, and 30
deterministic repetitions per cell after five excluded warmups. OASI produced
no observed duplicate effect, replay acceptance, cross-generation acceptance,
or altered-signature acceptance. The cooperative B3 receiver also produced no
observed duplicate effect and recovered more deliveries. The mechanism-
advantage criterion, locked locally before measurement but not registered in a
public registry, concluded `MECHANISM_ADVANTAGE_NOT_ESTABLISHED_AGAINST_B3`.

## S6: non-cooperative receiver

S6 executed 1,500 measured traces: five mechanisms, ten cases, and 30
deterministic repetitions per cell after five excluded warmups. In the two
post-effect ambiguity labels (`disconnect_after_effect` and
`ack_lost_after_effect`), the redispatching B3-unavailable policy produced 60
duplicate effects in 60 traces; OASI produced none and delivered 60 effects
once. The two labels exercise the same simulated recovery branch, not two
independent physical fault mechanisms.

The 90 pre-effect omissions split into two different causes. Thirty are clean
`PREPARED` aborts, for which submission of a new attempt is not modeled. Sixty
follow durable `CONSUMED` state before any effect and are blocked from
redispatch. The redispatch policy delivered all 90 once in the simulator.

These categorical outcomes were invariant across deterministic repetitions.
Accordingly, the repetition count measures implementation stability under the
fixture seeds; it is not treated as independent population sampling. Wilson
intervals present in the sealed internal summary are retained for provenance
but are not used for inferential claims in this publication.

## Adversarial interpretation

In S6, B2 and `B3_IDEMPOTENT_UNAVAILABLE` share the same redispatch path. The
OASI path instead marks an operation consumed before dispatch and refuses to
redispatch after ambiguity. The observed 60-versus-0 duplicate difference is
therefore attributable to this explicit retry-versus-no-retry policy contrast;
the experiment does not isolate a uniquely OASI implementation feature. The
scientifically defensible result is the policy tradeoff itself. A
policy-matched at-most-once baseline is required before attributing the
difference to OASI-specific structure.

The cases named crash, disconnect, and torn write are deterministic trace
simulations. They do not kill a separate process, close a live transport, or
inject a physical partial write. The torn-write branch appends corrupt bytes to
a cleanly closed SQLite file and tests seal rejection. The bundled checker is
a detached aggregate checker: it recalculates records and summaries but
cannot inspect per-run databases because those databases were
deleted by the campaign. Timing, CPU, RSS, and heap values are exploratory;
the host timer quantization and mostly zero CPU/RSS deltas preclude strong
performance conclusions.

This interpretation is consistent with established systems guidance: retries
of non-idempotent operations are unsafe when the client cannot know whether the
original effect occurred, and end-to-end exactly-once behavior normally
requires cooperation at the receiver or shared transactional state. See the
[Kafka delivery-semantics documentation](https://kafka.apache.org/42/design/design/),
[Flink 1.20 source/sink guarantees](https://nightlies.apache.org/flink/flink-docs-release-1.20/docs/connectors/datastream/guarantees/),
and the [Unum NSDI 2023 paper](https://www.usenix.org/conference/nsdi23/presentation/liu-david).
[RIFL](https://doi.org/10.1145/2815400.2815416) is an important counterexample
to any universal impossibility claim: it obtains stronger RPC semantics by
adding durable request identity and result retention at a cooperating server,
assumptions deliberately absent from the S6 fixture.

## Scope exclusions

The campaigns are local, fixture-only Python/SQLite experiments. They use
documented Ed25519 fixture keys and NOOP effects. They do not measure a guest,
QEMU, hardware, a production sink, adversarial host compromise, real keys,
external effects, deployment, or scientific replication by an independent
team. Performance values are descriptive micro-measurements from one WSL host
and are not general benchmarks.

## Reproducible evidence

- S5 raw records: `experiments/s5/results/RAW_RUNS.jsonl`
- S5 summary and detached aggregate-checker output: `experiments/s5/results/`
- S6 raw records: `experiments/s6/results/RAW_RUNS.jsonl`
- S6 summary and detached aggregate-checker output: `experiments/s6/results/`
- Linux/WSL runners and tests, qualified on WSL1 x86_64: `experiments/s5/`, `experiments/s6/`
- Executed-source hashes and portability delta:
  `experiments/EXECUTED_SOURCE_PINS.json`
