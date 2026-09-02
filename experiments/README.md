# S5 and S6 local fixture experiments

This directory publishes the data, protocols, verification code, and
experiment runners relocatable on Linux/WSL and qualified on WSL1 x86_64 for
two deterministic local campaigns:

- **S5:** a cooperative-sink comparison. The strongest baseline, B3 with
  receiver-side idempotence, matched the observed OASI safety outcomes and
  recovered more deliveries. The claimed mechanism advantage was therefore
  not established.
- **S6:** a non-cooperative append-only sink comparison. OASI's durable
  consume-before-dispatch policy produced no duplicate effects in the tested
  post-effect ambiguity cells, while a redispatch policy produced duplicates.
  The same OASI policy omitted deliveries in pre-effect ambiguity cells.

The combined publication-level conclusion is deliberately narrower than the
campaign's original internal S6 verdict: these fixtures expose a deterministic
**safety--availability policy tradeoff**. They do not isolate a uniquely OASI
mechanism, establish universal exactly-once effects, or support production,
guest, QEMU, hardware, or external-validity claims.

Each `results/` directory is byte-identical to its sealed campaign result set
and retains its original `RESULT_MANIFEST.sha256`. The public `experiment.py`
files differ from the executed files only in replacing a private absolute
module path with the relative `../common` path. The imported
`common/oasi_broker.py` is byte-identical to the executed ledger source.
`EXECUTED_SOURCE_PINS.json` records the original hashes.

See [REPRODUCIBILITY.md](../REPRODUCIBILITY.md) for commands and
[SCIENTIFIC_RESULTS_S5_S6.md](../SCIENTIFIC_RESULTS_S5_S6.md) for the full
claim boundary.

Read `INTERPRETATION_NOTICE.md` before citing either sealed historical report.
The reports are preserved byte-for-byte, but some original S6 wording and
interval treatment were superseded by the publication-level adversarial audit.
