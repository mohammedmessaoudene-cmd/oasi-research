# Independent reproduction target

## Purpose and effort

This is a bounded 4–8 hour request to reproduce the released OASI/AERA
v0.2.2 implementation and the S5/S6 categorical outcomes on Linux x86_64.
Negative results, setup failures, undocumented dependencies, and categorical
mismatches are valid outcomes and must be preserved without weakening tests.

This is not an independently developed implementation, a production audit, a
performance benchmark, or evidence of institutional endorsement.

## Pinned release procedure

```sh
git clone https://github.com/mohammedmessaoudene-cmd/oasi-research.git
cd oasi-research
git checkout --detach v0.2.2-research-preview
git rev-parse HEAD
test -z "$(git status --porcelain)"
sh tools/run_tests.sh post-doi \
  10.5281/zenodo.22266419 \
  10.5281/zenodo.22266401
```

Record the resolved commit before running. The final public issue will also pin
that commit, the tag object, both DOI records, and both released file hashes.

## Fresh S5/S6 generation

```sh
work="$(mktemp -d)"
python3 -I -B experiments/s5/experiment.py \
  --output "$work/s5-out" --scratch "$work/s5-scratch" \
  --preregistration experiments/s5/results/PREREGISTRATION_LOCKED.md
python3 -I -B experiments/s5/verify_results.py --results "$work/s5-out"

python3 -I -B experiments/s6/experiment.py \
  --output "$work/s6-out" --scratch "$work/s6-scratch" \
  --preregistration experiments/s6/results/PREREGISTRATION_LOCKED.md
python3 -I -B experiments/s6/verify_results.py --results "$work/s6-out"

python3 -I -B tools/compare_experiment_categories.py \
  experiments/s5/results/RAW_RUNS.jsonl "$work/s5-out/RAW_RUNS.jsonl"
python3 -I -B tools/compare_experiment_categories.py \
  experiments/s6/results/RAW_RUNS.jsonl "$work/s6-out/RAW_RUNS.jsonl"
sha256sum "$work/s5-out/RAW_RUNS.jsonl" "$work/s6-out/RAW_RUNS.jsonl"
```

Categorical comparisons, not timings or raw-file byte identity, are the
reproduction target. Fresh host timing, CPU, RSS, heap, and storage values may
differ.

## Expected observations, not pass-forcing requirements

- the Rust, S5, S6, deliberate-mutant, terminology, experiment, and release
  checks complete without a failure;
- sealed S5 contains 1,200 records across 40 cells;
- sealed S6 contains 1,500 records across 50 cells;
- each categorical comparison reports no missing tuples, extra tuples, or
  categorical mismatches;
- the publication verdict remains
  `MECHANISM_SPECIFIC_ADVANTAGE_NOT_ESTABLISHED;`
  `BOUNDED_SAFETY_AVAILABILITY_TRADEOFF_OBSERVED`.

If any observation differs, report the unmodified difference rather than
changing the artifact to match this list.

## Required reproduction report

Report all of the following:

1. operating system, architecture, kernel, and exact tool versions;
2. checked-out commit, tag object, and clean/dirty status;
3. exit codes and the complete command transcript;
4. released ZIP/PDF sizes and SHA-256 values;
5. fresh S5 and S6 raw-file SHA-256 values;
6. both categorical-comparator JSON outputs;
7. the first unmodified failure and logs, if anything fails;
8. any undocumented setup step;
9. all local modifications, if any;
10. whether the reporter was independent of the project before this run;
11. conflicts, compensation, or institutional relationships;
12. whether the result is complete, partial, failed, or exploratory;
13. whether the exact qualified environment was used;
14. a statement that timing and memory equality was not required;
15. permission status for quoting or linking the report.

## Safety and interpretation boundary

The campaigns use public fixture keys, local NOOP effects, and no network
during execution. They do not exercise hardware faults, physical power loss,
severed live transports, production receivers, deployment, or a complete OASI.
Read `experiments/INTERPRETATION_NOTICE.md` before interpreting S6: its result
is a retry-versus-omission policy tradeoff, not a general exactly-once result or
an OASI-specific advantage.
