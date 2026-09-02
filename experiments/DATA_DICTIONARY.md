# S5/S6 data dictionary

Each line of `RAW_RUNS.jsonl` is one deterministic simulated trace.

| Field | Meaning |
|---|---|
| `schema` | Record schema identifier. |
| `mechanism`, `case`, `repetition`, `seed` | Experimental cell and deterministic identity. |
| `effect_count` | Number of rows appended to the local effect fixture. |
| `double_effect` | True when `effect_count > 1`. |
| `delivered_exactly_once` | True when exactly one fixture row exists; not a universal exactly-once claim. |
| `delivery_lost`, `effect_expected` | S6 indicators for a modeled expected effect with zero rows. |
| `disposition`, `deterministic_terminal` | Scripted terminal label and membership in the allowed terminal set. |
| `replay_accepted`, `cross_generation_accepted`, `altered_signature_accepted` | Whether the simulated route accepted the named invalid input. |
| `ambiguous_post_effect`, `pre_effect_uncertainty` | S6 classification flags assigned by the scripted case. |
| `sink_*`, `b3_idempotency_request_honored` | S6 declared capabilities of the append-only receiver fixture. |
| `wall_ns`, `cpu_ns` | Local process timing. Exploratory only. |
| `python_heap_peak_bytes`, `rss_delta_bytes`, `artifact_bytes` | Local allocation and file-size indicators. Exploratory only. |
| `network_calls`, `real_effect` | Scope sentinels emitted by the generator; not independently observed network telemetry. |

The 30 repetitions per cell vary deterministic seeds and execution order but
follow the same categorical branch. They must not be interpreted as independent
population samples.

