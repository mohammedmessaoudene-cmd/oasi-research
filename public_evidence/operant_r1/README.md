# OASI operant study — results archive

`oasi-operant-results.zip` (21,037 bytes) is a results-only supplement to the previous software/data release. Its SHA-256 is in `SHA256SUMS.txt`. Extract the archive; run the following from the extracted `oasi-operant-results` directory with Python 3.11:

```sh
python -B -E -s -S verify_results.py
python -B -E -s -S -m unittest -v test_reader
```

The reader checks the internal consistency of the published derived data; it does not execute the original host service, authenticate the original receipts, or establish independent replication. The acquired rule and conservative fallback propose different initially admissible actions. With reduced buffer capacity, the recorded feedback cases show a different request before admission. The conventional option using the same tree follows the same trajectories. No advantage specific to OASI is established. See the archive for the per-case results, controls and limitations.

**Measurement and attribution.** Each successful admission, completed batch, produced record and extra content check performed in drift mode counts as one unit. The totals 104/104/100/100 sum only the four transfer episodes per arm. They exclude the two acquisition episodes (25 units combined), the four controls, policy compilation, process startup and CPU time. A conditional change before the guard is compatible with executing the shared tree; it does not establish that learning this tree, rather than supplying it conventionally, was necessary.

**Rights notice for this exact seal.** The owner approved publication of the above ZIP: Apache-2.0 for the new passive reader and tests; CC BY 4.0 for new documentation and derived data. This notice activates the file-specific terms proposed inside the sealed ZIP without altering it. Historical software and the article are not relicensed.
