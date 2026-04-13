# DO-356A Baseline DFS Experiment (Method 1)

## Purpose

This experiment implements the baseline method:

- No relation constraints
- No loop control (cycles are allowed)
- No path filtering
- Only ordinary DFS traversal on asset connections

The script runs this baseline and the current system method on the same DO-356A sample dataset, then exports a side-by-side comparison report.

## Run

From repository root:

```bash
npm run exp:do356a:baseline
```

Optional arguments (backend script):

```bash
npm run exp:do356a:baseline -w @attackgraph/backend -- --max-hops 6 --no-seed --generated-by my-exp
```

Arguments:

- `--max-hops <n>`: DFS depth limit. Default is `6`.
- `--no-seed`: do not reseed the DO-356A sample graph before running.
- `--generated-by <text>`: tag used in generated results.

## Output

The script writes one JSON report to:

- `docs/experiments/do356a-baseline-vs-system-EXP-<timestamp>.json`

The report includes:

- `summary.baseline`: total paths, cyclic paths, redundant paths, per-hop and per-entry counts
- `summary.system`: same metrics for current system output
- `summary.delta`: baseline minus system metric deltas
- `baseline_paths`: full path list from unconstrained DFS
- `system_paths`: full path list from current system analysis

## Notes

- Baseline paths are intentionally broad and may include cyclic/redundant paths.
- Current system output is expected to be smaller and more interpretable due to constraints and filtering.
