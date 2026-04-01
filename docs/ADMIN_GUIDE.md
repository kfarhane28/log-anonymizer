# Admin Guide

## Batch output structure

When the CLI or UI receives more than one input in a single execution, it writes outputs under a batch directory inside the configured output directory:

- `<output>/batch-YYYYMMDD-HHMMSS/`
  - `batch_summary.json`
  - `001-<input-name>/.../*.tar.gz`
  - `002-<input-name>/.../*.tar.gz`
  - ...

This avoids filename collisions (especially when filename anonymization is enabled, which forces a fixed output archive name).

## Concurrency controls

Batch mode uses two independent layers of parallelism:

1) Across inputs (batch-level worker pool)
- CLI: `--batch-parallel --batch-max-workers N`
- UI: “Enable parallel input processing (batch)” + “Max parallel inputs”

2) Inside an input (file-level worker pool)
- CLI: `--parallel --max-workers N`
- UI: “Enable parallel file processing” + “Max parallel workers”

These are intentionally separate so you can tune CPU/memory usage depending on bundle size and number of inputs.

