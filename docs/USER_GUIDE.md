# User Guide

## Batch processing (multiple inputs)

The Log Anonymizer can process multiple top-level inputs in a single run. Each input is treated independently, and failures are reported per input without necessarily stopping the whole batch.

### Supported inputs

- Regular files
- Directories
- `.zip` archives
- `.tar.gz` / `.tgz` archives

### CLI

Use repeated `--input` arguments:

```bash
log-anonymizer \
  --input path/to/logs_dir \
  --input path/to/bundle.zip \
  --input path/to/support.tar.gz \
  --output out
```

Parallelize across inputs (optional):

```bash
log-anonymizer \
  --input a.zip --input b.tar.gz --input logs/ \
  --output out \
  --batch-parallel --batch-max-workers 3
```

Output layout for batch runs:

- A batch subfolder is created under `--output` (example: `out/batch-20260401-153012/`)
- One subfolder per input (example: `001-bundle.zip/`)
- One anonymized `.tar.gz` archive per input subfolder
- A `batch_summary.json` file is written at the batch root

### UI (Streamlit)

- Select **Upload** and upload multiple files at once (regular files and archives can be mixed)
- Or select **Use path(s)** and provide one path per line
- Run the batch and download one output archive per input from the **Output** panel

