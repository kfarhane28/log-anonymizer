<p align="center">
  <img src="assets/logo.svg" width="96" alt="Log Anonymizer logo" />
</p>

<h1 align="center">Log Anonymizer</h1>

<p align="center">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-informational">
  <img alt="UI" src="https://img.shields.io/badge/UI-Streamlit-ff4b4b">
</p>

Production-ready CLI + Streamlit UI to redact/anonymize Hadoop ecosystem logs (HDFS, YARN, Hive, Spark, Impala, etc.) before sharing support bundles.

The project ships with a minimal set of built-in rules (IPs, Kerberos principals, common user/password key/value patterns) and lets you add your own rules and exclude patterns.

## Features

- Inputs: directory, single file, `.zip` archive, or `.tar.gz` archive
- Outputs: a single `.tar.gz` archive written inside the `--output` directory (preserves structure)
- `.exclude` support (glob patterns) to exclude sensitive/binary/large artifacts from both processing and output archive
- Built-in Hadoop-focused redaction rules + optional user-provided rules (`rules.json`)
- Optional parallel file processing (off by default; configurable max workers, default 5)
- Structured logging (JSON) at `INFO` by default (configurable)
- Streams large files line-by-line (memory efficient); never anonymizes non-text/binary files (but can include them in the output archive unless excluded)

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Quick start (CLI)

```bash
log-anonymizer \
  --input tmp_test/in \
  --output tmp_test/out
```

Output:
- the tool generates `tmp_test/out/in.tar.gz` and prints its path

## Web UI (Streamlit)

Launch the web UI:

```bash
source .venv/bin/activate
streamlit run app.py
```

The UI exposes the same options as the CLI, plus:
- live logs
- download button for the resulting archive
- optional sensitive-data profiling (heuristic) + suggested rules download
- editable **Rules** and **Exclude** tabs (view/modify uploaded content interactively)
- **Preview anonymisation** tab to test anonymization on pasted log lines (no files written)
- **Cancel** button during execution (safe stop with consistent output state)
- If you enable profiling + dry-run, the UI runs profiling only (no archive) and lets you download the report and suggested rules.
- **Performance** controls: enable/disable parallel processing and configure max parallel workers (default 5; can be overridden via `$LOG_ANONYMIZER_WORKERS`).

In **Preview anonymisation**, paste a small log excerpt, click **Anonymiser**, and review the anonymized output immediately (in-memory; no output files are generated).

## Workflow diagrams (.tar.gz input)

This section explains the end-to-end pipeline used when the input is a `.tar.gz` support bundle.
Most stages are shared with directory and single-file inputs; the main difference is the extraction/preparation step.

### 1) High-level processing workflow

```mermaid
flowchart TD
    A[Receive input: .tar.gz] --> B[Extract archive to temporary working directory]
    B --> C[Discover files recursively]
    C --> D[Load built-in exclude patterns]
    D --> E{User .exclude provided?}
    E -->|Yes| F[Append user patterns]
    E -->|No| G[Use built-in patterns only]
    F --> H[Filter files for output]
    G --> H
    H --> I{File is excluded?}
    I -->|Yes| I1[Skip from processing and output]
    I -->|No| J{Text file?}
    J -->|No| J1[Mark as passthrough; keep in output]
    J -->|Yes| K[Load rules: built-in + rules.json]
    K --> L{Execution mode}
    L -->|Sequential| M[Process one file at a time]
    L -->|Parallel| N[Process files with worker pool]
    M --> O[Anonymize text files line-by-line]
    N --> O
    O --> P[Write each file to temp output file]
    P --> Q[Atomic rename when file completes]
    J1 --> R[Copy passthrough files to output staging]
    Q --> S[Build final .tar.gz archive from staging dir]
    R --> S
    S --> T[Cleanup temporary extraction + staging directories]
    T --> U[Done]
```

For `.zip`, directory, and single-file inputs, the same filtering/anonymization/output stages are reused; only input preparation differs.

### 2) Decision and optional behavior map

```mermaid
flowchart TD
    A[Run starts from CLI or Streamlit UI] --> B{Preview tab?}
    B -->|Yes (UI)| B1[In-memory anonymization only; no files written] --> Z[Done]
    B -->|No| C{Dry-run enabled?}

    C -->|Yes| D{Profiling enabled?}
    D -->|Yes| D1[Profiling-only run: generate profiling_report.json + suggested_rules.json]
    D -->|No| D2[Show planned files/rules/excludes; no output archive]
    D1 --> Z
    D2 --> Z

    C -->|No| E[Normal anonymization pipeline]
    E --> F{Profile sensitive data?}
    F -->|Yes| F1[Also write profiling_report.json + suggested_rules.json]
    F -->|No| G[Skip profiling]
    F1 --> H
    G --> H

    H{Parallel enabled?}
    H -->|Yes (--parallel / UI checkbox)| H1[Concurrent file workers]
    H -->|No (default)| H2[Sequential file workers]
    H1 --> I
    H2 --> I

    I{Per-file outcome}
    I -->|Success| I1[Include processed file]
    I -->|Error| I2[Log error and continue with next file]
    I -->|Excluded| I3[Not included in output]
    I -->|Non-text and not excluded| I4[Passthrough copy in output]
    I1 --> J[Create final .tar.gz]
    I2 --> J
    I3 --> J
    I4 --> J
    J --> K[Cleanup]
    K --> Z[Done]
```

This diagram highlights optional branches that are already available in code and flags/options (`--dry-run`, profiling, parallel mode, UI preview).

### 3) Safe cancellation and output consistency

```mermaid
flowchart TD
    A[UI run in progress] --> B[User clicks Cancel]
    B --> C[Shared cancellation token set]
    C --> D[Scheduler stops accepting new files]
    D --> E[In-flight file checks token regularly]
    E --> F{Current file completed?}
    F -->|No| F1[Discard temp file; do not publish partial file]
    F -->|Yes| F2[Atomic rename temp file to final path]
    F1 --> G
    F2 --> G

    G{Rollback on cancel enabled?}
    G -->|No (default in UI/CLI)| H[Keep already committed files]
    G -->|Yes (backend config)| I[Remove generated archive / rollback output]
    H --> J[Finalize status: Cancelled with partial output kept]
    I --> K[Finalize status: Cancelled and rolled back]

    L[Any uncaught exception] --> M[Status: Failed]
    J --> N[Cleanup temporary extraction + staging dirs]
    K --> N
    M --> N
```

Cancellation is cooperative and safe: unfinished files are never partially written, completed files stay valid, and cleanup runs in all terminal states.

## Usage

### CLI examples

```bash
log-anonymizer --help
```

Anonymize a directory:

```bash
log-anonymizer \
  --input /path/to/logs \
  --output anonymized-out \
  --rules examples/rules.json \
  --exclude examples/.exclude
```

Anonymize a single file:

```bash
log-anonymizer \
  --input /path/to/hadoop.log \
  --output anonymized-out \
  --rules examples/rules.json
```

Anonymize a zip support bundle:

```bash
log-anonymizer \
  --input /path/to/support-bundle.zip \
  --output anonymized-out \
  --rules examples/rules.json \
  --exclude examples/.exclude
```

Anonymize a tar.gz support bundle:

```bash
log-anonymizer \
  --input /path/to/support-bundle.tar.gz \
  --output anonymized-out \
  --rules examples/rules.json \
  --exclude examples/.exclude
```

### Parallel processing (optional)

By default, the tool processes files **sequentially**. For large bundles, you can enable parallel processing:

```bash
# Parallel mode, default 5 workers
log-anonymizer --parallel --input /path/to/support-bundle.tar.gz --output anonymized-out
```

```bash
# Parallel mode with a custom limit
log-anonymizer --parallel --max-workers 3 --input /path/to/support-bundle.tar.gz --output anonymized-out
```

Notes:
- Parallelism applies to **independent files** (not to lines within a file).
- The output `.tar.gz` is still built in a single step (no concurrent writes to the archive).
- File ordering inside the output archive is kept deterministic (sorted by relative path).

### Dry-run

Preview which files will be processed, and how rules/exclude will be applied:

```bash
log-anonymizer \
  --input /path/to/support-bundle.zip \
  --output anonymized-out \
  --dry-run
```

### Optional sensitive-data profiling (heuristic)

You can optionally scan input text logs to detect *potential* sensitive data and generate rule suggestions.

This mode is **OFF by default** and does **not** change anonymization unless you apply the suggested rules.

```bash
log-anonymizer \
  --input /path/to/support-bundle.zip \
  --output anonymized-out \
  --profile-sensitive-data
```

Outputs (in addition to the archive):
- `anonymized-out/profiling_report.json`
- `anonymized-out/suggested_rules.json`

Profiling-only (no anonymization / no archive):

```bash
log-anonymizer \
  --input /path/to/support-bundle.zip \
  --output anonymized-out \
  --dry-run \
  --profile-sensitive-data
```

Optional flags:
- `--profiling-detectors email,ipv4,token,card`
- `--profiling-report /path/to/report.json`
- `--suggest-rules-output /path/to/suggested_rules.json`

## Configuration

Default logging configuration can be set via `log-anonymizer.ini` (or `--config`, or `$LOG_ANONYMIZER_CONFIG`):

```ini
[logging]
level = INFO
format = json
```

## Rules file (`rules.json`)

User rules are applied in addition to built-in rules. File format:

```json
{
  "version": 1,
  "rules": [
    {
      "description": "Bearer token",
      "trigger": "Bearer ",
      "search": "(?i)\\bBearer\\s+\\S+\\b",
      "replace": "Bearer [REDACTED]",
      "caseSensitive": "false"
    }
  ]
}
```

Notes:
- `trigger` is an optional fast substring pre-check (rule runs only if the trigger is present in the line). If omitted/empty, the rule runs on every line.
- `search` is a Python regex, `replace` is passed to `re.sub`.
- `caseSensitive` defaults to `true` if omitted.

## `.exclude` format

The `.exclude` file is a line-based list of glob patterns.

- Blank lines and lines starting with `#` are ignored.
- Patterns are matched against the POSIX-style relative path (with `/` separators).
- Patterns starting with `!` negate (re-include) a previously excluded match.

### Built-in excludes (default)

Even without `--exclude`, the CLI excludes common credential/key material by default:

```
creds.localjceks
creds.localjceks.sha
*.jceks
*.jceks.sha
*.keytab
krb5.conf
jaas.conf
*.jks
*keystore*
*truststore*
*.p12
*.pfx
*.pem
*.key
*.crt
*.cer
*.der
*.kdb
```

If you pass `--exclude path/to/.exclude`, its patterns are appended after the built-ins (so your file can override defaults using `!`):

```
!**/krb5.conf
**/*.parquet
```

See `examples/.exclude`.

## Development

Run tests:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

## Notes

- Text files are anonymized; the tool attempts UTF-8 decoding first and falls back to Latin-1.
- Non-text/binary files are never anonymized; they are included as-is only if not excluded by built-in excludes or your `.exclude`.
- It streams line-by-line to handle large log files.

## License

Apache License 2.0. See `LICENSE`.
