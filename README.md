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

- Inputs: one or more items (directory, single file, `.zip`, `.tar.gz`)
- Outputs:
  - single input: one `.tar.gz` archive written inside the `--output` directory (preserves structure)
  - multiple inputs: one batch folder under `--output`, with one `.tar.gz` archive per input + `batch_summary.json`
- `.exclude` support (glob patterns) to exclude sensitive/binary/large artifacts from both processing and output archive
- Built-in Hadoop-focused redaction rules + optional user-provided rules (`rules.json`)
- Optional parallel file processing (off by default; configurable max workers, default 5)
- Optional parallel input processing for batch runs (separate worker pool from per-file parallelism)
- Structured logging (JSON) at `INFO` by default (configurable)
- Streams large files line-by-line (memory efficient); never anonymizes non-text/binary files (but can include them in the output archive unless excluded)

## Install

```bash
python -m venv .venv
source .venv/bin/activate

# Core (CLI only)
pip install .

# With UI dependencies (Streamlit + pandas)
pip install ".[ui]"
```

## Run (CLI)

```bash
log-anonymizer --version
log-anonymizer --help
```

Example anonymization run:

```bash
log-anonymizer --input tmp_test/in --output tmp_test/out
```

Batch run (multiple inputs in one execution):

```bash
log-anonymizer \
  --input tmp_test/in \
  --input tmp_test/bundle.zip \
  --input tmp_test/support.tar.gz \
  --output tmp_test/out \
  --batch-parallel --batch-max-workers 3
```

Output layout (batch):
- `tmp_test/out/batch-YYYYMMDD-HHMMSS/001-<input-name>/.../*.tar.gz`
- `tmp_test/out/batch-YYYYMMDD-HHMMSS/batch_summary.json`

## Run (UI)

The UI requires the optional dependencies:

```bash
pip install ".[ui]"
log-anonymizer-ui
```

Then open `http://localhost:8501`.

## Build (wheel + sdist)

```bash
python -m pip install -U build
python -m build --no-isolation
```

Artifacts are written to `dist/` (`.whl` and `.tar.gz`).

You can also run `make build` if you prefer.

## Distribution & release

- Changelog: `CHANGELOG.md`
- Release process: `docs/RELEASE.md` (includes PyPI + Docker publishing)
- Local release build + smoke tests: `make release-build`

## Install from wheel

See `docs/INSTALL_WHEEL.md` (end users) and `docs/RELEASE.md` (admins).

## Guides

- User Guide: `docs/USER_GUIDE.md`
- Admin Guide: `docs/ADMIN_GUIDE.md`

## Docker

End-user/admin guide: `docs/INSTALL_DOCKER.md`.

### Build the image

Build a single image that can run both the CLI and the Streamlit UI:

```bash
docker build -t log-anonymizer:local .
```

Build a smaller CLI-only image (no Streamlit/pandas):

```bash
docker build --build-arg WITH_UI=0 -t log-anonymizer:cli .
```

### Run the CLI (with mounted input/output)

```bash
docker run --rm \
  -v "$PWD/tmp_test/in:/input:ro" \
  -v "$PWD/tmp_test/out:/output" \
  log-anonymizer:local \
  log-anonymizer --input /input --output /output
```

With additional files:

```bash
docker run --rm \
  -v "$PWD/tmp_test/in:/input:ro" \
  -v "$PWD/tmp_test/out:/output" \
  -v "$PWD/rules.json:/config/rules.json:ro" \
  -v "$PWD/.exclude:/config/.exclude:ro" \
  log-anonymizer:local \
  log-anonymizer --input /input --output /output --rules /config/rules.json --exclude /config/.exclude
```

Config file:

```bash
docker run --rm \
  -v "$PWD/tmp_test/in:/input:ro" \
  -v "$PWD/tmp_test/out:/output" \
  -v "$PWD/log-anonymizer.ini:/config/log-anonymizer.ini:ro" \
  -e LOG_ANONYMIZER_CONFIG=/config/log-anonymizer.ini \
  log-anonymizer:local \
  log-anonymizer --input /input --output /output
```

Note: the container runs as a non-root user by default. If you hit volume permission issues on Linux, add `--user "$(id -u):$(id -g)"`.

### Run the UI (Streamlit)

```bash
docker run --rm -p 8501:8501 log-anonymizer:local log-anonymizer-ui
```

If you want the UI to read/write host files by path, mount a volume (example mounts `tmp_test` to `/data`):

```bash
docker run --rm -p 8501:8501 \
  -v "$PWD/tmp_test:/data" \
  log-anonymizer:local \
  log-anonymizer-ui
```

Then open `http://localhost:8501`.

### Docker Compose (UI)

```bash
docker compose up --build
```

## Troubleshooting

- `log-anonymizer-ui`: if it says UI deps are missing, install with `pip install "log-anonymizer[ui]"` (or `pip install ".[ui]"` from the repo).
- Docker volume permissions (Linux): the container runs as non-root; add `--user "$(id -u):$(id -g)"` if output folders are not writable.
- Build isolation/offline networks: use `python -m build --no-isolation` in an environment where build dependencies are already installed.

## Quick start (CLI)

```bash
log-anonymizer \
  --input tmp_test/in \
  --output tmp_test/out
```

Output:
- the tool generates `tmp_test/out/in.tar.gz` and prints its path

## Web UI (Streamlit)

Launch the web UI (installed entry point):

```bash
source .venv/bin/activate
log-anonymizer-ui
```

Alternatively (repo/dev convenience):

```bash
source .venv/bin/activate
streamlit run app.py
```

The UI exposes the same options as the CLI, plus:
- live logs
- multi-upload batch mode (one output archive per input)
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
    B -->|Yes UI| B1[In-memory anonymization only, no files written] --> Z[Done]
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
    H -->|Yes parallel enabled| H1[Concurrent file workers]
    H -->|No default| H2[Sequential file workers]
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
    G -->|No default| H[Keep already committed files]
    G -->|Yes backend config| I[Remove generated archive, rollback output]
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

Anonymize file and folder names in the output (also sanitizes the output archive name):

```bash
log-anonymizer \
  --input /path/to/support-bundle.tar.gz \
  --output anonymized-out \
  --rules examples/rules.json \
  --exclude examples/.exclude \
  --anonymize-filenames
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

### Legacy format (v1)

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

### Action format (v2)

Rules v2 keep the same top-level shape, but use an `action` object instead of `replace`.

```json
{
  "version": 2,
  "rules": [
    {
      "description": "Mask account number",
      "trigger": "acct=",
      "search": "(?<=\\bacct=)\\d{12,16}\\b",
      "caseSensitive": "true",
      "action": { "type": "mask", "maskChar": "*", "keepLast": 4 }
    }
  ]
}
```

Supported `action.type` values:

- `replacement`: fixed replacement (same as legacy `replace`)
  - fields: `value` (string)
- `redaction`: remove the match entirely
  - fields: none
- `mask`: mask fully/partially with a character
  - fields: `maskChar` (1 char, default `*`), `keepLast` (int), `keepFirst` (int)
- `secure_hash`: deterministic SHA-256 hash replacement
  - fields: `algorithm` (`sha256`), `salt` (optional), `length` (8–64), `prefix`, `suffix`
- `date_shift`: shift parsed dates by a deterministic number of days
  - fields: `formats` (array of `strptime` formats), `maxShiftDays` (0+), `salt` (optional), `group` (optional capture group)
- `bucket`: map numeric values into configured ranges
  - fields: `buckets` (array of `{min,max,label}`), `group` (optional capture group), `fallbackLabel`

Notes:
- A `version: 2` rules file may mix legacy rules (`replace`) and action rules (`action`) in the same `rules` array.
- Some actions support `group` to replace only a capturing group while keeping the rest of the match unchanged (useful for `age=23`).

Examples:

```json
{
  "description": "Fixed replacement (v2)",
  "trigger": "uuid=",
  "search": "\\buuid=[0-9a-fA-F-]{36}\\b",
  "action": { "type": "replacement", "value": "uuid=[UUID]" }
}
```

```json
{
  "description": "Hash email",
  "trigger": "@",
  "search": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
  "action": { "type": "secure_hash", "algorithm": "sha256", "length": 16 }
}
```

```json
{
  "description": "Redact secret",
  "trigger": "secret=",
  "search": "secret=[^\\s]+",
  "action": { "type": "redaction" }
}
```

```json
{
  "description": "Mask full (PIN)",
  "trigger": "pin=",
  "search": "(?<=\\bpin=)\\d{4}\\b",
  "action": { "type": "mask", "maskChar": "*" }
}
```

```json
{
  "description": "Mask keep last 4 (account)",
  "trigger": "acct=",
  "search": "(?<=\\bacct=)\\d{12,16}\\b",
  "action": { "type": "mask", "maskChar": "*", "keepLast": 4 }
}
```

```json
{
  "description": "Bucket age",
  "trigger": "age=",
  "search": "\\bage=(\\d+)\\b",
  "action": {
    "type": "bucket",
    "group": 1,
    "fallbackLabel": "other",
    "buckets": [
      { "min": 0, "max": 17, "label": "0-17" },
      { "min": 18, "max": 29, "label": "18-29" },
      { "min": 30, "max": 49, "label": "30-49" },
      { "min": 50, "max": 200, "label": "50+" }
    ]
  }
}
```

```json
{
  "description": "Date shift (ISO date in key/value)",
  "trigger": "date=",
  "search": "\\bdate=(\\d{4}-\\d{2}-\\d{2})\\b",
  "action": {
    "type": "date_shift",
    "group": 1,
    "formats": ["%Y-%m-%d"],
    "maxShiftDays": 30
  }
}
```

Salt for deterministic actions:
- `secure_hash` and `date_shift` are deterministic for a given salt.
- You can set a per-rule salt (`action.salt`) or a global salt in `log-anonymizer.ini`:

```ini
[anonymization]
salt = your-stable-secret-salt
```

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
