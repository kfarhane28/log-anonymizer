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
- Structured logging (JSON) at `INFO` by default (configurable)
- Streams large files line-by-line (memory efficient); skips likely-binary files

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
- If you enable profiling + dry-run, the UI runs profiling only (no archive) and lets you download the report and suggested rules.

In **Preview anonymisation**, paste a small log excerpt, click **Anonymiser**, and review the anonymized output immediately (in-memory; no output files are generated).

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

- This tool processes files as text; it attempts UTF-8 decoding first and falls back to Latin-1.
- It streams line-by-line to handle large log files.

## License

Apache License 2.0. See `LICENSE`.
