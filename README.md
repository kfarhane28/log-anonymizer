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

The project ships with sensible built-in rules (IPs, hostnames, Kerberos principals, usernames, common paths) and lets you add your own rules and exclude patterns.

## Features

- Inputs: directory, single file, or `.zip` archive
- Outputs: anonymized files in an output directory + a `.zip` archive (preserves structure)
- `.exclude` support (glob patterns) to exclude sensitive/binary/large artifacts from both processing and output zip
- Built-in Hadoop-focused redaction rules + user-provided rules (`rules.json`)
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
  --output tmp_test/out \
  --rules examples/rules.json \
  --exclude examples/.exclude
```

Output:
- anonymized files are written under `tmp_test/out/`
- the tool generates `tmp_test/out.zip` and prints its path

## Web UI (Streamlit)

Launch the web UI:

```bash
source .venv/bin/activate
streamlit run app.py
```

The UI exposes the same options as the CLI, plus:
- live logs
- download button for the resulting zip
- editable **Rules** and **Exclude** tabs (view/modify uploaded content interactively)

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

### Dry-run

Preview which files will be processed, and how rules/exclude will be applied:

```bash
log-anonymizer \
  --input /path/to/support-bundle.zip \
  --output anonymized-out \
  --rules examples/rules.json \
  --exclude examples/.exclude \
  --dry-run
```

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
- `trigger` is a fast substring pre-check (rule runs only if the trigger is present in the line).
- `search` is a Python regex, `replace` is passed to `re.sub`.
- `caseSensitive` defaults to `true` if omitted.

## `.exclude` format

The `.exclude` file is a line-based list of glob patterns.

- Blank lines and lines starting with `#` are ignored.
- Patterns are matched against the POSIX-style relative path (with `/` separators).
- Patterns starting with `!` negate (re-include) a previously excluded match.

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
