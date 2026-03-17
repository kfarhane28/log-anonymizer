# log-anonymizer

Production-ready CLI tool to anonymize Hadoop/Cloudera logs (HDFS, YARN, Hive, Spark, Impala, etc.) using configurable regex rules.

## Features

- Accepts input as a directory, a single file, or a `.zip` archive
- Produces a `.zip` archive with anonymized logs (preserves folder structure)
- `.exclude` support (glob patterns) to skip files you don't want to ship (e.g., binaries, archives, huge traces)
- Deterministic anonymization via salted hashing (so repeated identifiers map to the same anonymized token)
- Structured logging (JSON) at INFO by default

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Quick start

### 1) Anonymize a directory of logs

```bash
log-anonymizer /path/to/logs \
  --rules examples/rules.json \
  --exclude examples/.exclude \
  --output anonymized-logs.zip
```

### 2) Anonymize a single file

```bash
log-anonymizer /path/to/hadoop.log \
  --rules examples/rules.json \
  --output anonymized.zip
```

### 3) Anonymize a zip of logs

```bash
log-anonymizer /path/to/support-bundle.zip \
  --rules examples/rules.json \
  --exclude examples/.exclude \
  --output anonymized-support-bundle.zip
```

## Rules format

Rules are loaded from JSON and applied sequentially to each line.

Supported actions:
- `hash`: replace each match with a deterministic hash token (recommended)
- `mask`: replace each match with `*` of the same length
- `token`: replace each match with a fixed token string (e.g., `[REDACTED]`)
- `replace`: replace using a `re.sub` replacement string (supports capture groups)

See `examples/rules.json`.

## `.exclude` format

The `.exclude` file is a line-based list of glob patterns.

- Blank lines and lines starting with `#` are ignored.
- Patterns are matched against the POSIX-style relative path (with `/` separators).
- Patterns starting with `!` negate (re-include) a previously excluded match.

See `examples/.exclude`.

## CLI reference

```bash
log-anonymizer --help
```

Common options:
- `--salt`: controls hashing stability. If omitted, a random salt is generated and logged once; provide one to make runs reproducible across environments.
- `--log-format`: `json` (default) or `text`
- `--log-level`: `INFO` (default), `DEBUG`, `WARNING`, ...

## Notes

- This tool processes files as text; it attempts UTF-8 decoding first and falls back to Latin-1.
- It streams line-by-line to handle large log files.

