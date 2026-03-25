# Docker install & operations

This project can be delivered as a Docker image that supports both:
- CLI (`log-anonymizer`)
- UI (`log-anonymizer-ui`, Streamlit; optional)

## Build

Build a single image that can run both the CLI and the UI:

```bash
docker build -t log-anonymizer:local .
```

Build a smaller CLI-only image (no Streamlit/pandas):

```bash
docker build --build-arg WITH_UI=0 -t log-anonymizer:cli .
```

## Run the CLI (recommended: mount input/output)

Example with mounted directories:

```bash
docker run --rm \
  -v "$PWD/tmp_test/in:/input:ro" \
  -v "$PWD/tmp_test/out:/output" \
  log-anonymizer:local \
  log-anonymizer --input /input --output /output
```

Pass rules/exclude/config as mounted files:

```bash
docker run --rm \
  -v "$PWD/tmp_test/in:/input:ro" \
  -v "$PWD/tmp_test/out:/output" \
  -v "$PWD/rules.json:/config/rules.json:ro" \
  -v "$PWD/.exclude:/config/.exclude:ro" \
  -v "$PWD/log-anonymizer.ini:/config/log-anonymizer.ini:ro" \
  -e LOG_ANONYMIZER_CONFIG=/config/log-anonymizer.ini \
  log-anonymizer:local \
  log-anonymizer --input /input --output /output --rules /config/rules.json --exclude /config/.exclude
```

## Run the UI (Streamlit)

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

## Docker Compose (UI)

```bash
docker compose up --build
```

## Admin notes

- Non-root runtime: the container runs as a non-root user by default. If you hit volume permission issues on Linux, add `--user "$(id -u):$(id -g)"`.
- UI presence: the default `Dockerfile` builds with UI enabled. For environments that disallow extra deps, use `--build-arg WITH_UI=0` and only run the CLI.

