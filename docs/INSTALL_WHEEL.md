# Install from a wheel (`.whl`)

This project publishes installable artifacts in `dist/`:
- a wheel: `dist/*.whl`
- a source archive: `dist/*.tar.gz`

## Install the wheel (recommended: in a virtualenv)

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install dist/*.whl

log-anonymizer --version
log-anonymizer --help
```

## Install with the UI extras

The CLI is dependency-light; the Streamlit UI is optional.

```bash
pip install "dist/*.whl[ui]"
```

Then launch:

```bash
log-anonymizer --help
log-anonymizer-ui
```

## Notes

- If you rebuilt with a different version, replace the filename accordingly (or use `dist/*.whl`).
- If you only installed the core wheel (without `[ui]`), `log-anonymizer-ui` will print an install hint.
- Health check (useful for automation): `log-anonymizer-ui --check`
