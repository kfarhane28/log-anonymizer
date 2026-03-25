# Release (admins)

This repo ships two distributables:
- Python wheel / sdist in `dist/`
- Docker image (tagged with the project version)

## Versioning

Source of truth: `pyproject.toml` (`[project].version`).

Typical release steps:
1. Update `pyproject.toml` version.
2. Add a changelog entry in `CHANGELOG.md`.
3. Tag the commit (recommended): `vX.Y.Z`.

## Local build + validation

```bash
make release-build
```

This runs:
- wheel/sdist build (`make build`)
- wheel install smoke test (`scripts/smoke_test_wheel.sh`)
- docker build + container smoke test (`scripts/smoke_test_docker.sh`)

## Publishing (suggested)

### PyPI

```bash
python -m pip install -U twine
python -m twine check dist/*
python -m twine upload dist/*
```

### Docker registry

```bash
VERSION="$(python -c 'import tomllib;print(tomllib.load(open(\"pyproject.toml\",\"rb\"))[\"project\"][\"version\"])')"
docker build -t log-anonymizer:${VERSION} .
docker push log-anonymizer:${VERSION}
```

