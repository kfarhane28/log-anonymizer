# Releasing (deprecated)

Use `docs/RELEASE.md` instead.

This repo ships two distributables:
- Python wheel / sdist in `dist/`
- Docker image (tagged with the project version)

## 1) Versioning

The source of truth is `pyproject.toml` (`[project].version`).

Release checklist:
1. Update `pyproject.toml` version.
2. Add a changelog entry in `CHANGELOG.md`.
3. Tag the commit: `vX.Y.Z` (recommended).

## 2) Build + smoke test (local)

```bash
make clean
make release-build
```

This runs:
- wheel/sdist build
- wheel install smoke test
- docker build + container smoke test

## 3) Publishing (suggested)

### PyPI

Use `twine` from a clean environment:

```bash
python -m pip install -U twine
python -m twine check dist/*
python -m twine upload dist/*
```

### Docker

Tag with the version and push:

```bash
VERSION="$(python -c 'import tomllib;print(tomllib.load(open(\"pyproject.toml\",\"rb\"))[\"project\"][\"version\"])')"
docker build -t log-anonymizer:${VERSION} .
docker push log-anonymizer:${VERSION}
```
