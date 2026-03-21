#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
WITH_UI="${WITH_UI:-0}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "PYTHON_BIN not found: $PYTHON_BIN" >&2
  exit 2
fi

if [ ! -d dist ]; then
  echo "dist/ not found; run: $PYTHON_BIN -m build" >&2
  exit 2
fi

WHEEL_PATH="$(ls -1 dist/*.whl 2>/dev/null | head -n 1 || true)"
if [ -z "$WHEEL_PATH" ]; then
  echo "No wheel found in dist/; build one first." >&2
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

"$PYTHON_BIN" -m venv "$TMP_DIR/venv"

VENV_PY="$TMP_DIR/venv/bin/python"

if [ "$WITH_UI" = "1" ]; then
  "$VENV_PY" -m pip install -U pip >/dev/null
  "$VENV_PY" -m pip install "${WHEEL_PATH}[ui]" >/dev/null
else
  "$VENV_PY" -m pip install "${WHEEL_PATH}" >/dev/null
fi

"$TMP_DIR/venv/bin/log-anonymizer" --help >/dev/null

if [ "$WITH_UI" = "1" ]; then
  "$TMP_DIR/venv/bin/log-anonymizer-ui" --check >/dev/null
else
  # UI should fail fast with a helpful message if UI deps are missing.
  set +e
  "$TMP_DIR/venv/bin/log-anonymizer-ui" --check >/dev/null 2>&1
  RC=$?
  set -e
  if [ "$RC" -eq 0 ]; then
    echo "Expected UI check to fail without UI deps, but it succeeded." >&2
    exit 1
  fi
fi

echo "OK: wheel smoke test passed ($WHEEL_PATH)"

