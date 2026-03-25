#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

IMAGE_TAG="${IMAGE_TAG:-log-anonymizer:smoke}"
WITH_UI="${WITH_UI:-1}"

docker build --build-arg "WITH_UI=${WITH_UI}" -t "${IMAGE_TAG}" .

docker run --rm "${IMAGE_TAG}" log-anonymizer --help >/dev/null

if [ "${WITH_UI}" = "1" ]; then
  docker run --rm "${IMAGE_TAG}" log-anonymizer-ui --check >/dev/null
fi

echo "OK: docker smoke test passed (${IMAGE_TAG})"

