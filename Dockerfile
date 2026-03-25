FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY log-anonymizer.ini ./
COPY assets ./assets
COPY examples ./examples
COPY src ./src

RUN python -m pip install --upgrade pip && \
    python -m pip install --upgrade build setuptools wheel && \
    python -m build --no-isolation --wheel


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_HEADLESS=true

WORKDIR /app

# Non-root user (override with `--user` if you need host volume permissions).
RUN addgroup --system --gid 10001 app && \
    adduser --system --uid 10001 --ingroup app --home /nonexistent --shell /usr/sbin/nologin app

COPY --from=builder /build/dist/*.whl /tmp/

# Build arg allows a smaller CLI-only image.
ARG WITH_UI=1
RUN python -m pip install --upgrade pip && \
    WHEEL_PATH="$(ls -1 /tmp/*.whl | head -n 1)" && \
    if [ -z "$WHEEL_PATH" ]; then echo "No wheel found in /tmp"; exit 2; fi && \
    python -m pip install "$WHEEL_PATH" && \
    if [ "$WITH_UI" = "1" ]; then \
        python -m pip install "streamlit>=1.30.0" "pandas>=2.0.0" ; \
    fi && \
    rm -f /tmp/*.whl

USER app

EXPOSE 8501

# Default shows CLI help; override in `docker run` to use CLI/UI.
CMD ["log-anonymizer", "--help"]
