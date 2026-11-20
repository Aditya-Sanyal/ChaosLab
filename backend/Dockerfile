FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp

WORKDIR /app

RUN groupadd --gid 10001 chaoslab \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /tmp/chaoslab chaoslab

COPY pyproject.toml ./
COPY chaoslab ./chaoslab
RUN pip install --no-cache-dir ".[postgres]" && rm -rf /app/chaoslab

COPY alembic.ini ./
COPY alembic ./alembic
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

RUN sed -i 's/\r$//' /app/docker-entrypoint.sh \
    && chmod +x /app/docker-entrypoint.sh \
    && mkdir -p /app/data \
    && chown -R chaoslab:chaoslab /app

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health/ready', timeout=3)"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
