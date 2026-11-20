#!/bin/sh
set -eu

python -m chaoslab init-db

if [ "${CHAOSLAB_AUTO_SEED_DEMO:-false}" = "true" ]; then
  python -m chaoslab seed-demo
fi

exec uvicorn chaoslab.api.app:get_asgi_app --factory --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips="*"
