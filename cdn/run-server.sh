#!/bin/bash
# Foreground CDN server entrypoint for launchd. Reads config from .env.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$SCRIPT_DIR/.env"

# launchd provides a minimal PATH; serve.py's shebang needs uv
export PATH="$HOME/.local/bin:/opt/homebrew/bin:$PATH"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found"
  exit 1
fi

source "$ENV_FILE"

for var in PASSWORD_HASH DATA_DIR; do
  if [ -z "${!var}" ]; then
    echo "ERROR: $var not set in $ENV_FILE"
    exit 1
  fi
done

ARGS=(
  --data-dir "$DATA_DIR"
  --repo-dir "$REPO_DIR"
  --password-hash "$PASSWORD_HASH"
)
if [ -n "$WEBHOOK_SECRET" ]; then
  ARGS+=(--webhook-secret "$WEBHOOK_SECRET")
fi

exec "$SCRIPT_DIR/serve.py" "${ARGS[@]}"
