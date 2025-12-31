#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$SCRIPT_DIR/.env"
SERVER_PID_FILE="/tmp/audio-server.pid"
TUNNEL_PID_FILE="/tmp/cloudflared.pid"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found"
  exit 1
fi

# Source env file to get variables
source "$ENV_FILE"

# Validate required vars
for var in PASSWORD_HASH DATA_DIR; do
  if [ -z "${!var}" ]; then
    echo "ERROR: $var not set in $ENV_FILE"
    exit 1
  fi
done

# Kill existing server by PID
if [ -f "$SERVER_PID_FILE" ]; then
  OLD_PID=$(cat "$SERVER_PID_FILE")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo "Stopping existing server (pid: $OLD_PID)"
    kill "$OLD_PID"
    sleep 1
  fi
  rm -f "$SERVER_PID_FILE"
fi

# Kill existing tunnel by PID
if [ -f "$TUNNEL_PID_FILE" ]; then
  OLD_PID=$(cat "$TUNNEL_PID_FILE")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo "Stopping existing tunnel (pid: $OLD_PID)"
    kill "$OLD_PID"
    sleep 1
  fi
  rm -f "$TUNNEL_PID_FILE"
fi

# Build server arguments
SERVER_ARGS=(
  --data-dir "$DATA_DIR"
  --repo-dir "$REPO_DIR"
  --password-hash "$PASSWORD_HASH"
)
if [ -n "$WEBHOOK_SECRET" ]; then
  SERVER_ARGS+=(--webhook-secret "$WEBHOOK_SECRET")
fi

# Start file server
nohup "$REPO_DIR/cdn/serve.py" "${SERVER_ARGS[@]}" > /tmp/audio-server.log 2>&1 &
echo "$!" > "$SERVER_PID_FILE"
echo "File server started (pid: $!)"

# Start tunnel
nohup /opt/homebrew/bin/cloudflared tunnel run audio > /tmp/cloudflared.log 2>&1 &
echo "$!" > "$TUNNEL_PID_FILE"
echo "Cloudflared started (pid: $!)"

sleep 2

# Verify
curl -sf https://audio.jkyl.io/login -X OPTIONS > /dev/null && echo "CDN is live at https://audio.jkyl.io/" || echo "Warning: CDN not responding yet"
