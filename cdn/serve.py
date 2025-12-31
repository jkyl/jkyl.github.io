#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "starlette",
#   "uvicorn",
# ]
# ///
# CDN server with webhook-based auto-deployment
import argparse
import hashlib
import hmac
import os
import secrets
import subprocess
from dataclasses import dataclass

import uvicorn

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.routing import Route

SESSION_SECRET = secrets.token_hex(32)
ALLOWED_ORIGINS = ["https://jkyl.io", "https://audio.jkyl.io"]


# Global config populated by argparse
@dataclass
class Config:
    data_dir: str
    repo_dir: str
    password_hash: str
    webhook_secret: str
    port: int


def create_session_token():
    data = secrets.token_hex(16)
    sig = hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[
        :16
    ]
    return f"{data}.{sig}"


def verify_session_token(token):
    if not token or "." not in token:
        return False
    data, sig = token.rsplit(".", 1)
    expected = hmac.new(
        SESSION_SECRET.encode(), data.encode(), hashlib.sha256
    ).hexdigest()[:16]
    return hmac.compare_digest(sig, expected)


def get_session_token(request: Request) -> str | None:
    return request.cookies.get("session")


async def login_page(request: Request):
    """Serve login.html (no auth required)."""
    return FileResponse(os.path.join(config.repo_dir, "cdn", "login.html"))


async def login(request: Request):
    """Handle login POST."""
    try:
        data = await request.json()
        received_hash = data.get("hash", "")
    except Exception:
        received_hash = ""

    if hmac.compare_digest(received_hash, config.password_hash):
        token = create_session_token()
        response = JSONResponse({"ok": True})
        response.set_cookie(
            "session",
            token,
            path="/",
            httponly=True,
            secure=True,
            samesite="none",
            max_age=31536000,
        )
        return response
    return JSONResponse({"ok": False}, status_code=401)


async def webhook(request: Request):
    """Handle GitHub webhook for auto-deployment."""
    if not config.webhook_secret or not config.repo_dir:
        return Response("Webhook not configured", status_code=500)

    body = await request.body()
    sig_header = request.headers.get("X-Hub-Signature-256", "")

    if not sig_header.startswith("sha256="):
        return Response("Missing signature", status_code=401)

    expected = (
        "sha256="
        + hmac.new(config.webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    )

    if not hmac.compare_digest(sig_header, expected):
        return Response("Invalid signature", status_code=401)

    try:
        # Fetch and reset to handle force pushes
        subprocess.run(
            ["git", "-C", config.repo_dir, "fetch", "origin"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        result = subprocess.run(
            ["git", "-C", config.repo_dir, "reset", "--hard", "origin/main"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return Response(f"Git reset failed: {result.stderr}", status_code=500)

        # Restart via start-cdn.sh (reads fresh config from .env)
        start_script = os.path.join(config.repo_dir, "cdn", "start-cdn.sh")
        subprocess.Popen([start_script], start_new_session=True)
        return Response("OK, restarting...")

    except Exception as e:
        return Response(f"Error: {e}", status_code=500)


async def serve_files(request: Request):
    """Serve files and directory listings (auth required)."""
    path = request.url.path

    # Check authentication
    token = get_session_token(request)
    if not verify_session_token(token):
        if path == "/":
            return FileResponse(os.path.join(config.repo_dir, "cdn", "login.html"))
        return Response("Unauthorized", status_code=401)

    # Security: prevent path traversal
    safe_path = os.path.normpath(path.lstrip("/"))
    if ".." in safe_path:
        return Response("Forbidden", status_code=403)

    full_path = (
        os.path.join(config.data_dir, safe_path) if safe_path else config.data_dir
    )

    # Serve directory listing
    if os.path.isdir(full_path):
        entries = sorted(os.listdir(full_path))
        dirs = [
            e
            for e in entries
            if os.path.isdir(os.path.join(full_path, e)) and not e.startswith(".")
        ]
        files = [
            e
            for e in entries
            if os.path.isfile(os.path.join(full_path, e)) and not e.startswith(".")
        ]
        html = f"<html><body><h1>{path}</h1><ul>"
        for d in dirs:
            html += f'<li><a href="{path.rstrip("/")}/{d}/">{d}/</a></li>'
        for f in files:
            html += f'<li><a href="{path.rstrip("/")}/{f}">{f}</a></li>'
        html += "</ul></body></html>"
        return HTMLResponse(html)

    # Serve file (FileResponse handles range requests automatically)
    if os.path.isfile(full_path):
        return FileResponse(full_path)

    return Response("Not found", status_code=404)


routes = [
    Route("/login.html", login_page, methods=["GET"]),
    Route("/login", login, methods=["POST"]),
    Route("/webhook", webhook, methods=["POST"]),
    Route("/{path:path}", serve_files, methods=["GET"]),
]

middleware = [
    Middleware(
        CORSMiddleware,  # ty:ignore[invalid-argument-type]
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type"],
    ),
]

app = Starlette(routes=routes, middleware=middleware)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CDN server with authentication")
    parser.add_argument(
        "--data-dir", required=True, help="Directory to serve files from"
    )
    parser.add_argument("--repo-dir", required=True, help="Git repository directory")
    parser.add_argument(
        "--password-hash", required=True, help="SHA256 hash of password"
    )
    parser.add_argument("--webhook-secret", default="", help="GitHub webhook secret")
    parser.add_argument("--port", type=int, default=8888, help="Port to listen on")
    args = parser.parse_args()

    # Populate global config
    config = Config(**vars(args))

    print(f"Serving on port {args.port}...")
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning")
