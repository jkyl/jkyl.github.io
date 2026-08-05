#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "starlette",
#   "uvicorn",
# ]
# ///
# CDN server with webhook-based auto-deployment
#
# To create the PASSWORD_HASH value for cdn/.env:  ./serve.py hash-password
import argparse
import asyncio
import getpass
import hashlib
import hmac
import html
import ipaddress
import os
import secrets
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import quote

import uvicorn

from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.routing import Route

SESSION_SECRET = secrets.token_hex(32)
ALLOWED_ORIGINS = [
    "https://jkyl.io",
    "https://audio.jkyl.io",
    "http://localhost:8000",
]

# Failed logins allowed per client within the window before /login returns 429
LOGIN_MAX_FAILURES = 10
LOGIN_WINDOW_SECONDS = 300
login_attempts: dict[str, deque[float]] = {}

# scrypt cost for stored password hashes: about 16 MB and tens of ms per check
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
# Cap concurrent checks so a login flood can't exhaust memory or CPU
password_check_slots = asyncio.Semaphore(4)


# Global config populated by argparse
@dataclass
class Config:
    data_dir: str
    repo_dir: str
    password_hash: str
    webhook_secret: str
    host: str
    port: int


def client_key(request: Request) -> str:
    """Identify the client for login throttling."""
    peer = request.client.host if request.client else ""
    ip = peer
    # cloudflared connects over loopback and sets CF-Connecting-IP. Only trust
    # the header from there, since anyone connecting directly can forge it.
    if peer in ("127.0.0.1", "::1"):
        ip = request.headers.get("CF-Connecting-IP", peer)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        # One client typically controls a whole /64
        return str(ipaddress.ip_network((addr, 64), strict=False).network_address)
    return str(addr)


def login_throttled(key: str) -> bool:
    attempts = login_attempts.get(key)
    if not attempts:
        return False
    cutoff = time.monotonic() - LOGIN_WINDOW_SECONDS
    while attempts and attempts[0] < cutoff:
        attempts.popleft()
    if not attempts:
        del login_attempts[key]
        return False
    return len(attempts) >= LOGIN_MAX_FAILURES


def record_login_attempt(key: str) -> None:
    if len(login_attempts) > 10000:  # bound memory under a distributed flood
        login_attempts.clear()
    login_attempts.setdefault(key, deque()).append(time.monotonic())


def make_password_hash(client_hash: str) -> str:
    """Build the PASSWORD_HASH value stored in .env.

    The browser sends SHA-256(password). Storing a salted scrypt of that means
    the stored value can't be replayed as a login or cheaply brute-forced.
    Colon-separated because .env is sourced by bash, where '$' would expand.
    """
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        client_hash.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
    )
    return f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}:{salt.hex()}:{digest.hex()}"


def parse_scrypt_hash(stored: str) -> tuple[int, int, int, bytes, bytes] | None:
    """Parse 'scrypt:n:r:p:salt_hex:hash_hex'; None if malformed."""
    try:
        scheme, n, r, p, salt, digest = stored.split(":")
        parsed = int(n), int(r), int(p), bytes.fromhex(salt), bytes.fromhex(digest)
    except ValueError:
        return None
    return parsed if scheme == "scrypt" and parsed[4] else None


def check_password(received_hash: str, stored: str) -> bool:
    if not stored or len(received_hash) > 128:
        return False
    if not stored.startswith("scrypt:"):
        # Legacy format: the stored value is the bare SHA-256 the browser sends
        return hmac.compare_digest(received_hash.encode(), stored.encode())
    parsed = parse_scrypt_hash(stored)
    if parsed is None:
        return False  # malformed stored hash: fail closed
    n, r, p, salt, expected = parsed
    try:
        actual = hashlib.scrypt(
            received_hash.encode(), salt=salt, n=n, r=r, p=p, dklen=len(expected)
        )
    except (ValueError, OverflowError):
        return False
    return hmac.compare_digest(actual, expected)


def hash_password_cli() -> None:
    """Prompt for a password and print the PASSWORD_HASH line for .env."""
    password = getpass.getpass("Password: ")
    if not password:
        sys.exit("Empty password")
    if getpass.getpass("Again: ") != password:
        sys.exit("Passwords do not match")
    # Same digest the login pages compute in the browser
    client_hash = hashlib.sha256(password.encode()).hexdigest()
    print(f"PASSWORD_HASH={make_password_hash(client_hash)}")


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
    # Compare bytes: compare_digest raises on non-ASCII str input
    return hmac.compare_digest(sig.encode(), expected.encode())


def get_session_token(request: Request) -> str | None:
    return request.cookies.get("session")


async def login_page(request: Request):
    """Serve login.html (no auth required)."""
    return FileResponse(os.path.join(config.repo_dir, "cdn", "login.html"))


async def login(request: Request):
    """Handle login POST."""
    key = client_key(request)
    if login_throttled(key):
        return JSONResponse(
            {"ok": False},
            status_code=429,
            headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)},
        )
    # Count the attempt before checking it, so a burst of parallel requests
    # can't outrun the limit. A successful login clears the count.
    record_login_attempt(key)

    try:
        data = await request.json()
        received_hash = data.get("hash", "")
    except Exception:
        received_hash = ""
    if not isinstance(received_hash, str):
        received_hash = ""

    # scrypt is deliberately slow; keep it off the event loop so streaming
    # to other clients isn't stalled by login attempts
    async with password_check_slots:
        ok = await run_in_threadpool(
            check_password, received_hash, config.password_hash
        )

    if ok:
        login_attempts.pop(key, None)
        token = create_session_token()
        response = JSONResponse({"ok": True})
        # Lax is enough: jkyl.io and audio.jkyl.io are the same site, and it
        # keeps the cookie off requests made by unrelated sites.
        response.set_cookie(
            "session",
            token,
            path="/",
            httponly=True,
            secure=True,
            samesite="lax",
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

        # Exit after the response is sent; launchd (KeepAlive) restarts us with
        # the freshly-pulled code. The tunnel stays up throughout.
        return Response(
            "OK, restarting...", background=BackgroundTask(lambda: os._exit(0))
        )

    except Exception as e:
        return Response(f"Error: {e}", status_code=500)


async def serve_files(request: Request):
    """Serve files and directory listings (auth required)."""
    # The decoded request path as received. request.url.path is re-parsed from
    # a URL string, so it is shaped by the Host header and cut at '?' or '#'.
    path = request.scope["path"]

    # Check authentication
    token = get_session_token(request)
    if not verify_session_token(token):
        if path == "/":
            return FileResponse(os.path.join(config.repo_dir, "cdn", "login.html"))
        return Response("Unauthorized", status_code=401)

    # Security: prevent path traversal, and never serve hidden files
    # (.env, .git, ...) even when requested by exact URL
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if any(p.startswith(".") for p in parts):
        return Response("Forbidden", status_code=403)

    full_path = os.path.join(config.data_dir, *parts)

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
        # Names are escaped as text and percent-encoded in links, so neither
        # the URL nor a filename can inject markup.
        base = "".join("/" + quote(p) for p in parts)
        title = html.escape("/" + "".join(p + "/" for p in parts))
        page = f"<html><body><h1>{title}</h1><ul>"
        for d in dirs:
            page += f'<li><a href="{base}/{quote(d)}/">{html.escape(d)}/</a></li>'
        for f in files:
            page += f'<li><a href="{base}/{quote(f)}">{html.escape(f)}</a></li>'
        page += "</ul></body></html>"
        return HTMLResponse(
            page, headers={"Content-Security-Policy": "default-src 'none'"}
        )

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
    if sys.argv[1:] == ["hash-password"]:
        hash_password_cli()
        sys.exit(0)

    parser = argparse.ArgumentParser(description="CDN server with authentication")
    parser.add_argument(
        "--data-dir", required=True, help="Directory to serve files from"
    )
    parser.add_argument("--repo-dir", required=True, help="Git repository directory")
    parser.add_argument(
        "--password-hash",
        required=True,
        help="Stored password hash (create with: serve.py hash-password)",
    )
    parser.add_argument("--webhook-secret", default="", help="GitHub webhook secret")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Address to listen on (loopback by default; the tunnel connects locally)",
    )
    parser.add_argument("--port", type=int, default=8888, help="Port to listen on")
    args = parser.parse_args()

    # Populate global config
    config = Config(**vars(args))

    # Report a weak or broken PASSWORD_HASH but keep serving either way, so the
    # deploy webhook stays reachable and the fix can be made in .env.
    if not config.password_hash.startswith("scrypt:"):
        print(
            "NOTE: PASSWORD_HASH is a bare SHA-256, which works as a login by "
            "itself if it leaks. Replace it with the output of: serve.py hash-password",
            flush=True,
        )
    elif parse_scrypt_hash(config.password_hash) is None:
        print("ERROR: PASSWORD_HASH is malformed; all logins will fail", flush=True)

    print(f"Serving on {args.host}:{args.port}...")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
