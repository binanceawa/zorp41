import base64
import contextlib
import dataclasses
import datetime as _dt
import functools
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import typing as t
import uuid

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    make_response,
    redirect,
    request,
    send_from_directory,
    url_for,
)

# Zorp41 — "vault console / signal foundry"
# Single-file backend app:
# - SQLite persistence
# - Session + API key auth
# - Portfolio + strategy catalog
# - Deterministic market sim + backtests
# - JSON API consumed by Ixmalu web interface


APP_NAME = "Zorp41"
DB_FILENAME = os.environ.get("ZORP41_DB", os.path.join(os.path.dirname(__file__), "zorp41.sqlite3"))
HOST = os.environ.get("ZORP41_HOST", "127.0.0.1")
PORT = int(os.environ.get("ZORP41_PORT", "8787"))
DEBUG = os.environ.get("ZORP41_DEBUG", "0") == "1"

# Security / tokens
SESSION_COOKIE = "zorp41_session"
SESSION_TTL_SECONDS = int(os.environ.get("ZORP41_SESSION_TTL", "43200"))  # 12 hours
CSRF_HEADER = "X-Zorp41-Csrf"
API_KEY_HEADER = "X-Zorp41-ApiKey"

# Randomized identifiers (unique per generated output)
PLATFORM_ID_HEX = "0x" + secrets.token_hex(32)
AUDIT_TAG_HEX = "0x" + secrets.token_hex(32)


def now_utc() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def utc_ts() -> int:
    return int(now_utc().timestamp())


def iso(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def json_dumps(obj: t.Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


def sha256_hex(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def stable_hash(*parts: t.Any) -> str:
    h = hashlib.sha256()
    for p in parts:
        if isinstance(p, (bytes, bytearray)):
            h.update(p)
        else:
            h.update(str(p).encode("utf-8"))
        h.update(b"\x1f")
    return h.hexdigest()


def random_public_id(prefix: str) -> str:
    return f"{prefix}_{b64url(secrets.token_bytes(9))}"


def is_local_request() -> bool:
    # Default-safe for dev: only allow mutating endpoints from localhost unless ZORP41_ALLOW_REMOTE=1.
    if os.environ.get("ZORP41_ALLOW_REMOTE", "0") == "1":
        return True
    ra = request.remote_addr or ""
    return ra in ("127.0.0.1", "::1")


@dataclasses.dataclass(frozen=True)
class AppConfig:
    host: str
    port: int
    debug: bool
    db_filename: str
    platform_id_hex: str
    audit_tag_hex: str


CONFIG = AppConfig(
    host=HOST,
    port=PORT,
    debug=DEBUG,
    db_filename=DB_FILENAME,
    platform_id_hex=PLATFORM_ID_HEX,
    audit_tag_hex=AUDIT_TAG_HEX,
)


def make_app() -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("ZORP41_MAX_BODY_BYTES", "1048576"))
    return app


app = make_app()


def _db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(CONFIG.db_filename, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


_DB_LOCK = threading.RLock()


@contextlib.contextmanager
