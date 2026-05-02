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
def db() -> t.Iterator[sqlite3.Connection]:
    with _DB_LOCK:
        conn = _db_connect()
        try:
            yield conn
        finally:
            conn.close()


def db_exec(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> sqlite3.Cursor:
    return conn.execute(sql, params)


def db_many(conn: sqlite3.Connection, sql: str, rows: list[tuple]) -> None:
    conn.executemany(sql, rows)


def row_to_dict(r: sqlite3.Row) -> dict[str, t.Any]:
    return {k: r[k] for k in r.keys()}


def ensure_schema() -> None:
    schema = [
        """
        CREATE TABLE IF NOT EXISTS meta (
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            last_login_at INTEGER
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            csrf_token TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            user_agent TEXT,
            ip TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            label TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            revoked_at INTEGER,
            last_used_at INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS vaults (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            chain TEXT NOT NULL,
            asset_symbol TEXT NOT NULL,
            asset_decimals INTEGER NOT NULL,
            address TEXT,
            created_at INTEGER NOT NULL,
            status TEXT NOT NULL,
            deposit_cap REAL NOT NULL,
            mgmt_fee_bps_per_year INTEGER NOT NULL,
            perf_fee_bps INTEGER NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS strategies (
            id TEXT PRIMARY KEY,
            vault_id TEXT NOT NULL,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            risk_grade TEXT NOT NULL,
            target_weight REAL NOT NULL,
            max_debt REAL NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            params_json TEXT NOT NULL,
            FOREIGN KEY(vault_id) REFERENCES vaults(id) ON DELETE CASCADE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS prices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            symbol TEXT NOT NULL,
            ts INTEGER NOT NULL,
            px REAL NOT NULL,
            source TEXT NOT NULL,
            UNIQUE(symbol, ts)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS signals (
            id TEXT PRIMARY KEY,
            vault_id TEXT NOT NULL,
            ts INTEGER NOT NULL,
            horizon TEXT NOT NULL,
            score REAL NOT NULL,
            rationale TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            FOREIGN KEY(vault_id) REFERENCES vaults(id) ON DELETE CASCADE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS portfolios (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            label TEXT NOT NULL,
            base_currency TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS portfolio_positions (
            id TEXT PRIMARY KEY,
            portfolio_id TEXT NOT NULL,
            symbol TEXT NOT NULL,
            qty REAL NOT NULL,
            cost_basis REAL NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(portfolio_id, symbol),
            FOREIGN KEY(portfolio_id) REFERENCES portfolios(id) ON DELETE CASCADE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            ts INTEGER NOT NULL,
            actor_user_id TEXT,
            action TEXT NOT NULL,
            details_json TEXT NOT NULL,
            ip TEXT,
            user_agent TEXT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            started_at INTEGER,
            finished_at INTEGER,
            last_heartbeat_at INTEGER,
            progress REAL NOT NULL DEFAULT 0,
            result_json TEXT,
            error TEXT
        );
        """,
    ]
    with db() as conn:
        for stmt in schema:
            conn.execute(stmt)
        # Seed meta if missing.
        conn.execute("INSERT OR IGNORE INTO meta(k, v) VALUES(?, ?)", ("platform_id", CONFIG.platform_id_hex))
        conn.execute("INSERT OR IGNORE INTO meta(k, v) VALUES(?, ?)", ("audit_tag", CONFIG.audit_tag_hex))
        conn.execute("INSERT OR IGNORE INTO meta(k, v) VALUES(?, ?)", ("schema_version", "7"))


def pbkdf2_hash(password: str, salt: str, rounds: int = 200_000) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), rounds, dklen=32)
    return f"pbkdf2_sha256${rounds}${salt}${base64.b64encode(dk).decode('ascii')}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds_s, salt, b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        rounds = int(rounds_s)
        check = pbkdf2_hash(password, salt, rounds=rounds)
        return hmac.compare_digest(check, stored)
    except Exception:
        return False


def audit(action: str, actor_user_id: str | None, details: dict[str, t.Any]) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit_log(id, ts, actor_user_id, action, details_json, ip, user_agent) VALUES(?,?,?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                utc_ts(),
                actor_user_id,
                action,
                json_dumps(details),
                request.remote_addr,
                request.headers.get("User-Agent"),
            ),
        )


def require_local_write() -> None:
