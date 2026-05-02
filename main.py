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
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and not is_local_request():
        abort(make_response(jsonify({"ok": False, "error": "remote_write_disabled"}), 403))


@app.before_request
def _guard_writes():
    require_local_write()


def get_cookie(name: str) -> str | None:
    return request.cookies.get(name)


def set_cookie(resp: Response, name: str, value: str, ttl: int) -> None:
    expires = _dt.datetime.utcfromtimestamp(utc_ts() + ttl)
    resp.set_cookie(
        name,
        value,
        expires=expires,
        httponly=True,
        secure=False if CONFIG.debug else False,
        samesite="Lax",
        path="/",
    )


def clear_cookie(resp: Response, name: str) -> None:
    resp.set_cookie(name, "", expires=0, httponly=True, samesite="Lax", path="/")


def session_load(session_id: str) -> dict[str, t.Any] | None:
    with db() as conn:
        r = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not r:
            return None
        if int(r["expires_at"]) <= utc_ts():
            conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            return None
        return row_to_dict(r)


def session_touch(session_id: str) -> None:
    with db() as conn:
        conn.execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (utc_ts(), session_id))


def session_create(user_id: str) -> dict[str, str]:
    sid = random_public_id("sess")
    csrf = b64url(secrets.token_bytes(18))
    created = utc_ts()
    exp = created + SESSION_TTL_SECONDS
    with db() as conn:
        conn.execute(
            "INSERT INTO sessions(id, user_id, csrf_token, created_at, expires_at, last_seen_at, user_agent, ip) VALUES(?,?,?,?,?,?,?,?)",
            (
                sid,
                user_id,
                csrf,
                created,
                exp,
                created,
                request.headers.get("User-Agent"),
                request.remote_addr,
            ),
        )
    return {"session_id": sid, "csrf": csrf}


def session_destroy(session_id: str) -> None:
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))


def require_csrf(sess: dict[str, t.Any]) -> None:
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        got = request.headers.get(CSRF_HEADER, "")
        if not got or not hmac.compare_digest(got, str(sess["csrf_token"])):
            abort(make_response(jsonify({"ok": False, "error": "csrf"}), 403))


def api_key_hash(key: str) -> str:
    return sha256_hex(("zorp41:" + key).encode("utf-8"))


def api_key_validate(key: str) -> dict[str, t.Any] | None:
    h = api_key_hash(key)
    with db() as conn:
        r = conn.execute(
            "SELECT api_keys.*, users.email, users.is_admin FROM api_keys JOIN users ON users.id = api_keys.user_id "
            "WHERE api_keys.key_hash = ? AND api_keys.revoked_at IS NULL",
            (h,),
        ).fetchone()
        if not r:
            return None
        conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (utc_ts(), r["id"]))
        return row_to_dict(r)


def auth_context() -> dict[str, t.Any] | None:
    # Priority: API key (for programmatic use) then browser session.
    api_key = request.headers.get(API_KEY_HEADER)
    if api_key:
        ak = api_key_validate(api_key)
        if ak:
            return {"kind": "api_key", "user_id": ak["user_id"], "email": ak["email"], "is_admin": bool(ak["is_admin"])}
        return None
    sid = get_cookie(SESSION_COOKIE)
    if not sid:
        return None
    sess = session_load(sid)
    if not sess:
        return None
    session_touch(sid)
    with db() as conn:
        u = conn.execute("SELECT id, email, is_admin FROM users WHERE id = ?", (sess["user_id"],)).fetchone()
        if not u:
            return None
        return {
            "kind": "session",
            "session_id": sid,
            "csrf": sess["csrf_token"],
            "user_id": u["id"],
            "email": u["email"],
            "is_admin": bool(u["is_admin"]),
        }


def require_auth() -> dict[str, t.Any]:
    ctx = auth_context()
    if not ctx:
        abort(make_response(jsonify({"ok": False, "error": "auth"}), 401))
    return ctx


def require_admin() -> dict[str, t.Any]:
    ctx = require_auth()
    if not ctx.get("is_admin"):
        abort(make_response(jsonify({"ok": False, "error": "admin"}), 403))
    return ctx


def require_mutation(ctx: dict[str, t.Any]) -> None:
    if ctx.get("kind") == "session":
        with db() as conn:
            r = conn.execute("SELECT csrf_token FROM sessions WHERE id = ?", (ctx["session_id"],)).fetchone()
            if not r:
                abort(make_response(jsonify({"ok": False, "error": "auth"}), 401))
            sess = {"csrf_token": r["csrf_token"]}
        require_csrf(sess)


def api_ok(data: t.Any = None, **extra) -> Response:
    body = {"ok": True, "data": data}
    body.update(extra)
    return jsonify(body)


def api_err(code: str, status: int = 400, **extra) -> Response:
    body = {"ok": False, "error": code}
    body.update(extra)
    return make_response(jsonify(body), status)


def parse_json(required: bool = True) -> dict[str, t.Any]:
    if not request.data:
        if required:
            abort(make_response(jsonify({"ok": False, "error": "json_required"}), 400))
        return {}
    try:
        j = request.get_json(force=True, silent=False)
        if not isinstance(j, dict):
            abort(make_response(jsonify({"ok": False, "error": "json_object_required"}), 400))
        return t.cast(dict[str, t.Any], j)
    except Exception:
        abort(make_response(jsonify({"ok": False, "error": "json_parse"}), 400))


def get_meta(k: str) -> str | None:
    with db() as conn:
        r = conn.execute("SELECT v FROM meta WHERE k = ?", (k,)).fetchone()
        return str(r["v"]) if r else None


def set_meta(k: str, v: str) -> None:
    with db() as conn:
        conn.execute("INSERT INTO meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, v))


def seed_admin_if_needed() -> None:
    # If no users exist, create a randomized admin user with printed credentials.
    with db() as conn:
        r = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        if r and int(r["n"]) > 0:
            return
        email = os.environ.get("ZORP41_BOOTSTRAP_EMAIL", "admin@zorp41.local")
        password = os.environ.get("ZORP41_BOOTSTRAP_PASSWORD") or b64url(secrets.token_bytes(12))
        salt = b64url(secrets.token_bytes(16))
        ph = pbkdf2_hash(password, salt)
        user_id = random_public_id("usr")
        conn.execute(
            "INSERT INTO users(id, email, password_hash, salt, is_admin, created_at) VALUES(?,?,?,?,?,?)",
            (user_id, email, ph, salt, 1, utc_ts()),
        )
        # Create a default portfolio.
        pid = random_public_id("pf")
        conn.execute(
            "INSERT INTO portfolios(id, user_id, label, base_currency, created_at) VALUES(?,?,?,?,?)",
            (pid, user_id, "Primary", "USD", utc_ts()),
        )
        set_meta("bootstrap_email", email)
        set_meta("bootstrap_password", password)


def seed_demo_vault_if_needed() -> None:
    with db() as conn:
        r = conn.execute("SELECT COUNT(*) AS n FROM vaults").fetchone()
        if r and int(r["n"]) > 0:
            return
        vid = random_public_id("vlt")
        conn.execute(
            "INSERT INTO vaults(id, name, chain, asset_symbol, asset_decimals, address, created_at, status, deposit_cap, mgmt_fee_bps_per_year, perf_fee_bps) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                vid,
                "Nimbrex Gate Vault",
                "EVM-mainnet",
                "USDC",
                6,
                None,
                utc_ts(),
                "draft",
                25_000_000.0,
                175,
                900,
            ),
        )
        base_params = {"notes": "seeded", "rebalance_window_sec": 21600, "oracle_mode": "sim"}
        strat_rows = [
            (random_public_id("st"), vid, "Delta Carry", "carry", "B", 0.35, 12_000_000.0, 1, utc_ts(), json_dumps({**base_params, "leverage": 1.6})),
            (random_public_id("st"), vid, "Range Maker", "market_making", "C", 0.25, 8_000_000.0, 1, utc_ts(), json_dumps({**base_params, "bands": 5})),
            (random_public_id("st"), vid, "Trend Pulse", "momentum", "B", 0.25, 9_000_000.0, 1, utc_ts(), json_dumps({**base_params, "lookback_days": 28})),
            (random_public_id("st"), vid, "Stable Yield", "lending", "A", 0.15, 6_000_000.0, 1, utc_ts(), json_dumps({**base_params, "utilization_cap": 0.82})),
        ]
        conn.executemany(
            "INSERT INTO strategies(id, vault_id, name, kind, risk_grade, target_weight, max_debt, enabled, created_at, params_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            strat_rows,
        )


# -----------------------------
# Market simulation + pricing
# -----------------------------

@dataclasses.dataclass
class PricePoint:
    symbol: str
    ts: int
    px: float
    source: str


class DeterministicMarket:
    """
    Deterministic pseudo-market to keep the app functional without external APIs.
    Produces smooth-ish price series per symbol using hashed seeds.
    """

    def __init__(self, seed_tag: str):
        self.seed_tag = seed_tag

    def _seed(self, symbol: str) -> int:
        h = stable_hash("market", self.seed_tag, symbol)
        return int(h[:16], 16)

    def px_at(self, symbol: str, ts: int) -> float:
        base = 1.0
        if symbol.upper() in ("USDC", "USDT", "DAI"):
            base = 1.0
        elif symbol.upper() in ("ETH", "WETH"):
            base = 3200.0
        elif symbol.upper() in ("BTC", "WBTC"):
            base = 68000.0
        else:
            base = 12.0 + (self._seed(symbol) % 3000) / 100.0

        s = self._seed(symbol)
        # Multi-frequency waves + gentle drift; deterministic from seed and time.
        t0 = ts / 3600.0
        w1 = (s % 997) / 997.0
        w2 = ((s >> 10) % 991) / 991.0
        w3 = ((s >> 20) % 983) / 983.0
        # Use bounded oscillation and trend.
        osc = (
            0.020 * _sin(0.19 * t0 + 6.1 * w1)
            + 0.013 * _sin(0.053 * t0 + 11.2 * w2)
            + 0.009 * _sin(0.011 * t0 + 19.7 * w3)
        )
        drift = 0.000004 * (t0 - 1000.0) * (0.6 + 0.4 * (w1))
        shock = 0.0
        if symbol.upper() not in ("USDC", "USDT", "DAI"):
            shock = 0.006 * _sin(0.67 * t0 + 3.2 * w2) * _sin(0.041 * t0 + 8.8 * w3)
        px = base * (1.0 + osc + drift + shock)
        if symbol.upper() in ("USDC", "USDT", "DAI"):
            px = clamp(px, 0.992, 1.008)
        else:
            px = max(0.05, px)
        return float(px)


def _sin(x: float) -> float:
    # Quick sine approximation (enough for deterministic visuals).
    # Range reduction:
    pi = 3.141592653589793
    x = x % (2 * pi)
    if x > pi:
        x -= 2 * pi
    # 7th order taylor-like approx
    x2 = x * x
    return x * (1 - x2 / 6 + x2 * x2 / 120 - x2 * x2 * x2 / 5040)


MARKET = DeterministicMarket(seed_tag=CONFIG.platform_id_hex)


def price_upsert(symbol: str, ts: int, px: float, source: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO prices(symbol, ts, px, source) VALUES(?,?,?,?) ON CONFLICT(symbol, ts) DO UPDATE SET px = excluded.px, source = excluded.source",
            (symbol.upper(), int(ts), float(px), source),
        )


def price_latest(symbol: str) -> PricePoint | None:
    with db() as conn:
        r = conn.execute("SELECT symbol, ts, px, source FROM prices WHERE symbol = ? ORDER BY ts DESC LIMIT 1", (symbol.upper(),)).fetchone()
        if not r:
            return None
        return PricePoint(symbol=r["symbol"], ts=int(r["ts"]), px=float(r["px"]), source=r["source"])


def price_series(symbol: str, start_ts: int, end_ts: int, step_sec: int) -> list[PricePoint]:
    symbol = symbol.upper()
    out: list[PricePoint] = []
    with db() as conn:
        rows = conn.execute(
            "SELECT symbol, ts, px, source FROM prices WHERE symbol = ? AND ts BETWEEN ? AND ? ORDER BY ts ASC",
            (symbol, start_ts, end_ts),
        ).fetchall()
    have = {int(r["ts"]): float(r["px"]) for r in rows}
    ts = start_ts
    while ts <= end_ts:
        px = have.get(ts)
        if px is None:
            px = MARKET.px_at(symbol, ts)
            price_upsert(symbol, ts, px, "sim")
        out.append(PricePoint(symbol=symbol, ts=ts, px=float(px), source="sim" if ts not in have else "db"))
        ts += step_sec
    return out


# -----------------------------
# Risk + allocation engine
# -----------------------------
