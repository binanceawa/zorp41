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

@dataclasses.dataclass
class StrategyModel:
    id: str
    vault_id: str
    name: str
    kind: str
    risk_grade: str
    target_weight: float
    max_debt: float
    enabled: bool
    params: dict[str, t.Any]


RISK_GRADE_TO_VOL = {"A": 0.08, "B": 0.14, "C": 0.22, "D": 0.35}


def parse_strategy_row(r: sqlite3.Row) -> StrategyModel:
    return StrategyModel(
        id=str(r["id"]),
        vault_id=str(r["vault_id"]),
        name=str(r["name"]),
        kind=str(r["kind"]),
        risk_grade=str(r["risk_grade"]),
        target_weight=float(r["target_weight"]),
        max_debt=float(r["max_debt"]),
        enabled=bool(r["enabled"]),
        params=json.loads(str(r["params_json"] or "{}")),
    )


def vault_get(vault_id: str) -> dict[str, t.Any] | None:
    with db() as conn:
        r = conn.execute("SELECT * FROM vaults WHERE id = ?", (vault_id,)).fetchone()
        return row_to_dict(r) if r else None


def vault_strategies(vault_id: str) -> list[StrategyModel]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM strategies WHERE vault_id = ? ORDER BY created_at ASC", (vault_id,)).fetchall()
        return [parse_strategy_row(r) for r in rows]


def normalize_weights(strats: list[StrategyModel]) -> dict[str, float]:
    enabled = [s for s in strats if s.enabled and s.target_weight > 0]
    total = sum(s.target_weight for s in enabled)
    if total <= 0:
        return {s.id: 0.0 for s in strats}
    return {s.id: (s.target_weight / total) for s in strats}


def risk_budget_for_vault(vault: dict[str, t.Any]) -> float:
    # Convert fees + cap into a simple "risk appetite" scalar.
    cap = float(vault.get("deposit_cap") or 1.0)
    mgmt = float(vault.get("mgmt_fee_bps_per_year") or 0) / 10_000.0
    perf = float(vault.get("perf_fee_bps") or 0) / 10_000.0
    # Higher fees -> allow slightly higher risk (pretend more budget for ops).
    k_fee = 1.0 + 0.65 * mgmt + 0.35 * perf
    k_cap = clamp((cap / 25_000_000.0) ** 0.05, 0.92, 1.08)
    return float(k_fee * k_cap)


def strategy_expected_return(kind: str, horizon: str) -> float:
    kind = kind.lower().strip()
    if horizon == "1d":
        scale = 1.0
    elif horizon == "7d":
        scale = 1.7
    elif horizon == "30d":
        scale = 2.8
    else:
        scale = 2.0
    base = {
        "lending": 0.06,
        "carry": 0.10,
        "market_making": 0.12,
        "momentum": 0.16,
        "mean_reversion": 0.13,
        "arb": 0.09,
    }.get(kind, 0.11)
    return base * scale


def strategy_volatility(grade: str) -> float:
    return float(RISK_GRADE_TO_VOL.get(grade.upper().strip(), 0.18))


def allocation_recommendation(vault: dict[str, t.Any], strats: list[StrategyModel], horizon: str) -> dict[str, t.Any]:
    # Build a normalized weight suggestion with risk adjustment.
    weights = normalize_weights(strats)
    budget = risk_budget_for_vault(vault)

    scored: list[tuple[StrategyModel, float, float]] = []
    for s in strats:
        if not s.enabled:
            continue
        w = float(weights.get(s.id, 0.0))
        if w <= 0:
            continue
        exp = strategy_expected_return(s.kind, horizon)
        vol = strategy_volatility(s.risk_grade)
        # Sharpe-ish score; risk budget influences vol penalty.
        score = (exp / max(0.01, vol)) * (budget / (1.0 + 2.2 * vol))
        scored.append((s, score, w))

    if not scored:
        return {"horizon": horizon, "weights": {}, "notes": "no_enabled_strategies"}

    # Softmax-like normalization for scores.
    max_score = max(sc for _, sc, _ in scored)
    raw = []
    for s, sc, w in scored:
        x = (sc - max_score)
        # exp approximation for stability
        e = 1.0 + x + (x * x) / 2.0 if x > -1.5 else 0.08
        raw.append((s, max(0.0001, e) * w))

    total = sum(v for _, v in raw)
    weights_out = {s.id: float(v / total) for s, v in raw}

    # Debt caps & max_debt constraints in USD terms.
    cap = float(vault.get("deposit_cap") or 0.0)
    alloc = []
    for s in strats:
        if not s.enabled:
            continue
        w = float(weights_out.get(s.id, 0.0))
        alloc_usd = cap * w
        alloc_usd = min(alloc_usd, float(s.max_debt))
        alloc.append(
            {
                "strategy_id": s.id,
                "name": s.name,
                "kind": s.kind,
                "risk_grade": s.risk_grade,
                "weight": w,
                "max_debt": float(s.max_debt),
                "recommended_debt": float(alloc_usd),
            }
        )

    # Normalize after caps
    total_after = sum(x["recommended_debt"] for x in alloc) or 1.0
    for x in alloc:
        x["weight_capped"] = float(x["recommended_debt"] / total_after)

    return {"horizon": horizon, "risk_budget": budget, "allocations": alloc}


def signal_for_vault(vault: dict[str, t.Any], horizon: str) -> dict[str, t.Any]:
    # Derive signal from market proxy (ETH) and risk appetite. Deterministic but feels "AI-ish".
    px = MARKET.px_at("ETH", utc_ts())
    cap = float(vault.get("deposit_cap") or 1.0)
    fee_drag = (float(vault.get("mgmt_fee_bps_per_year") or 0) / 10_000.0) * 0.55
    appetite = clamp((cap / 25_000_000.0) ** 0.09, 0.9, 1.1) * (1.0 - fee_drag)
    # Score 0..1
    p = clamp((px - 2800.0) / 1600.0, -1.0, 1.0)
    h = {"1d": 0.7, "7d": 0.85, "30d": 1.0}.get(horizon, 0.9)
    score = clamp(0.52 + 0.23 * p * h * appetite, 0.02, 0.98)
    rationale = (
        f"Market proxy ETH={px:,.2f}. Appetite={appetite:.3f}. "
        f"Horizon={horizon}. Score blends proxy momentum and fee-adjusted capacity."
    )
    payload = {"proxy": {"symbol": "ETH", "px": px}, "appetite": appetite, "horizon": horizon}
    return {"horizon": horizon, "score": score, "rationale": rationale, "payload": payload}


# -----------------------------
# Backtesting
# -----------------------------

@dataclasses.dataclass
class BacktestParams:
    symbol: str
    start_ts: int
    end_ts: int
    step_sec: int
    fee_bps: float
    slippage_bps: float
    strategy: str


def backtest_run(p: BacktestParams) -> dict[str, t.Any]:
    series = price_series(p.symbol, p.start_ts, p.end_ts, p.step_sec)
    if len(series) < 3:
        return {"ok": False, "error": "insufficient_series"}

    # Toy strategies; deterministic & fast.
    cash = 1.0
    pos = 0.0
    equity_curve = []
    trades = []

    def equity(px: float) -> float:
        return cash + pos * px

    last_px = series[0].px
    ma_fast = last_px
    ma_slow = last_px

    for i, pt in enumerate(series):
        px = pt.px
        ma_fast = 0.88 * ma_fast + 0.12 * px
        ma_slow = 0.96 * ma_slow + 0.04 * px
        edge = ma_fast - ma_slow

        # Signal: momentum / mean reversion / carry proxy
        want = 0.0
        if p.strategy == "momentum":
            want = 1.0 if edge > 0 else 0.0
        elif p.strategy == "mean_reversion":
            want = 1.0 if (px < ma_slow * 0.992) else 0.0
        elif p.strategy == "carry":
            # Always hold small risk-on.
            want = 0.35 + 0.15 * (1.0 if edge > 0 else -1.0)
            want = clamp(want, 0.0, 1.0)
        else:
            want = 0.5 + 0.2 * (1.0 if edge > 0 else -1.0)
            want = clamp(want, 0.0, 1.0)

        eq = equity(px)
        target_pos_value = eq * want
        target_pos = target_pos_value / px if px > 0 else 0.0

        # Trade if gap meaningful
        if abs(target_pos - pos) > 0.0001:
            delta = target_pos - pos
            notional = abs(delta) * px
            fee = notional * (p.fee_bps / 10_000.0)
            slip = notional * (p.slippage_bps / 10_000.0)
            cost = fee + slip
            # Execute: buy/sell
            if delta > 0:
                # buy
                spend = delta * px + cost
                if spend > cash:
                    # scale down
                    delta = max(0.0, (cash - cost) / px)
                    spend = delta * px + cost
                cash -= spend
                pos += delta
            else:
                # sell
                sell_qty = min(pos, -delta)
                proceeds = sell_qty * px - cost
                pos -= sell_qty
                cash += proceeds
            trades.append({"ts": pt.ts, "px": px, "delta": delta, "fee": fee, "slip": slip})

        equity_curve.append({"ts": pt.ts, "equity": equity(px), "px": px, "ma_fast": ma_fast, "ma_slow": ma_slow})
        last_px = px

    eq0 = equity_curve[0]["equity"]
    eqN = equity_curve[-1]["equity"]
    ret = (eqN / eq0) - 1.0 if eq0 else 0.0
    # Drawdown
    peak = -1e18
    max_dd = 0.0
    for x in equity_curve:
        e = float(x["equity"])
        if e > peak:
            peak = e
        dd = (peak - e) / peak if peak > 0 else 0.0
        max_dd = max(max_dd, dd)

    return {
        "ok": True,
        "params": dataclasses.asdict(p),
        "summary": {
            "equity_start": float(eq0),
            "equity_end": float(eqN),
            "return": float(ret),
            "max_drawdown": float(max_dd),
            "trades": int(len(trades)),
        },
        "equity_curve": equity_curve,
        "trades": trades[:2000],
    }


# -----------------------------
# Background jobs
# -----------------------------

class JobRunner:
    def __init__(self):
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self):
        t1 = threading.Thread(target=self._price_pump_loop, name="zorp41-price-pump", daemon=True)
        t2 = threading.Thread(target=self._signal_loop, name="zorp41-signal", daemon=True)
        self._threads = [t1, t2]
        for t_ in self._threads:
            t_.start()

    def stop(self):
        self._stop.set()
        for t_ in self._threads:
            t_.join(timeout=1.5)

    def _price_pump_loop(self):
        # Keep a rolling price series for key symbols.
        symbols = ["USDC", "ETH", "BTC", "SOL", "ARB", "OP"]
        while not self._stop.is_set():
            try:
                ts = utc_ts()
                # Snap to 5-minute grid for reproducibility.
                ts = ts - (ts % 300)
                for sym in symbols:
                    px = MARKET.px_at(sym, ts)
                    price_upsert(sym, ts, px, "sim")
            except Exception:
                pass
            self._stop.wait(25.0)

    def _signal_loop(self):
        while not self._stop.is_set():
            try:
                with db() as conn:
                    vaults = conn.execute("SELECT * FROM vaults ORDER BY created_at ASC").fetchall()
                for v in vaults:
                    vdict = row_to_dict(v)
                    for horizon in ("1d", "7d", "30d"):
                        s = signal_for_vault(vdict, horizon)
                        sid = random_public_id("sig")
                        with db() as conn:
                            conn.execute(
                                "INSERT INTO signals(id, vault_id, ts, horizon, score, rationale, payload_json) VALUES(?,?,?,?,?,?,?)",
                                (
                                    sid,
                                    vdict["id"],
                                    utc_ts(),
                                    horizon,
                                    float(s["score"]),
                                    str(s["rationale"]),
                                    json_dumps(s["payload"]),
                                ),
                            )
            except Exception:
                pass
            self._stop.wait(90.0)


JOBS = JobRunner()


def job_create(kind: str) -> str:
    jid = random_public_id("job")
    with db() as conn:
        conn.execute(
            "INSERT INTO jobs(id, kind, status, created_at, progress) VALUES(?,?,?,?,?)",
            (jid, kind, "queued", utc_ts(), 0.0),
        )
    return jid


def job_update(jid: str, **fields: t.Any) -> None:
    allowed = {"status", "started_at", "finished_at", "last_heartbeat_at", "progress", "result_json", "error"}
    sets = []
    params = []
    for k, v in fields.items():
        if k not in allowed:
            continue
        sets.append(f"{k} = ?")
        params.append(v)
    if not sets:
        return
    params.append(jid)
    with db() as conn:
        conn.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE id = ?", tuple(params))


def job_get(jid: str) -> dict[str, t.Any] | None:
    with db() as conn:
        r = conn.execute("SELECT * FROM jobs WHERE id = ?", (jid,)).fetchone()
        return row_to_dict(r) if r else None


# -----------------------------
# Minimal bootstrap + tiny status page
# -----------------------------

def ensure_bootstrap_api_key() -> str:
    """
    Create a bootstrap API key if none exist.
    Stored in meta as plaintext ONCE for convenience; API auth uses hash in db.
    """
    existing = get_meta("bootstrap_api_key")
    if existing:
        return existing
    key = os.environ.get("ZORP41_BOOTSTRAP_API_KEY") or b64url(secrets.token_bytes(30))
    # Tie it to the first admin user.
    with db() as conn:
        u = conn.execute("SELECT id FROM users WHERE is_admin = 1 ORDER BY created_at ASC LIMIT 1").fetchone()
        if not u:
            seed_admin_if_needed()
            u = conn.execute("SELECT id FROM users WHERE is_admin = 1 ORDER BY created_at ASC LIMIT 1").fetchone()
        user_id = str(u["id"])
        conn.execute(
            "INSERT INTO api_keys(id, user_id, label, key_hash, created_at) VALUES(?,?,?,?,?)",
            (random_public_id("key"), user_id, "bootstrap", api_key_hash(key), utc_ts()),
        )
    set_meta("bootstrap_api_key", key)
    return key


@app.get("/")
def root_status():
    # Tiny HTML to avoid heavy templates.
    ensure_bootstrap_api_key()
    api_key = get_meta("bootstrap_api_key") or ""
    html = f"""
    <!doctype html>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Zorp41</title>
    <style>
      body{{margin:0;background:#0b1020;color:#eaf0ff;font:14px/1.45 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial}}
      .w{{max-width:860px;margin:26px auto;padding:0 16px}}
      .c{{background:#101a33;border:1px solid rgba(255,255,255,.10);border-radius:14px;padding:14px;margin:12px 0}}
      code{{font-family:ui-monospace,Consolas,Monaco,monospace;color:#cfe6ff}}
      a{{color:#77c0ff;text-decoration:none}}
    </style>
    <div class="w">
      <div class="c">
        <b>Zorp41 backend is running.</b>
        <div style="color:#93a4c8;margin-top:6px">Platform <code>{CONFIG.platform_id_hex}</code> · Audit <code>{CONFIG.audit_tag_hex}</code></div>
      </div>
      <div class="c">
        <div><b>Bootstrap API key</b> (header <code>{API_KEY_HEADER}</code>)</div>
        <div style="margin-top:8px"><code>{api_key}</code></div>
        <div style="color:#93a4c8;margin-top:10px">Open <a href="/ixmalu">/ixmalu</a> or call <a href="/health">/health</a>.</div>
      </div>
    </div>
    """
    return make_response(html)


@app.get("/health")
def health():
    with db() as conn:
        r = conn.execute("SELECT v FROM meta WHERE k = 'schema_version'").fetchone()
        ok = bool(r)
    return api_ok({"ok": ok, "ts": utc_ts(), "platform": CONFIG.platform_id_hex})


# -----------------------------
# Routes: JSON API
# -----------------------------


@app.get("/api/me")
def api_me():
    ctx = require_auth()
    out = {k: ctx[k] for k in ("user_id", "email", "is_admin", "kind") if k in ctx}
    if ctx.get("kind") == "session":
        out["csrf"] = ctx.get("csrf")
    return api_ok(out)


@app.get("/api/vaults")
def api_vaults():
    require_auth()
    with db() as conn:
        rows = conn.execute("SELECT * FROM vaults ORDER BY created_at DESC").fetchall()
    return api_ok([row_to_dict(r) for r in rows])


@app.get("/api/vault/<vault_id>")
def api_vault(vault_id: str):
    require_auth()
    v = vault_get(vault_id)
    if not v:
        return api_err("not_found", 404)
    strats = vault_strategies(vault_id)
    return api_ok(
        {
            "vault": v,
            "strategies": [dataclasses.asdict(s) for s in strats],
            "weights": normalize_weights(strats),
        }
    )


@app.post("/api/vault/<vault_id>/allocation")
def api_allocation(vault_id: str):
    ctx = require_auth()
    require_mutation(ctx)
    v = vault_get(vault_id)
    if not v:
        return api_err("not_found", 404)
    j = parse_json(required=False)
    horizon = str(j.get("horizon") or "30d")
    if horizon not in ("1d", "7d", "30d"):
        return api_err("bad_horizon", 400)
    strats = vault_strategies(vault_id)
    rec = allocation_recommendation(v, strats, horizon)
    audit("allocation_request", ctx["user_id"], {"vault_id": vault_id, "horizon": horizon})
    return api_ok(rec)


@app.get("/api/vault/<vault_id>/signals")
def api_signals(vault_id: str):
    require_auth()
    with db() as conn:
        rows = conn.execute("SELECT * FROM signals WHERE vault_id = ? ORDER BY ts DESC LIMIT 120", (vault_id,)).fetchall()
    out = [row_to_dict(r) for r in rows]
    for r in out:
        try:
            r["payload"] = json.loads(r.pop("payload_json"))
        except Exception:
            r["payload"] = {}
    return api_ok(out)


@app.get("/api/vault/<vault_id>/signals/generate")
def api_signal_generate(vault_id: str):
    ctx = require_auth()
    v = vault_get(vault_id)
    if not v:
        return api_err("not_found", 404)
    with db() as conn:
        for horizon in ("1d", "7d", "30d"):
            s = signal_for_vault(v, horizon)
            conn.execute(
                "INSERT INTO signals(id, vault_id, ts, horizon, score, rationale, payload_json) VALUES(?,?,?,?,?,?,?)",
                (random_public_id("sig"), vault_id, utc_ts(), horizon, float(s["score"]), str(s["rationale"]), json_dumps(s["payload"])),
            )
    audit("signal_generate", ctx["user_id"], {"vault_id": vault_id})
    return api_ok({"vault_id": vault_id, "generated": 3})


@app.post("/api/backtest")
def api_backtest_start():
    """
    Start a backtest job.
    Body:
      { "symbol":"ETH", "strategy":"momentum", "days":120, "step_min":60, "fee_bps":6, "slippage_bps":9 }
    """
    ctx = require_auth()
    require_mutation(ctx)
    j = parse_json(required=False)
    symbol = str(j.get("symbol") or "ETH").strip().upper()
    strategy = str(j.get("strategy") or "momentum").strip()
    days = int(j.get("days") or 120)
    step_min = int(j.get("step_min") or 60)
    fee_bps = float(j.get("fee_bps") or 6.0)
    slippage_bps = float(j.get("slippage_bps") or 9.0)
    if days <= 5 or days > 2000:
        return api_err("days_range", 400)
    if step_min < 5 or step_min > 1440:
        return api_err("step_range", 400)

    end_ts = utc_ts()
    start_ts = end_ts - days * 86400
    start_ts = start_ts - (start_ts % (step_min * 60))
    end_ts = end_ts - (end_ts % (step_min * 60))
    p = BacktestParams(
        symbol=symbol,
        start_ts=start_ts,
        end_ts=end_ts,
        step_sec=step_min * 60,
        fee_bps=fee_bps,
        slippage_bps=slippage_bps,
        strategy=strategy,
    )

    jid = job_create("backtest")
    audit("job_create", ctx["user_id"], {"job_id": jid, "kind": "backtest", "symbol": symbol, "strategy": strategy})

    def _run():
        job_update(jid, status="running", started_at=utc_ts(), last_heartbeat_at=utc_ts(), progress=0.05)
        try:
            res = backtest_run(p)
            job_update(
                jid,
                status="done" if res.get("ok") else "error",
                finished_at=utc_ts(),
                progress=1.0,
                result_json=json_dumps(res),
                error=None if res.get("ok") else res.get("error"),
            )
        except Exception as e:
            job_update(jid, status="error", finished_at=utc_ts(), progress=1.0, error=str(e))

    threading.Thread(target=_run, name=f"zorp41-job-{jid}", daemon=True).start()
    return api_ok({"job_id": jid})


@app.get("/api/price/<symbol>")
def api_price(symbol: str):
    require_auth()
    symbol = symbol.upper()
    p = price_latest(symbol)
    if not p:
        ts = utc_ts()
        ts = ts - (ts % 300)
        px = MARKET.px_at(symbol, ts)
        price_upsert(symbol, ts, px, "sim")
        p = price_latest(symbol)
    return api_ok(dataclasses.asdict(p) if p else None)


@app.get("/api/price/<symbol>/series")
def api_price_series(symbol: str):
    require_auth()
    symbol = symbol.upper()
    end_ts = int(request.args.get("end_ts") or utc_ts())
    days = int(request.args.get("days") or 30)
    step = int(request.args.get("step_sec") or 3600)
    days = int(clamp(days, 1, 3650))
    step = int(clamp(step, 60, 86400))
    start_ts = end_ts - days * 86400
    start_ts = start_ts - (start_ts % step)
    end_ts = end_ts - (end_ts % step)
    pts = price_series(symbol, start_ts, end_ts, step)
    return api_ok([dataclasses.asdict(p) for p in pts])


@app.get("/api/job/<job_id>")
def api_job(job_id: str):
    require_auth()
    j = job_get(job_id)
