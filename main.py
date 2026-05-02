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
