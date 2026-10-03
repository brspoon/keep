from flask import Flask, jsonify, render_template, render_template_string, request, redirect, session, url_for, has_request_context, g

def get_client_ip():
    return request.remote_addr or "unknown"
import requests
from urllib.parse import urlencode, urlsplit
from onboarding import Onboarding, digest as bootstrap_digest
from deployment_transport import cookie_policy, validate_origin
from connection_settings import (ConnectionSettings, CONNECTION_FIELDS, EMAIL_FIELDS, SECRETS, PLEX_FIELDS,
                                 SERVICE_URL_PORTS, split_service_url, service_url_from_form,
                                 connection_open_services)
import media_services
import leaving_forecast
import artwork_cache
import seerr
import connection_monitor
import background_jobs
import email_templates
import api_v1
MASKED_CONNECTION_FIELDS = SECRETS + ("PLEX_MACHINE_IDENTIFIER",)
from contextvars import ContextVar
from service_discovery import discover_collections, test_plex
import smtplib
import os
os.umask(0o077)
import errno
import socket
import ssl
import secrets
import json
import sqlite3
import time
import sys
import uuid
import html
import re
import hashlib
import math
import fcntl
from itsdangerous import URLSafeTimedSerializer, BadSignature
import xml.etree.ElementTree as ET
from contextlib import closing, contextmanager
from functools import wraps
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from pathlib import Path
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# Read release metadata once per process, independent of the working directory.
APP_VERSION = Path(__file__).with_name("VERSION").read_text(encoding="utf-8").strip()
if not APP_VERSION:
    raise RuntimeError("VERSION must contain the application release number")

app = Flask(__name__)


@app.errorhandler(500)
def unexpected_error(error):
    """A safe fallback that does not depend on DB-backed context processors."""
    if request.path == '/api/v1' or request.path.startswith('/api/v1/'):
        return api_v1.error_response(500, 'internal_error', 'Keep could not complete the request. Check the current state before retrying.')
    if request.path.startswith('/api/') or request.is_json:
        response = jsonify(error='Something went wrong. Check the latest state before trying again.')
    else:
        retry_url = request.path if request.method == 'GET' and not request.path.startswith('/auth/') else '/'
        response = app.response_class(app.jinja_env.get_template('error.html').render(
            app_version=APP_VERSION, retry_url=retry_url, is_action=request.method != 'GET'), mimetype='text/html')
    response.status_code = 500
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.after_request
def security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    if request.path.startswith(('/settings/connections', '/setup', '/auth/plex')):
        response.headers['Cache-Control'] = 'no-store'
    return response


@app.context_processor
def release_context():
    context = {"app_version": APP_VERSION, "theme_mode": "system"}
    user = session.get("plex_user")
    if user:
        profile = current_profile()
        if profile:
            context['theme_mode'] = profile['theme_mode']
        context.update(plex_user=user, owner=is_owner(), capabilities=user_capabilities(),
                       granted_libraries=granted_library_keys(), csrf_token=get_csrf_token(),
                       announcement_version=ANNOUNCEMENT_VERSION,
                       show_announcement=bool(profile and request.path != '/help'
                                              and not announcement_seen(profile['plex_id'])))
    return context


app.secret_key = os.environ["FLASK_SECRET_KEY"]
if len(app.secret_key) < 32:
    raise RuntimeError("FLASK_SECRET_KEY must contain at least 32 random characters")
KEEP_TRANSPORT_MODE = os.environ.get("KEEP_TRANSPORT_MODE", "https")
try:
    secure_session_cookie = cookie_policy(KEEP_TRANSPORT_MODE, os.environ.get("KEEP_URL", ""))
except ValueError as error:
    raise RuntimeError(str(error)) from error
app.config.update(
    MAX_CONTENT_LENGTH=1024 * 1024,
    KEEP_TRANSPORT_MODE=KEEP_TRANSPORT_MODE,
    SESSION_COOKIE_SECURE=secure_session_cookie,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,
)
if KEEP_TRANSPORT_MODE == "lan-http":
    app.config['TRUSTED_HOSTS'] = [urlsplit(os.environ['KEEP_URL']).hostname, '127.0.0.1', 'localhost']

MAINTAINERR_URL = ""
SMTP_HOST = ""
SMTP_PORT = 465
SMTP_USER = ""
SMTP_FROM = ""
SMTP_SENDER_NAME = "Keep"
SMTP_SECURITY = "ssl"
EMAIL_ENABLED = "false"
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
KEEP_WEBHOOK_SECRET = os.environ.get("KEEP_WEBHOOK_SECRET", "")
KEEP_URL = os.environ.get("KEEP_URL", "")
PLEX_CLIENT_IDENTIFIER = os.environ.get("PLEX_CLIENT_IDENTIFIER", "Keep")
PLEX_PRODUCT = "Keep"
PLEX_AUTH_BASE = "https://app.plex.tv/auth"
PLEX_API_BASE = "https://plex.tv/api/v2"
PLEX_SERVER_URL = os.environ.get("PLEX_SERVER_URL", "").rstrip("/")
PLEX_MACHINE_IDENTIFIER = os.environ.get("PLEX_MACHINE_IDENTIFIER", "")
PLEX_OWNER_ID = os.environ.get("PLEX_OWNER_ID", "")
if PLEX_OWNER_ID and not re.fullmatch(r"[1-9][0-9]*", PLEX_OWNER_ID):
    raise RuntimeError("Set PLEX_OWNER_ID to the operator-selected Plex account ID before starting Keep")
PLEX_ADMIN_TOKEN = os.environ.get("PLEX_ADMIN_TOKEN", "")
PLEX_ACCESS_SYNC_SECONDS = int(os.environ.get("PLEX_ACCESS_SYNC_SECONDS", "900"))
PLEX_ACCESS_LEASE_SECONDS = 24 * 60 * 60
LOCAL_SETUP_SECONDS = 24 * 60 * 60
PASSWORD_MIN_LENGTH = 15
TEMPORARY_KEEP_DAYS = 30
TEMPORARY_KEEP_MIGRATION = "temporary-keeps-v1"
COLLECTIONS = {}
RECIPIENT_COLLECTION_IDS = ()
password_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
DUMMY_PASSWORD_HASH = password_hasher.hash(secrets.token_urlsafe(32))




KEEP_DB_PATH = os.environ.get("KEEP_DB_PATH", "/app/data/keep.sqlite3")
os.makedirs(os.path.dirname(os.path.abspath(KEEP_DB_PATH)), exist_ok=True)


connection_settings = ConnectionSettings(KEEP_DB_PATH)
onboarding = Onboarding(KEEP_DB_PATH, PLEX_OWNER_ID)
if "PLEX_CLIENT_IDENTIFIER" not in os.environ:
    PLEX_CLIENT_IDENTIFIER = onboarding.client_id()

def owner_id():
    return onboarding.owner()



_settings_snapshot = ContextVar('keep_settings', default=None)


def connection_value(name):
    snapshot = _settings_snapshot.get()
    fallback = globals().get(name, '')
    return snapshot.get(name, fallback) if snapshot is not None else connection_settings.get(name, fallback)


def get_collections():
    raw = connection_value('KEEP_COLLECTIONS')
    return {int(key): label for key, label in json.loads(raw).items()} if raw else COLLECTIONS


def recipient_collection_ids():
    return tuple(get_collections())


def email_enabled():
    return connection_value('EMAIL_ENABLED') == 'true'


@app.before_request
def load_settings_snapshot():
    from flask import g
    onboarding.cleanup()
    g.settings_context_token = _settings_snapshot.set(connection_settings.snapshot())


@app.teardown_request
def release_settings_snapshot(error=None):
    from flask import g
    token = g.pop('settings_context_token', None)
    if token is not None:
        _settings_snapshot.reset(token)



def attribution_db():
    db = sqlite3.connect(KEEP_DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    return db


with closing(attribution_db()) as db, db:
    db.execute("BEGIN IMMEDIATE")
    db.execute("""
        CREATE TABLE IF NOT EXISTS keep_attribution (
            collection_id TEXT NOT NULL,
            media_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            kept_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (collection_id, media_id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS keep_schedules (
            collection_id TEXT NOT NULL,
            media_id TEXT NOT NULL,
            expires_at TEXT,
            extension_available_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (collection_id, media_id)
        )
    """)
    schedule_columns = {row["name"] for row in db.execute("PRAGMA table_info(keep_schedules)")}
    if "extension_available_at" not in schedule_columns:
        db.execute("ALTER TABLE keep_schedules ADD COLUMN extension_available_at TEXT")
    db.execute("""
        CREATE TABLE IF NOT EXISTS keep_migrations (
            name TEXT PRIMARY KEY,
            started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT
        )
    """)
    db.execute("INSERT OR IGNORE INTO keep_migrations(name) VALUES (?)",
               (TEMPORARY_KEEP_MIGRATION,))


with closing(attribution_db()) as db, db:
    db.execute("BEGIN IMMEDIATE")
    db.execute("""CREATE TABLE IF NOT EXISTS user_profiles (
        plex_id TEXT PRIMARY KEY,
        plex_username TEXT NOT NULL DEFAULT '',
        email TEXT NOT NULL DEFAULT '',
        full_name TEXT NOT NULL DEFAULT '',
        display_name TEXT NOT NULL DEFAULT '',
        can_remove_any INTEGER NOT NULL DEFAULT 0 CHECK (can_remove_any IN (0, 1)),
        can_keep_indefinitely INTEGER NOT NULL DEFAULT 0 CHECK (can_keep_indefinitely IN (0, 1)),
        can_delete_media INTEGER NOT NULL DEFAULT 0 CHECK (can_delete_media IN (0, 1)),
        can_delete_any INTEGER NOT NULL DEFAULT 0 CHECK (can_delete_any IN (0, 1)),
        auth_type TEXT NOT NULL DEFAULT 'plex',
        status TEXT NOT NULL DEFAULT 'active',
        password_hash TEXT NOT NULL DEFAULT '',
        invite_token_hash TEXT,
        invite_expires_at REAL,
        session_version INTEGER NOT NULL DEFAULT 0,
        last_seen_at TEXT,
        plex_access TEXT NOT NULL DEFAULT 'active',
        plex_checked_at TEXT,
        plex_sync_visible INTEGER NOT NULL DEFAULT 0,
        theme_mode TEXT NOT NULL DEFAULT 'system' CHECK (theme_mode IN ('system', 'light', 'dark'))
    )""")
    profile_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(user_profiles)")
    }
    if "can_remove_any" not in profile_columns:
        db.execute("ALTER TABLE user_profiles ADD COLUMN can_remove_any INTEGER NOT NULL DEFAULT 0")
    profile_migrations = {
        "can_keep_indefinitely": "INTEGER NOT NULL DEFAULT 0",
        "can_delete_media": "INTEGER NOT NULL DEFAULT 0",
        "can_delete_any": "INTEGER NOT NULL DEFAULT 0",
        "auth_type": "TEXT NOT NULL DEFAULT 'plex'",
        "status": "TEXT NOT NULL DEFAULT 'active'",
        "password_hash": "TEXT NOT NULL DEFAULT ''",
        "invite_token_hash": "TEXT",
        "invite_expires_at": "REAL",
        "session_version": "INTEGER NOT NULL DEFAULT 0",
        "welcome_version": "TEXT NOT NULL DEFAULT ''",
        "plex_access": "TEXT NOT NULL DEFAULT 'active'",
        "plex_checked_at": "TEXT",
        "plex_sync_visible": "INTEGER NOT NULL DEFAULT 0",
        "theme_mode": "TEXT NOT NULL DEFAULT 'system' CHECK (theme_mode IN ('system', 'light', 'dark'))",
    }
    for column, definition in profile_migrations.items():
        if column not in profile_columns:
            db.execute(f"ALTER TABLE user_profiles ADD COLUMN {column} {definition}")
    db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS local_user_email_unique
                  ON user_profiles(lower(email)) WHERE auth_type = 'local'""")
    db.execute("""CREATE TABLE IF NOT EXISTS email_recipients (
        email TEXT PRIMARY KEY COLLATE NOCASE,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS recipient_subscriptions (
        email TEXT NOT NULL COLLATE NOCASE,
        collection_id INTEGER NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        PRIMARY KEY (email, collection_id)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS auth_rate_limits (
        action TEXT NOT NULL,
        client_key TEXT NOT NULL,
        window_started INTEGER NOT NULL,
        attempts INTEGER NOT NULL,
        PRIMARY KEY (action, client_key)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        actor_id TEXT NOT NULL DEFAULT '',
        actor_name TEXT NOT NULL DEFAULT '',
        action TEXT NOT NULL,
        description TEXT NOT NULL
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS media_libraries (
        library_key TEXT PRIMARY KEY,
        service TEXT NOT NULL CHECK (service IN ('radarr', 'sonarr')),
        external_id TEXT NOT NULL,
        name TEXT NOT NULL,
        path TEXT NOT NULL,
        last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(service, external_id)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS user_library_permissions (
        user_id TEXT NOT NULL,
        library_key TEXT NOT NULL,
        PRIMARY KEY(user_id, library_key),
        FOREIGN KEY(user_id) REFERENCES user_profiles(plex_id) ON DELETE CASCADE,
        FOREIGN KEY(library_key) REFERENCES media_libraries(library_key) ON DELETE CASCADE
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS user_feature_acknowledgements (
        user_id TEXT NOT NULL,
        feature_key TEXT NOT NULL,
        version TEXT NOT NULL,
        acknowledged_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(user_id, feature_key)
    )""")
    for recipient in db.execute("SELECT email FROM email_recipients").fetchall():
        db.executemany("""INSERT OR IGNORE INTO recipient_subscriptions
            (email, collection_id, enabled) VALUES (?, ?, 1)""",
            ((recipient["email"], collection_id)
             for collection_id in recipient_collection_ids()))
    # Migrate names cached by the former Seerr integration, if present.
    old_names = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'keeper_names'"
    ).fetchone()
    if old_names:
        db.execute("""INSERT OR IGNORE INTO user_profiles(plex_id, display_name)
                      SELECT plex_id, display_name FROM keeper_names""")


def short_keeper_name(full_name):
    parts = full_name.split()
    if len(parts) > 1:
        return f"{parts[0]} {parts[-1][0].upper()}"
    return parts[0] if parts else ""


def get_keeper_names():
    with closing(attribution_db()) as db:
        return {
            row["plex_id"]: row["display_name"] or row["plex_username"]
            for row in db.execute("SELECT plex_id, plex_username, display_name FROM user_profiles")
        }


def plex_account_access_active(profile):
    """Bound Plex-derived access by the most recent positive verification."""
    if not profile:
        return False
    if profile['auth_type'] != 'plex':
        return True
    if profile['plex_access'] != 'active':
        return False
    if str(profile['plex_id']) == owner_id():
        return True
    try:
        checked = datetime.fromisoformat(profile['plex_checked_at'])
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - checked).total_seconds()
    except (TypeError, ValueError):
        return False
    return 0 <= age < PLEX_ACCESS_LEASE_SECONDS


def remember_plex_user(user, *, access_verified=False):
    if user.get("auth_type") == "local":
        with closing(attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET last_seen_at = CURRENT_TIMESTAMP WHERE plex_id = ?",
                       (str(user["id"]),))
        return
    with closing(attribution_db()) as db, db:
        db.execute('BEGIN IMMEDIATE')
        profile = db.execute('SELECT * FROM user_profiles WHERE plex_id=?',
                             (str(user['id']),)).fetchone()
        expired = bool(access_verified and profile and profile['plex_access'] == 'active'
                       and not plex_account_access_active(profile))
        db.execute("""
            INSERT INTO user_profiles(plex_id, plex_username, email, last_seen_at,
                                      plex_access, plex_checked_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, 'active',
                    CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END)
            ON CONFLICT(plex_id) DO UPDATE SET
                plex_username = excluded.plex_username,
                email = excluded.email,
                last_seen_at = CURRENT_TIMESTAMP,
                plex_access = CASE WHEN ? THEN 'active' ELSE user_profiles.plex_access END,
                plex_checked_at = CASE WHEN ? THEN CURRENT_TIMESTAMP
                                       ELSE user_profiles.plex_checked_at END,
                session_version = user_profiles.session_version + ?
        """, (str(user["id"]), user.get("username") or "", user.get("email") or "",
              int(access_verified), int(access_verified), int(access_verified), int(expired)))


def mark_plex_access(plex_id, access):
    """Record an authoritative Plex access result and invalidate active sessions on change."""
    if access not in ("active", "revoked"):
        raise ValueError("Invalid Plex access state")
    with closing(attribution_db()) as db, db:
        row = db.execute("""SELECT plex_access FROM user_profiles
            WHERE plex_id = ? AND auth_type = 'plex'""", (str(plex_id),)).fetchone()
        if not row:
            return False
        changed = row["plex_access"] != access
        db.execute("""UPDATE user_profiles SET plex_access = ?, plex_checked_at = CURRENT_TIMESTAMP,
            session_version = session_version + ? WHERE plex_id = ?""",
            (access, int(changed), str(plex_id)))
    return changed


def get_authorized_plex_user_ids():
    """Return users currently authorized by Plex, or None when Plex cannot be checked."""
    if not connection_value('PLEX_ADMIN_TOKEN'):
        return None
    headers = {**plex_headers(), "Accept": "application/xml",
               "X-Plex-Token": connection_value('PLEX_ADMIN_TOKEN')}
    try:
        accounts_response = requests.get(
            f"{connection_value('PLEX_SERVER_URL')}/accounts", headers=headers, timeout=15, allow_redirects=False)
        accounts_response.raise_for_status()
        shared_response = requests.get(
            "https://plex.tv/api/users", headers=headers, timeout=15)
        shared_response.raise_for_status()
        account_root = ET.fromstring(accounts_response.content)
        shared_root = ET.fromstring(shared_response.content)
    except (requests.RequestException, ET.ParseError):
        app.logger.error("Could not refresh Plex user access")
        return None

    authorized = {owner_id()} if owner_id() else set()
    authorized.update(
        str(account.get("id")) for account in account_root.findall("Account")
        if account.get("id")
    )

    for user in shared_root.findall("User"):
        servers = user.findall("Server")
        if user.get("id") and (
            not servers or any(server.get("machineIdentifier") == connection_value('PLEX_MACHINE_IDENTIFIER')
                               for server in servers)
        ):
            authorized.add(str(user.get("id")))
    return authorized


def sync_plex_user_access():
    authorized = get_authorized_plex_user_ids()
    if authorized is None:
        return None
    changes = []
    with closing(attribution_db()) as db, db:
        db.execute('BEGIN IMMEDIATE')
        users = db.execute("SELECT * FROM user_profiles WHERE auth_type = 'plex'").fetchall()
        for user in users:
            is_authorized = str(user["plex_id"]) in authorized
            if (not is_authorized and not user["plex_sync_visible"]
                    and plex_account_access_active(user)):
                continue
            next_access = "active" if is_authorized else "revoked"
            changed = user["plex_access"] != next_access
            db.execute("""UPDATE user_profiles SET plex_access = ?,
                plex_checked_at = CURRENT_TIMESTAMP, plex_sync_visible = ?,
                session_version = session_version + ? WHERE plex_id = ?""",
                (next_access, int(is_authorized or user["plex_sync_visible"]),
                 int(changed or (is_authorized and not plex_account_access_active(user))),
                 user["plex_id"]))
            if changed:
                changes.append((user["display_name"] or user["plex_username"] or user["plex_id"],
                                next_access))
    for label, access in changes:
        description = (f"Restored Plex access for {label}" if access == "active"
                       else f"Marked {label} as no longer having Plex access")
        log_activity("plex-access-changed", description,
                     actor={"username": "Keep access sync"})
    return len(changes)


def local_session_user(profile):
    return {
        "id": profile["plex_id"],
        "username": profile["display_name"] or profile["full_name"] or profile["email"],
        "email": profile["email"],
        "thumb": "",
        "auth_type": "local",
        "session_version": profile["session_version"],
    }


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def persistent_rate_limit(action, limit, window_seconds):
    """Return a 429 response after a per-client fixed-window limit is exhausted."""
    now = int(time.time())
    window_started = now - (now % window_seconds)
    client_key = hashlib.sha256(
        f"{app.secret_key}\0{get_client_ip()}".encode("utf-8")
    ).hexdigest()
    with closing(attribution_db()) as db, db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("""SELECT window_started, attempts FROM auth_rate_limits
            WHERE action = ? AND client_key = ?""", (action, client_key)).fetchone()
        if not row or row["window_started"] != window_started:
            attempts = 1
            db.execute("""INSERT INTO auth_rate_limits(action, client_key, window_started, attempts)
                VALUES (?, ?, ?, 1) ON CONFLICT(action, client_key) DO UPDATE SET
                window_started = excluded.window_started, attempts = 1""",
                (action, client_key, window_started))
        else:
            attempts = row["attempts"] + 1
            db.execute("""UPDATE auth_rate_limits SET attempts = ?
                WHERE action = ? AND client_key = ?""", (attempts, action, client_key))
        db.execute("DELETE FROM auth_rate_limits WHERE window_started < ?",
                   (now - 24 * 60 * 60,))
    if attempts <= limit:
        return None
    response = app.make_response(("Too many requests. Please try again later.", 429))
    response.headers["Retry-After"] = str(max(1, window_started + window_seconds - now))
    return response


def activity_actor(user=None):
    if user is None:
        user = session.get("plex_user") if has_request_context() else {}
    user = user or {}
    return (
        str(user.get("id") or ""),
        user.get("display_name") or user.get("username") or user.get("email") or "System",
    )


def log_activity(action, description, actor=None):
    actor_id, actor_name = activity_actor(actor)
    try:
        with closing(attribution_db()) as db, db:
            db.execute("""INSERT INTO activity_log(actor_id, actor_name, action, description)
                VALUES (?, ?, ?, ?)""", (actor_id, actor_name, action, description))
    except sqlite3.Error:
        app.logger.error("Could not record activity %s", action)


def relative_timestamp(value):
    if not value:
        return "Never"
    try:
        moment = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return "Unknown"
    seconds = max(0, int((datetime.now(timezone.utc) - moment).total_seconds()))
    if seconds < 60:
        return "Just now"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} hr ago"
    return f"{seconds // 86400} days ago"


def invite_expiry_label(value):
    if not value:
        return "No setup link pending"
    seconds = int(value - time.time())
    if seconds <= 0:
        return "Setup link expired"
    if seconds < 3600:
        return f"Setup link expires in {max(1, seconds // 60)} min"
    return f"Setup link expires in {(seconds + 3599) // 3600} hr"


def get_local_user_by_token(token):
    digest = token_digest(token)
    with closing(attribution_db()) as db:
        return db.execute("""SELECT * FROM user_profiles
            WHERE auth_type = 'local' AND invite_token_hash = ?
              AND invite_expires_at > ?""", (digest, time.time())).fetchone()


def is_owner():
    user = session.get("plex_user") or {}
    return bool(owner_id()) and str(user.get("id")) == owner_id()


def current_owner_session():
    if not is_owner():
        return False
    with closing(attribution_db()) as db:
        profile = db.execute('SELECT * FROM user_profiles WHERE plex_id=?', (owner_id(),)).fetchone()
    user = session.get('plex_user') or {}
    return bool(profile and profile['status'] == 'active' and profile['auth_type'] == 'plex'
                and profile['plex_access'] == 'active'
                and user.get('session_version', 0) == profile['session_version'])


def can_remove_any_keep(user=None):
    user = user or session.get("plex_user") or {}
    plex_id = str(user.get("id") or "")
    if not plex_id:
        return False
    if owner_id() and plex_id == owner_id():
        return True
    with closing(attribution_db()) as db:
        profile = db.execute(
            "SELECT can_remove_any FROM user_profiles WHERE plex_id = ?", (plex_id,)
        ).fetchone()
    return bool(profile and profile["can_remove_any"])


def user_capabilities(user=None):
    user = user or session.get("plex_user") or {}
    user_id = str(user.get("id") or "")
    owner = bool(owner_id()) and user_id == owner_id()
    if not user_id:
        return {"owner": False, "keep_indefinitely": False,
                "manage_any": False, "remove_any": False, "delete_media": False, "delete_any": False}
    with closing(attribution_db()) as db:
        profile = db.execute("""SELECT can_keep_indefinitely, can_remove_any,
            can_delete_media, can_delete_any FROM user_profiles WHERE plex_id = ?""", (user_id,)).fetchone()
    manage_any = owner or bool(profile and profile["can_remove_any"])
    return {
        "owner": owner,
        "keep_indefinitely": owner or bool(profile and profile["can_keep_indefinitely"]),
        "manage_any": manage_any,
        # Retained for compatibility with existing templates and callers.
        "remove_any": manage_any,
        "delete_media": owner or bool(profile and profile["can_delete_media"]),
        "delete_any": owner or bool(profile and profile["can_delete_media"] and profile["can_delete_any"]),
    }


def can_keep_indefinitely(user=None):
    return user_capabilities(user)["keep_indefinitely"]


def media_libraries():
    with closing(attribution_db()) as db:
        return [dict(row) for row in db.execute(
            "SELECT * FROM media_libraries ORDER BY name COLLATE NOCASE, service"
        )]


def granted_library_keys(user=None):
    user = user or session.get("plex_user") or {}
    user_id = str(user.get("id") or "")
    if not user_capabilities(user)["delete_media"]:
        return set()
    with closing(attribution_db()) as db:
        if owner_id() and user_id == owner_id():
            return {row[0] for row in db.execute("SELECT library_key FROM media_libraries")}
        return {row[0] for row in db.execute(
            "SELECT library_key FROM user_library_permissions WHERE user_id = ?", (user_id,)
        )}


def refresh_media_libraries(service):
    libraries = media_services.discover_libraries(service, connection_value)
    with closing(attribution_db()) as db, db:
        current_keys = {library["key"] for library in libraries}
        stale_keys = {row[0] for row in db.execute(
            "SELECT library_key FROM media_libraries WHERE service = ?", (service,)
        ) if row[0] not in current_keys}
        if stale_keys:
            placeholders = ",".join("?" for _ in stale_keys)
            db.execute(f"DELETE FROM user_library_permissions WHERE library_key IN ({placeholders})",
                       tuple(stale_keys))
            db.execute(f"DELETE FROM media_libraries WHERE library_key IN ({placeholders})",
                       tuple(stale_keys))
        for library in libraries:
            db.execute("""INSERT INTO media_libraries
                (library_key, service, external_id, name, path, last_seen_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(library_key) DO UPDATE SET name=excluded.name,
                    path=excluded.path, last_seen_at=CURRENT_TIMESTAMP""",
                (library["key"], library["service"], library["external_id"],
                 library["name"], library["path"]))
    return libraries


def db_timestamp(value):
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def temporary_keep_expiry(now=None):
    now = now or datetime.now(timezone.utc)
    return db_timestamp(now + timedelta(days=TEMPORARY_KEEP_DAYS))


def record_keeper(collection_id, media_id, user, duration="temporary", now=None):
    if duration not in {"temporary", "indefinite"}:
        raise ValueError("unsupported keep duration")
    remember_plex_user(user)
    with closing(attribution_db()) as db, db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("""
            INSERT INTO keep_attribution (collection_id, media_id, user_id, username)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(collection_id, media_id) DO NOTHING
        """, (str(collection_id), str(media_id), str(user["id"]),
              user.get("username") or "Plex user"))
        db.execute("""
            INSERT INTO keep_schedules
                (collection_id, media_id, expires_at, extension_available_at)
            VALUES (?, ?, ?, NULL)
            ON CONFLICT(collection_id, media_id) DO UPDATE SET
                expires_at=excluded.expires_at, extension_available_at=NULL
        """, (str(collection_id), str(media_id),
              temporary_keep_expiry(now) if duration == "temporary" else None))


def can_manage_keep(collection_id, media_id, user=None):
    user = user or session.get("plex_user") or {}
    if can_remove_any_keep(user):
        return True
    with closing(attribution_db()) as db:
        keeper = db.execute("""SELECT user_id FROM keep_attribution
            WHERE collection_id = ? AND media_id = ?""",
            (str(collection_id), str(media_id))).fetchone()
    return bool(keeper and keeper["user_id"] == str(user.get("id") or ""))


def can_remove_keep(collection_id, media_id, user=None):
    return can_remove_any_keep(user) or can_manage_keep(collection_id, media_id, user)


def keep_migration_started_at():
    with closing(attribution_db()) as db:
        row = db.execute("SELECT started_at FROM keep_migrations WHERE name = ?",
                         (TEMPORARY_KEEP_MIGRATION,)).fetchone()
    return datetime.strptime(row["started_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def migrate_existing_keep_schedules(exclusions_by_collection=None):
    """Give every exclusion present at upgrade a fresh, one-time 30-day keep."""
    with closing(attribution_db()) as db:
        migration = db.execute("SELECT * FROM keep_migrations WHERE name = ?",
                               (TEMPORARY_KEEP_MIGRATION,)).fetchone()
    if migration and migration["completed_at"]:
        return 0

    if exclusions_by_collection is None:
        exclusions_by_collection = {
            collection_id: get_collection_exclusions(collection_id).get("items", [])
            for collection_id in get_collections()
        }

    expires_at = temporary_keep_expiry(keep_migration_started_at())
    migrated = 0
    with closing(attribution_db()) as db, db:
        db.execute("BEGIN IMMEDIATE")
        migration = db.execute("SELECT completed_at FROM keep_migrations WHERE name = ?",
                               (TEMPORARY_KEEP_MIGRATION,)).fetchone()
        if migration and migration["completed_at"]:
            return 0
        for collection_id, items in exclusions_by_collection.items():
            for item in items:
                # Collection feeds also include global exclusions. Leave those
                # operator-owned protections outside Keep's automatic lifecycle.
                if "ruleGroupId" in item and item.get("ruleGroupId") is None:
                    continue
                media_id = item.get("mediaServerId")
                if media_id is None:
                    continue
                cursor = db.execute("""
                    INSERT OR IGNORE INTO keep_schedules(collection_id, media_id, expires_at)
                    VALUES (?, ?, ?)
                """, (str(collection_id), str(media_id), expires_at))
                migrated += cursor.rowcount
        db.execute("UPDATE keep_migrations SET completed_at=CURRENT_TIMESTAMP WHERE name = ?",
                   (TEMPORARY_KEEP_MIGRATION,))

    if migrated:
        expiry_date = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S").strftime("%B %d, %Y")
        log_activity(
            "keeps-migrated",
            f"Converted {migrated} existing keeps to 30-day keeps expiring {expiry_date}",
            actor={"username": "Keep maintenance worker"},
        )
    return migrated


def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def plex_headers():
    return {
        "Accept": "application/json",
        "X-Plex-Product": PLEX_PRODUCT,
        "X-Plex-Client-Identifier": PLEX_CLIENT_IDENTIFIER,
    }


@app.route("/auth/plex", methods=["GET", "POST"])
def plex_login():
    if request.method == "GET":
        return render_template("setup.html", mode="login", csrf_token=get_csrf_token())
    csrf_error = require_form_csrf()
    if csrf_error:
        return csrf_error
    return begin_plex_flow("login")


def begin_plex_flow(purpose, extra=None):
    if purpose == "login" and not owner_id():
        return redirect("/setup")
    try:
        origin = validate_origin(connection_value("KEEP_URL"), app.config['KEEP_TRANSPORT_MODE'])
    except ValueError:
        return "Configure KEEP_URL for the selected HTTPS or local HTTP deployment before connecting Plex.", 400
    limited = persistent_rate_limit("plex-login", 10, 60)
    if limited:
        return limited
    try:
        response = requests.post(f"{PLEX_API_BASE}/pins", headers=plex_headers(),
                                 data={"strong": "true"}, timeout=10, allow_redirects=False)
        response.raise_for_status()
        pin = response.json()
        pin_id, code = pin["id"], pin["code"]
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return "Plex authentication is temporarily unavailable. Please try again.", 503
    binding = secrets.token_urlsafe(32)
    session["plex_binding"] = binding
    state = onboarding.put_flow(binding, purpose, {"pin": pin_id, "code": code, **(extra or {})})
    callback = origin + '/auth/plex/callback?' + urlencode({'state': state})
    return redirect(PLEX_AUTH_BASE + '#?' + urlencode({
        'clientID': PLEX_CLIENT_IDENTIFIER, 'code': code,
        'context[device][product]': PLEX_PRODUCT, 'forwardUrl': callback}))


@app.route("/auth/plex/callback")
def plex_callback():
    flow = onboarding.take_flow(request.args.get("state", ""), session.pop("plex_binding", ""))
    if not flow:
        return "Plex login session expired or already used. Please try again.", 400
    purpose, payload = flow
    pin_id = payload['pin']
    if purpose == 'connect' and (not current_owner_session() or payload.get('owner') != owner_id()):
        return "Owner authorization required.", 403

    try:
        response = requests.get(
            f"{PLEX_API_BASE}/pins/{pin_id}",
            headers=plex_headers(),
            params={"code": payload["code"]},
            allow_redirects=False,
            timeout=10,
        )
        response.raise_for_status()
        pin = response.json()
    except (requests.RequestException, ValueError):
        session.clear()
        return "Plex authentication could not be completed. Please try again.", 503

    auth_token = pin.get("authToken") if isinstance(pin, dict) else None

    if not auth_token:
        return "Plex authentication has not completed yet. Please try signing in again.", 401

    plex_user = get_plex_user(auth_token)

    if not plex_user:
        session.clear()
        return "Plex authentication could not be verified. Please try again.", 503

    if purpose in ('bootstrap', 'connect'):
        if purpose == 'connect' and str(plex_user['id']) != owner_id():
            return "Sign in with the existing Keep owner's Plex account.", 403
        try:
            resources = owned_plex_servers(auth_token)
            if not resources:
                return "This Plex account has no eligible owned servers. Claim a Plex server first, then try again.", 400
            if purpose == 'bootstrap':
                onboarding.claim(payload['bootstrap'], str(plex_user['id']))
                remember_plex_user(plex_user, access_verified=True)
                session.clear()
                session['plex_user'] = plex_user
                session.permanent = True
            binding = secrets.token_urlsafe(32)
            session['plex_selection_binding'] = binding
            session['plex_selection'] = onboarding.put_flow(binding, 'selection',
                {'owner': owner_id(), 'servers': resources})
            return redirect('/settings/connections/plex/select')
        except (ValueError, requests.RequestException):
            return "Plex ownership or server discovery could not be verified. Start again.", 400

    if not plex_user["id"] or (str(plex_user["id"]) != owner_id() and not plex_user_has_server_access(auth_token)):
        if plex_user["id"]:
            mark_plex_access(plex_user["id"], "revoked")
        session.clear()
        return render_auth_page(
            title="Access denied",
            message="This Plex account doesn’t have access to Keep. Sign in with an account that has access to this Plex server.",
            button_label="Back to sign in",
            button_url=url_for("login"),
            footnote="If you think you should have access, contact the server owner.",
        ), 403

    remembered_user = {
        "id": plex_user["id"],
        "username": plex_user["username"],
        "email": plex_user["email"],
        "thumb": plex_user["thumb"],
    }
    remember_plex_user(remembered_user, access_verified=True)
    with closing(attribution_db()) as db:
        profile = db.execute("SELECT * FROM user_profiles WHERE plex_id = ?",
                             (str(plex_user["id"]),)).fetchone()
    if (profile and profile["status"] == "disabled"
            and str(profile["plex_id"]) != owner_id()):
        session.clear()
        return render_auth_page(
            title="Access disabled",
            message="Your Keep account has been disabled by the owner.",
            button_label="Back to sign in",
            button_url=url_for("login"),
            footnote="Contact the server owner if you think this is a mistake.",
        ), 403

    session.clear()
    session.permanent = True
    remembered_user["session_version"] = profile["session_version"] if profile else 0
    session["plex_user"] = remembered_user
    log_activity("login", "Signed in with Plex")

    return redirect("/")




def get_plex_user(auth_token):
    try:
        response = requests.get(
            f"{PLEX_API_BASE}/user",
            headers={
                **plex_headers(),
                "X-Plex-Token": auth_token,
            },
            timeout=10, allow_redirects=False,
        )
        response.raise_for_status()
        user = response.json()
    except (requests.RequestException, ValueError):
        return None

    if not isinstance(user, dict) or not re.fullmatch(r"[1-9][0-9]*", str(user.get("id", ""))):
        return None
    return {
        "id": str(user.get("id", "")),
        "username": user.get("username", ""),
        "email": user.get("email", ""),
        "thumb": user.get("thumb", ""),
    }



def plex_user_has_server_access(auth_token):
    try:
        response = requests.get(
            f"{PLEX_API_BASE}/resources",
            headers={
                **plex_headers(),
                "X-Plex-Token": auth_token,
            },
            timeout=10,
        )
        response.raise_for_status()
        resources = response.json()
    except (requests.RequestException, ValueError):
        return False

    return any(
        resource.get("clientIdentifier") == connection_value('PLEX_MACHINE_IDENTIFIER')
        and "server" in resource.get("provides", "").split(",")
        for resource in resources
    )



@app.before_request
def require_keep_auth():
    if request.path == '/api/v1' or request.path.startswith('/api/v1/'):
        return None  # The supported API independently authenticates Bearer keys.
    public_paths = {
        "/health",
        "/login",
        "/logout",
        "/auth/plex",
        "/auth/plex/callback",
        "/auth/local",
        "/auth/local/forgot",
        "/api/webhooks/maintainerr",
    }

    if request.path == "/setup" and not owner_id():
        return None
    if (request.path in public_paths or request.path.startswith("/auth/local/setup/")
            or request.path.startswith("/static/")):
        return None

    if not owner_id():
        return redirect("/setup")
    user = session.get("plex_user")
    if not user:
        return redirect(url_for("login"))
    with closing(attribution_db()) as db:
        profile = db.execute("SELECT * FROM user_profiles WHERE plex_id = ?",
                             (str(user.get("id") or ""),)).fetchone()
    invalid = not profile or profile["status"] != "active"
    if profile and not plex_account_access_active(profile):
        invalid = True
    stored_version = user.get("session_version")
    if profile and stored_version is not None and profile["session_version"] != stored_version:
        invalid = True
    if invalid:
        session.clear()
        return redirect(url_for("login"))
    if stored_version is None:
        session["plex_user"]["session_version"] = profile["session_version"]
    if user.get("auth_type") == "local":
        session["plex_user"] = local_session_user(profile)
    if request.path == "/" and is_owner() and onboarding.pending():
        return redirect("/setup")



@app.route("/login")
def login():
    if not owner_id():
        return redirect("/setup")
    if session.get("plex_user"):
        return redirect(url_for("home"))

    return render_auth_page(local_login=True)


@app.route("/auth/local/forgot", methods=["GET", "POST"])
def forgot_local_password():
    if not email_enabled():
        return render_auth_page(title="Contact the Keep owner", message="Email is disabled. Ask the owner for a private password reset link.", button_label="Back to sign in", button_url="/login")
    page_options = {
        "title": "Reset password",
        "message": "Enter the email address for your household Keep account.",
        "footnote": "Password reset is available for active household accounts.",
        "forgot_password": True,
    }
    if request.method == "GET":
        return render_auth_page(**page_options)

    limited = persistent_rate_limit("forgot-password", 5, 60 * 60)
    if limited:
        return limited

    csrf_error = require_form_csrf()
    if csrf_error:
        return csrf_error

    email_address = request.form.get("email", "").strip().lower()
    with closing(attribution_db()) as db:
        profile = db.execute("""SELECT * FROM user_profiles
            WHERE auth_type = 'local' AND status = 'active'
              AND password_hash != '' AND lower(email) = ?""",
            (email_address,)).fetchone()

    if profile:
        try:
            issue_local_setup(profile["plex_id"], reset=True)
            log_activity("password-reset-requested", "Requested a password-reset link",
                         actor=dict(profile))
        except Exception:
            app.logger.error("Could not send requested local password reset for %s",
                                 profile["plex_id"])

    return render_auth_page(**page_options, reset_requested=True)


@app.post("/auth/local")
def local_login():
    limited = persistent_rate_limit("local-login", 5, 60)
    if limited:
        return limited
    csrf_error = require_form_csrf()
    if csrf_error:
        return csrf_error
    email_address = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    with closing(attribution_db()) as db:
        profile = db.execute("""SELECT * FROM user_profiles
            WHERE auth_type = 'local' AND lower(email) = ?""", (email_address,)).fetchone()
    candidate_hash = (profile["password_hash"] if profile and profile["password_hash"]
                      else DUMMY_PASSWORD_HASH)
    candidate_password = password if len(password) <= 128 else "invalid-overlength-password"
    try:
        hash_matches = password_hasher.verify(candidate_hash, candidate_password)
    except (VerificationError, InvalidHashError):
        hash_matches = False
    valid = bool(profile and profile["status"] == "active" and hash_matches)
    if not valid:
        return render_auth_page(
            local_login=True,
            error="The email address or password is incorrect.",
        ), 401
    if password_hasher.check_needs_rehash(profile["password_hash"]):
        with closing(attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET password_hash = ? WHERE plex_id = ?",
                       (password_hasher.hash(password), profile["plex_id"]))
            profile = db.execute("SELECT * FROM user_profiles WHERE plex_id = ?",
                                 (profile["plex_id"],)).fetchone()
    session.clear()
    session.permanent = True
    session["plex_user"] = local_session_user(profile)
    with closing(attribution_db()) as db, db:
        db.execute("UPDATE user_profiles SET last_seen_at = CURRENT_TIMESTAMP WHERE plex_id = ?",
                   (profile["plex_id"],))
    log_activity("login", "Signed in with a household account", actor=dict(profile))
    return redirect(url_for("home"))


def render_auth_page(
    title="Keep",
    message="Review what’s leaving Plex and save the things you want to keep.",
    button_label="Sign in with Plex",
    button_url="/auth/plex",
    footnote="Access is limited to users authorized on this Plex server.",
    local_login=False,
    error=None,
    forgot_password=False,
    reset_requested=False,
):
    return render_template_string("""
    <!doctype html>
    <html lang="en" data-theme="{{ theme_mode }}">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
        <script src="/static/keep-theme.js?v={{ app_version }}"></script>
        <meta name="theme-color" content="#f5a623">
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-title" content="Keep">
        <link rel="icon" type="image/svg+xml" href="/static/keep-icon.svg?v=20260907-2">
        <link rel="icon" type="image/png" sizes="32x32" href="/static/favicon-32.png?v=20260907-2">
        <link rel="apple-touch-icon" sizes="180x180" href="/static/apple-touch-icon.png?v=20260907-2">
        <link rel="manifest" href="/static/site.webmanifest">
        <title>{{ title }} · Keep</title>
        <style>
          :root {
            --background: #090a0d;
            --surface: rgba(27, 29, 35, 0.78);
            --border: rgba(255, 255, 255, 0.08);
            --text: #f5f6f7;
            --muted: #969ba6;
            --accent: #f5a623;
            --accent-hover: #ffb638;
          }

          * {
            box-sizing: border-box;
          }

          html {
            background: var(--background);
          }

          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            padding: 24px;
            font-family:
              -apple-system,
              BlinkMacSystemFont,
              "Segoe UI",
              Helvetica,
              Arial,
              sans-serif;
            color: var(--text);
            background:
              radial-gradient(circle at 15% -10%, rgba(245, 166, 35, 0.14), transparent 32rem),
              radial-gradient(circle at 85% 0%, rgba(92, 82, 255, 0.08), transparent 30rem),
              var(--background);
          }

          .login-card {
            width: min(430px, 100%);
            padding: 38px 34px 34px;
            border: 1px solid var(--border);
            border-radius: 24px;
            background: var(--surface);
            backdrop-filter: blur(20px);
            box-shadow:
              0 24px 70px rgba(0, 0, 0, 0.34),
              inset 0 1px 0 rgba(255, 255, 255, 0.04);
            text-align: center;
          }

          .brand-mark {
            width: 62px;
            height: 62px;
            margin: 0 auto 20px;
            display: grid;
            place-items: center;
            border-radius: 18px;
            background:
              linear-gradient(145deg, rgba(255, 190, 82, 1), rgba(231, 135, 18, 1));
            color: #111;
            font-size: 32px;
            font-weight: 900;
            box-shadow:
              0 12px 34px rgba(245, 166, 35, 0.24),
              inset 0 1px 0 rgba(255, 255, 255, 0.4);
          }

          h1 {
            margin: 0;
            font-size: 38px;
            line-height: 1;
            letter-spacing: -0.045em;
          }

          .subtitle {
            margin: 12px auto 28px;
            max-width: 320px;
            color: var(--muted);
            font-size: 15px;
            line-height: 1.55;
          }

          .plex-button {
            width: 100%;
            min-height: 48px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: 12px;
            background: linear-gradient(180deg, var(--accent-hover), var(--accent));
            color: #17120a;
            font-size: 14px;
            font-weight: 800;
            letter-spacing: 0.03em;
            text-decoration: none;
            box-shadow:
              0 8px 22px rgba(245, 166, 35, 0.2),
              inset 0 1px 0 rgba(255,255,255,0.42);
            transition:
              transform 120ms ease,
              filter 120ms ease;
          }

          .plex-button:hover {
            filter: brightness(1.04);
          }

          .plex-button:active {
            transform: scale(0.985);
          }

          .footnote {
            margin-top: 20px;
            color: var(--muted);
            font-size: 12px;
            line-height: 1.45;
          }

          .divider { display:flex; align-items:center; gap:12px; margin:22px 0;
            color:var(--muted); font-size:11px; font-weight:800; letter-spacing:.08em; }
          .divider::before,.divider::after { content:""; flex:1; height:1px; background:var(--border); }
          .local-form { display:grid; gap:11px; text-align:left; }
          .local-form label { color:var(--muted); font-size:12px; font-weight:700; }
          .local-form input { width:100%; margin-top:6px; padding:12px 13px; border:1px solid var(--border);
            border-radius:10px; background:#121318; color:var(--text); font:inherit; }
          .local-form input:focus { outline:2px solid rgba(245,166,35,.3); border-color:var(--accent); }
          .local-button { width:100%; min-height:46px; margin-top:3px; border:1px solid var(--border);
            border-radius:11px; background:rgba(255,255,255,.055); color:var(--text);
            font:800 13px/1 inherit; cursor:pointer; }
          .forgot-link { margin-top:1px; text-align:right; }
          .forgot-link a,.back-link { color:var(--accent); font-size:12px; font-weight:700;
            text-decoration:none; }
          .forgot-link a:hover,.back-link:hover { text-decoration:underline; }
          .success { margin:0 0 18px; padding:12px 13px; border:1px solid rgba(108,213,148,.28);
            border-radius:10px; background:rgba(108,213,148,.08); color:#b8f2ce;
            font-size:13px; line-height:1.5; text-align:left; }
          .error { margin:0 0 15px; padding:11px 12px; border:1px solid rgba(255,118,118,.3);
            border-radius:10px; background:rgba(255,118,118,.08); color:#ffb0b0;
            font-size:12px; line-height:1.4; text-align:left; }
        </style>
<link rel="stylesheet" href="/static/keep-ui.css?v={{ app_version }}">
<link rel="stylesheet" href="/static/keep-theme.css?v={{ app_version }}">
<script defer src="/static/keep-toast.js?v=2.4.6"></script>
<script defer src="/static/keep-interactions.js?v={{ app_version }}"></script>
      </head>
      <body class="auth-ui">
        <main class="login-card">
          <img class="brand-mark" src="/static/keep-icon.svg?v=20260907-2" alt="Keep" width="52" height="52">
          <h1>{{ title }}</h1>
          <p class="subtitle">
            {{ message }}
          </p>
          {% if error %}<div class="error" role="alert">{{ error }}</div>{% endif %}
          {% if forgot_password %}
            {% if reset_requested %}
              <div class="success" role="status">If an active household account exists for that email address, a password-reset link is on its way.</div>
              <a class="plex-button" href="/login">Back to sign in</a>
            {% else %}
              <form class="local-form" method="post" action="/auth/local/forgot">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <label>Email address<input type="email" name="email" autocomplete="email" required autofocus></label>
                <button class="local-button" type="submit">Send reset link</button>
              </form>
              <p class="footnote"><a class="back-link" href="/login">Back to sign in</a></p>
            {% endif %}
          {% else %}
          {% if button_url == '/auth/plex' %}
          <form method="post" action="/auth/plex"><input type="hidden" name="csrf_token" value="{{ csrf_token }}"><button class="plex-button" type="submit">{{ button_label }}</button></form>
          {% else %}<a class="plex-button" href="{{ button_url }}">{{ button_label }}</a>{% endif %}
          {% if local_login %}
          <div class="divider">OR HOUSEHOLD SIGN-IN</div>
          <form class="local-form" method="post" action="/auth/local">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label>Email address<input type="email" name="email" autocomplete="username" required></label>
            <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
            <div class="forgot-link"><a href="/auth/local/forgot">Forgot your password?</a></div>
            <button class="local-button" type="submit">Sign in to Keep</button>
          </form>
          {% endif %}
          <p class="footnote">
            {{ footnote }}
          </p>
          {% endif %}
          <footer class="footnote">Keep v{{ app_version }}</footer>
        </main>
      </body>
    </html>
    """, title=title, message=message, button_label=button_label,
        button_url=button_url, footnote=footnote, local_login=local_login,
        error=error, forgot_password=forgot_password, reset_requested=reset_requested,
        csrf_token=get_csrf_token())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def get_email_recipients():
    with closing(attribution_db()) as db:
        return [
            row["email"] for row in db.execute(
                "SELECT email FROM email_recipients WHERE enabled = 1 ORDER BY email COLLATE NOCASE"
            )
        ]


def ensure_recipient_subscriptions(db, email_address):
    db.executemany("""INSERT OR IGNORE INTO recipient_subscriptions
        (email, collection_id, enabled) VALUES (?, ?, 1)""",
        ((email_address, collection_id) for collection_id in recipient_collection_ids()))


def get_recipient_delivery_preferences():
    with closing(attribution_db()) as db:
        rows = db.execute("""SELECT r.email, s.collection_id
            FROM email_recipients r
            JOIN recipient_subscriptions s ON s.email = r.email AND s.enabled = 1
            WHERE r.enabled = 1 ORDER BY r.email COLLATE NOCASE, s.collection_id""").fetchall()
    preferences = {}
    for row in rows:
        preferences.setdefault(row["email"], set()).add(row["collection_id"])
    return preferences


def send_email(to_addresses, subject, html_body, text_body):
    if not email_enabled():
        raise RuntimeError('Email is disabled')
    if not connection_value('SMTP_HOST') or not connection_value('SMTP_FROM'):
        raise RuntimeError('SMTP host and sender must be configured')

    if isinstance(to_addresses, str):
        to_addresses = [to_addresses]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{connection_value('SMTP_SENDER_NAME')} <{connection_value('SMTP_FROM')}>"
    msg["Bcc"] = ", ".join(to_addresses)

    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    import ssl
    transport = smtplib.SMTP_SSL if connection_value('SMTP_SECURITY') == 'ssl' else smtplib.SMTP
    tls_options = {'context': ssl.create_default_context()} if connection_value('SMTP_SECURITY') == 'ssl' else {}
    with transport(connection_value('SMTP_HOST'), int(connection_value('SMTP_PORT')), timeout=20, **tls_options) as smtp:
        if connection_value('SMTP_SECURITY') == 'starttls':
            smtp.starttls(context=ssl.create_default_context())
        if connection_value('SMTP_USER'):
            smtp.login(connection_value('SMTP_USER'), connection_value('SMTP_PASSWORD') or '')
        refused = smtp.send_message(msg)
        if refused:
            raise RuntimeError("SMTP rejected one or more digest recipients")


def send_local_setup_email(profile, token, reset=False):
    setup_url = f"{connection_value('KEEP_URL').rstrip('/')}/auth/local/setup/{token}"
    name = profile["display_name"] or profile["full_name"] or "there"
    subject, body, plain = email_templates.account_email(name, setup_url, reset)
    send_email([profile["email"]], subject, body, plain)


def private_setup_link(token):
    response = app.make_response(render_template("private_setup_link.html",
    link=connection_value('KEEP_URL').rstrip('/') + '/auth/local/setup/' + token))
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


def issue_local_setup(plex_id, reset=False):
    token = secrets.token_urlsafe(32)
    with closing(attribution_db()) as db, db:
        profile = db.execute("""SELECT * FROM user_profiles
            WHERE plex_id = ? AND auth_type = 'local'""", (str(plex_id),)).fetchone()
        if not profile:
            raise LookupError("Local user not found")
        db.execute("""UPDATE user_profiles
            SET invite_token_hash = ?, invite_expires_at = ? WHERE plex_id = ?""",
            (token_digest(token), time.time() + LOCAL_SETUP_SECONDS, str(plex_id)))
    if email_enabled():
        send_local_setup_email(profile, token, reset=reset)
    return token


def render_local_setup_page(profile=None, token="", error=None, complete=False):
    response = app.make_response(render_template_string("""
    <!doctype html><html lang="en" data-theme="{{ theme_mode }}"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1, viewport-fit=cover">
    <script src="/static/keep-theme.js?v={{ app_version }}"></script>
    <meta name="referrer" content="no-referrer"><meta name="theme-color" content="#f5a623">
    <meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="Keep">
    <link rel="icon" type="image/svg+xml" href="/static/keep-icon.svg?v=20260907-2">
    <link rel="icon" type="image/png" sizes="32x32" href="/static/favicon-32.png?v=20260907-2">
    <link rel="apple-touch-icon" sizes="180x180" href="/static/apple-touch-icon.png?v=20260907-2">
    <link rel="manifest" href="/static/site.webmanifest"><title>Set password · Keep</title>
    <style>
      :root{--bg:#090a0d;--surface:rgba(27,29,35,.84);--border:rgba(255,255,255,.09);
        --text:#f5f6f7;--muted:#969ba6;--accent:#f5a623}
      *{box-sizing:border-box} body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;
        color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
        background:radial-gradient(circle at 15% -10%,rgba(245,166,35,.14),transparent 32rem),var(--bg)}
      main{width:min(440px,100%);padding:36px 34px;border:1px solid var(--border);border-radius:24px;
        background:var(--surface);box-shadow:0 24px 70px rgba(0,0,0,.34)}
      .mark{width:58px;height:58px;display:grid;place-items:center;border-radius:17px;background:var(--accent);
        color:#111;font-size:30px;font-weight:900} h1{margin:22px 0 8px;font-size:30px;letter-spacing:-.04em}
      p{margin:0 0 22px;color:var(--muted);font-size:14px;line-height:1.55}
      form{display:grid;gap:13px} label{color:var(--muted);font-size:12px;font-weight:750}
      input{width:100%;margin-top:6px;padding:13px;border:1px solid var(--border);border-radius:10px;
        background:#121318;color:var(--text);font:inherit} input:focus{outline:2px solid rgba(245,166,35,.3);border-color:var(--accent)}
      button,.button{min-height:47px;display:flex;align-items:center;justify-content:center;border:0;border-radius:11px;
        background:var(--accent);color:#17120a;font:800 13px/1 inherit;text-decoration:none;cursor:pointer}
      .error{margin-bottom:16px;padding:11px;border:1px solid rgba(255,118,118,.3);border-radius:10px;
        color:#ffb0b0;background:rgba(255,118,118,.08);font-size:12px}
    </style>
<link rel="stylesheet" href="/static/keep-ui.css?v={{ app_version }}">
<script defer src="/static/keep-toast.js?v=2.4.6"></script>
<link rel="stylesheet" href="/static/keep-theme.css?v={{ app_version }}">
<script defer src="/static/keep-interactions.js?v={{ app_version }}"></script></head><body class="setup-ui"><main><img class="mark" src="/static/keep-icon.svg?v=20260907-2" alt="Keep" width="52" height="52">
      {% if complete %}<h1>Password saved</h1><p>Your Keep account is ready.</p>
        <a class="button" href="/">Open Keep</a>
      {% elif profile %}<h1>Choose your password</h1>
        <p>Set a password for {{ profile.display_name or profile.full_name or profile.email }}.
        Use at least {{ minimum }} characters.</p>
        {% if error %}<div class="error" role="alert">{{ error }}</div>{% endif %}
        <form method="post">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          <label>New password<input type="password" name="password" autocomplete="new-password" required minlength="{{ minimum }}" maxlength="128"></label>
          <label>Confirm password<input type="password" name="confirm_password" autocomplete="new-password" required minlength="{{ minimum }}" maxlength="128"></label>
          <button type="submit">Save password</button>
        </form>
      {% else %}<h1>Link unavailable</h1><p>This setup link is invalid or has expired. Ask the Keep owner to send a new one.</p>
        <a class="button" href="/login">Back to sign in</a>{% endif %}
      <footer style="margin-top:22px;color:var(--muted);font-size:12px;text-align:center">Keep v{{ app_version }}</footer>
    </main></body></html>""", profile=profile, token=token, error=error, complete=complete,
        minimum=PASSWORD_MIN_LENGTH, csrf_token=get_csrf_token()))
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.route("/auth/local/setup/<token>", methods=["GET", "POST"])
def local_setup(token):
    limited = persistent_rate_limit("password-setup", 10, 60)
    if limited:
        return limited
    profile = get_local_user_by_token(token)
    if not profile:
        return render_local_setup_page(), 400
    if request.method == "GET":
        return render_local_setup_page(profile, token)
    csrf_error = require_form_csrf()
    if csrf_error:
        return csrf_error
    password = request.form.get("password", "")
    confirmation = request.form.get("confirm_password", "")
    if password != confirmation:
        return render_local_setup_page(profile, token, "The passwords do not match."), 400
    if not PASSWORD_MIN_LENGTH <= len(password) <= 128:
        return render_local_setup_page(
            profile, token, f"Use between {PASSWORD_MIN_LENGTH} and 128 characters."
        ), 400
    new_hash = password_hasher.hash(password)
    with closing(attribution_db()) as db, db:
        changed = db.execute("""UPDATE user_profiles SET password_hash = ?, status = 'active',
            invite_token_hash = NULL, invite_expires_at = NULL,
            session_version = session_version + 1, last_seen_at = CURRENT_TIMESTAMP
            WHERE plex_id = ? AND invite_token_hash = ? AND invite_expires_at > ?""",
            (new_hash, profile["plex_id"], token_digest(token), time.time())).rowcount
        if not changed:
            return render_local_setup_page(), 400
        profile = db.execute("SELECT * FROM user_profiles WHERE plex_id = ?",
                             (profile["plex_id"],)).fetchone()
    session.clear()
    session.permanent = True
    session["plex_user"] = local_session_user(profile)
    log_activity("password-changed", "Set or changed the household account password",
                 actor=dict(profile))
    return render_local_setup_page(complete=True)

def build_media_added_email(item, collection_name, days_left, keep_url):
    return build_digest_email([_single_email_item(item, collection_name, days_left)], keep_url)


def build_media_warning_email(item, collection_name, days_left, keep_url):
    return build_digest_email([_single_email_item(item, collection_name, days_left, urgent=True)], keep_url)


def _single_email_item(item, collection_name, days_left, urgent=False):
    media = item.get("mediaData") or {}
    return {"collection": collection_name, "title": media.get("title") or "Untitled",
            "year": media.get("year"), "poster_url": item.get("image_path") or "",
            "days": days_left, "urgent": urgent}


def get_collection_media(collection_id):
    cache_key = (connection_value('MAINTAINERR_URL'), str(collection_id))
    cache = g.setdefault('collection_media', {}) if has_request_context() and request.method == 'GET' else {}
    if cache_key in cache:
        return cache[cache_key]
    media_url = f"{connection_value('MAINTAINERR_URL')}/api/collections/media/{collection_id}/content/1"

    media_response = requests.get(media_url, params={"size": 100}, timeout=10)
    media_response.raise_for_status()

    media_data = media_response.json()
    exclusions_data = get_collection_exclusions(collection_id)

    excluded_ids = {
        str(item.get("mediaServerId"))
        for item in exclusions_data.get("items", [])
    }

    media_data["items"] = [
        item
        for item in media_data.get("items", [])
        if str(item.get("mediaServerId")) not in excluded_ids
    ]

    media_data["totalSize"] = len(media_data["items"])
    cache[cache_key] = media_data
    return media_data

def find_collection_item(collection_name, media_server_id):
    collection_id = next(
        (cid for cid, name in get_collections().items() if name == collection_name),
        None,
    )

    if collection_id is None:
        return None, None

    media_items = get_collection_media(collection_id)

    for item in media_items.get("items", []):
        if str(item.get("mediaServerId")) == str(media_server_id):
            return collection_id, item

    return collection_id, None

def get_kept_item_poster(media_server_id):
    try:
        metadata = requests.get(
            f"{connection_value('MAINTAINERR_URL')}/api/media-server/meta/{media_server_id}",
            timeout=10,
        )
        metadata.raise_for_status()
        metadata = metadata.json()

        provider_ids = metadata.get("providerIds", {})
        media_type = metadata.get("type", "movie")
        image_type = "show" if media_type in ("show", "season", "episode") else "movie"

        params = {}
        for provider in ("tmdb", "tvdb", "imdb"):
            values = provider_ids.get(provider) or []
            if values:
                params[f"{provider}Id"] = values[0]
                break

        if not params:
            return None

        image = requests.get(
            f"{connection_value('MAINTAINERR_URL')}/api/metadata/image/{image_type}",
            params=params,
            timeout=10,
        )
        image.raise_for_status()

        return image.json().get("url")
    except requests.RequestException:
        return None


def get_collection_exclusions(collection_id):
    cache_key = (connection_value('MAINTAINERR_URL'), str(collection_id))
    cache = g.setdefault('collection_exclusions', {}) if has_request_context() and request.method == 'GET' else {}
    if cache_key in cache:
        return cache[cache_key]
    url = f"{connection_value('MAINTAINERR_URL')}/api/collections/exclusions/{collection_id}/content/1"
    response = requests.get(url, params={"size": 100}, timeout=10)
    response.raise_for_status()
    cache[cache_key] = response.json()
    return cache[cache_key]


def change_maintainerr_exclusion(media_id, collection_id, action):
    response = requests.post(
        f"{connection_value('MAINTAINERR_URL')}/api/rules/exclusion",
        json={
            "mediaId": str(media_id),
            "collectionId": collection_id,
            "action": action,
        },
        timeout=10,
    )
    response.raise_for_status()
    try:
        result = response.json()
    except (TypeError, ValueError):
        result = None
    if isinstance(result, dict) and result.get("code") == 0:
        raise requests.RequestException(result.get("message") or "Maintainerr exclusion action failed")
    return response


def get_collection_delete_after_days(collection_id):
    response = requests.get(
        f"{connection_value('MAINTAINERR_URL')}/api/collections/collection/{collection_id}",
        timeout=10,
    )
    response.raise_for_status()
    return response.json().get("deleteAfterDays")


def calculate_days_left(add_date, delete_after_days):
    if not add_date or delete_after_days is None:
        return None

    try:
        from datetime import datetime, timezone, timedelta
        import math

        added = datetime.fromisoformat(add_date.replace("Z", "+00:00"))
        deletion_date = added + timedelta(days=delete_after_days)
        remaining = (deletion_date - datetime.now(timezone.utc)).total_seconds() / 86400

        return max(0, math.ceil(remaining))
    except (TypeError, ValueError):
        return None


def calculate_removal_date(add_date, delete_after_days):
    if not add_date or delete_after_days is None:
        return None
    try:
        from datetime import timedelta
        added = datetime.fromisoformat(add_date.replace("Z", "+00:00"))
        return (added + timedelta(days=delete_after_days)).date()
    except (TypeError, ValueError):
        return None


def build_review_collections():
    collections = []

    for collection_id, collection_name in get_collections().items():
        data = get_collection_media(collection_id)
        delete_after_days = get_collection_delete_after_days(collection_id)

        items = data.get("items", [])
        for item in items:
            item["days_left"] = calculate_days_left(
                item.get("addDate"),
                delete_after_days,
            )

        collections.append({
            "id": collection_id,
            "name": collection_name,
            "items": items,
        })

    return collections


def build_kept_collections():
    collections = []
    exclusions_by_collection = {
        collection_id: get_collection_exclusions(collection_id).get("items", [])
        for collection_id in get_collections()
    }
    migrate_existing_keep_schedules(exclusions_by_collection)

    with closing(attribution_db()) as db:
        keepers = {(row["collection_id"], row["media_id"]): dict(row)
                   for row in db.execute("SELECT * FROM keep_attribution")}
        schedules = {(row["collection_id"], row["media_id"]): dict(row)
                     for row in db.execute("SELECT * FROM keep_schedules")}

    names = get_keeper_names() if keepers else {}
    viewer_id = str((session.get("plex_user") or {}).get("id") or "")
    manage_any = can_remove_any_keep()
    indefinite_allowed = can_keep_indefinitely()
    for keeper in keepers.values():
        keeper["display_name"] = names.get(keeper["user_id"], keeper["username"])

    now = datetime.now(timezone.utc)
    for collection_id, collection_name in get_collections().items():
        kept_items = exclusions_by_collection[collection_id]

        for item in kept_items:
            key = (str(collection_id), str(item.get("mediaServerId")))
            item["image_path"] = url_for('kept_artwork', media_server_id=str(item.get("mediaServerId")))
            item["keeper"] = keepers.get(key)
            item["kept_by_viewer"] = bool(
                item["keeper"] and item["keeper"]["user_id"] == viewer_id
            )
            item["can_remove"] = manage_any or bool(
                item["kept_by_viewer"]
            )
            schedule = schedules.get(key)
            expires_at = schedule["expires_at"] if schedule else None
            item["keep_is_temporary"] = bool(expires_at)
            item["can_manage"] = bool((manage_any or item["kept_by_viewer"]) and
                                      (expires_at or indefinite_allowed or manage_any))
            if expires_at:
                expiry = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                seconds = max(0, int((expiry - now).total_seconds()))
                item["keep_days_left"] = (seconds + 86399) // 86400
                item["keep_expiry_label"] = f"{expiry.strftime('%B')} {expiry.day}, {expiry.year}"
                next_expiry = max(now, expiry) + timedelta(days=TEMPORARY_KEEP_DAYS)
                available_at = schedule.get("extension_available_at") if schedule else None
                available = (datetime.strptime(available_at, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc) if available_at else None)
                item["keep_can_extend"] = not available or now >= available
                item["keep_extension_available_label"] = (
                    f"{available.strftime('%B')} {available.day}, {available.year}"
                    if available and now < available else ""
                )
            else:
                item["keep_days_left"] = None
                item["keep_expiry_label"] = None
                next_expiry = now + timedelta(days=TEMPORARY_KEEP_DAYS)
                item["keep_can_extend"] = False
                item["keep_extension_available_label"] = ""
            item["keep_next_temporary_label"] = (
                f"{next_expiry.strftime('%B')} {next_expiry.day}, {next_expiry.year}"
            )

        collections.append({
            "id": collection_id,
            "name": collection_name,
            "items": kept_items,
        })

    return collections


@app.get('/kept/artwork/<int:media_server_id>')
def kept_artwork(media_server_id):
    if not session.get('plex_user'):
        return '', 401
    poster = get_kept_item_poster(media_server_id)
    if not poster or not poster.startswith(('https://', 'http://')):
        return '', 404
    response = redirect(poster)
    response.headers['Cache-Control'] = 'private, max-age=300'
    return response


@app.get("/kept", endpoint="kept")
@app.get("/")
def home():
    plex_user = session.get("plex_user")
    if not plex_user:
        return redirect(url_for("login"))
    is_kept_view = request.path == "/kept"

    if is_kept_view:
        collections = build_kept_collections()
    else:
        collections = build_review_collections()

    total_items = sum(
        len(get_collection_media(collection_id).get("items", []))
        for collection_id in get_collections()
    )

    total_kept = sum(
        len(get_collection_exclusions(collection_id).get("items", []))
        for collection_id in get_collections()
    )

    return render_template_string(
        """
<!doctype html>
<html lang="en" data-theme="{{ theme_mode }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <script src="/static/keep-theme.js?v={{ app_version }}"></script>
    <meta name="color-scheme" content="dark">
    <meta name="theme-color" content="#f5a623">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-title" content="Keep">
    <title>Keep</title>
    <link rel="icon" type="image/svg+xml" href="/static/keep-icon.svg?v=20260907-2">
    <link rel="icon" type="image/png" sizes="32x32" href="/static/favicon-32.png?v=20260907-2">
    <link rel="apple-touch-icon" sizes="180x180" href="/static/apple-touch-icon.png?v=20260907-2">
    <link rel="manifest" href="/static/site.webmanifest">

    <style>
        * {
            box-sizing: border-box;
        }

        :root {
            --background: #090a0d;
            --surface: rgba(27, 29, 35, 0.78);
            --surface-hover: rgba(35, 38, 45, 0.94);
            --border: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(255, 255, 255, 0.16);
            --text: #f5f6f7;
            --muted: #969ba6;
            --accent: #f5a623;
            --accent-hover: #ffb638;
            --success: #37d67a;
        }

        html {
            background: var(--background);
        }

        body {
            margin: 0;
            min-height: 100vh;
            font-family:
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                Helvetica,
                Arial,
                sans-serif;
            color: var(--text);
            background:
                radial-gradient(circle at 15% -10%, rgba(245, 166, 35, 0.12), transparent 32rem),
                radial-gradient(circle at 85% 0%, rgba(92, 82, 255, 0.08), transparent 30rem),
                var(--background);
        }

        .page {
            width: min(1500px, 100%);
            margin: 0 auto;
            padding: 54px 34px 80px;
        }

        .hero {
            display: flex;
            align-items: flex-end;
            justify-content: space-between;
            gap: 28px;
            margin-bottom: 52px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .brand-mark {
            width: 52px;
            height: 52px;
            display: grid;
            place-items: center;
            border-radius: 15px;
            background:
                linear-gradient(145deg, rgba(255, 190, 82, 1), rgba(231, 135, 18, 1));
            color: #111;
            font-size: 28px;
            font-weight: 900;
            box-shadow:
                0 10px 30px rgba(245, 166, 35, 0.22),
                inset 0 1px 0 rgba(255, 255, 255, 0.4);
        }

        h1 {
            margin: 0;
            font-size: clamp(34px, 4vw, 48px);
            line-height: 1;
            letter-spacing: -0.045em;
        }

        .subtitle {
            margin: 8px 0 0;
            color: var(--muted);
            font-size: 16px;
            line-height: 1.5;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .user-menu {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 7px 10px;
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 14px;
            background: rgba(255,255,255,0.035);
        }

        .user-avatar {
            width: 34px;
            height: 34px;
            border-radius: 50%;
            overflow: hidden;
            display: grid;
            place-items: center;
            flex: 0 0 auto;
            background: #2a2d35;
            color: #f5f6f7;
            border: 1px solid rgba(255,255,255,0.1);
            font-size: 14px;
            font-weight: 900;
        }

        .user-avatar.fallback {
            background: linear-gradient(145deg, #383d49, #20232a);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 5px 14px rgba(0,0,0,0.22);
            text-shadow: 0 1px 2px rgba(0,0,0,0.45);
        }

        .user-avatar img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            display: block;
        }

        .user-meta {
            min-width: 0;
            line-height: 1.15;
        }

        .user-name {
            max-width: 220px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-size: 13px;
            font-weight: 700;
            color: var(--text);
        }

        .user-links {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .logout-link {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-height: 34px;
            padding: 0 12px;
            margin-left: 0;
            border: 1px solid rgba(255,255,255,0.10);
            border-radius: 10px;
            background: rgba(255,255,255,0.05);
            color: var(--muted);
            font-size: 11px;
            font-weight: 700;
            text-decoration: none;
            white-space: nowrap;
        }

        .logout-link:hover {
            color: var(--text);
            background: rgba(255,255,255,0.08);
        }

        .view-switcher {
            flex-shrink: 0;
            display: inline-flex;
            padding: 4px;
            border: 1px solid var(--border);
            border-radius: 999px;
            background: rgba(255,255,255,0.035);
            backdrop-filter: blur(16px);
        }

        .view-tab {
            appearance: none;
            border: 0;
            border-radius: 999px;
            padding: 8px 12px;
            background: transparent;
            color: var(--muted);
            font: inherit;
            font-size: 14px;
            font-weight: 700;
            text-decoration: none;
            cursor: pointer;
            transition:
                color 140ms ease,
                background 140ms ease;
        }

        .view-tab span {
            margin-left: 4px;
            opacity: 0.8;
        }

        .view-tab.active {
            background: var(--accent);
            color: #111;
        }

        .section-nav {
            position: sticky;
            top: 0;
            z-index: 20;
            display: flex;
            gap: 8px;
            margin: 0 0 16px;
            padding: 12px 40px 12px 0;
            overflow-x: auto;
            scroll-padding-right: 40px;
            background: linear-gradient(
                to bottom,
                rgba(9, 10, 13, 0.98) 70%,
                rgba(9, 10, 13, 0)
            );
            backdrop-filter: blur(14px);
            scrollbar-width: none;
        }

        .section-nav::-webkit-scrollbar {
            display: none;
        }

        .section-nav a {
            flex: 0 0 auto;
            padding: 9px 13px;
            border: 1px solid var(--border);
            border-radius: 999px;
            background: rgba(255,255,255,0.035);
            color: var(--muted);
            font-size: 13px;
            font-weight: 700;
            text-decoration: none;
            transition:
                color 140ms ease,
                border-color 140ms ease,
                background 140ms ease;
        }

        .section-nav a:hover {
            color: var(--text);
            border-color: var(--border-hover);
            background: rgba(255,255,255,0.07);
        }

        .media-search {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            margin: 0 0 34px;
        }

        .keep-scope-filter {
            display: inline-flex;
            flex: 0 0 auto;
            gap: 3px;
            padding: 4px;
            border: 1px solid var(--border);
            border-radius: 12px;
            background: rgba(255,255,255,0.035);
        }

        .keep-scope-option {
            min-height: 38px;
            padding: 0 14px;
            border: 0;
            border-radius: 8px;
            background: transparent;
            color: var(--muted);
            font: 700 12px/1 inherit;
            cursor: pointer;
            transition: color 140ms ease, background 140ms ease, box-shadow 140ms ease;
        }

        .keep-scope-option:hover { color: var(--text); }
        .keep-scope-option[aria-pressed="true"] {
            background: #2a2d35;
            color: var(--text);
            box-shadow: 0 1px 5px rgba(0,0,0,.28);
        }

        .search-field {
            position: relative;
            width: min(520px, 100%);
        }

        .search-icon {
            position: absolute;
            left: 15px;
            top: 50%;
            width: 17px;
            height: 17px;
            transform: translateY(-50%);
            color: var(--muted);
            pointer-events: none;
        }

        .search-field input {
            width: 100%;
            min-height: 46px;
            padding: 0 42px;
            border: 1px solid var(--border);
            border-radius: 13px;
            outline: none;
            background: rgba(255,255,255,0.045);
            color: var(--text);
            font: 600 14px/1 inherit;
            transition: border-color 140ms ease, background 140ms ease, box-shadow 140ms ease;
        }

        .search-field input::placeholder { color: var(--muted); }
        .search-field input:focus {
            border-color: rgba(245,166,35,.62);
            background: rgba(255,255,255,0.065);
            box-shadow: 0 0 0 3px rgba(245,166,35,.12);
        }

        .search-status { color: var(--muted); font-size: 12px; font-weight: 700; white-space: nowrap; }
        .search-empty { margin-bottom: 34px; }
        .card[hidden], section[hidden], .search-empty[hidden] { display: none; }

        section {
            scroll-margin-top: 84px;
            margin-bottom: 58px;
        }

        section + section {
            padding-top: 34px;
            border-top: 1px solid rgba(255, 255, 255, 0.09);
        }

        .section-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 18px;
        }

        h2 {
            margin: 0;
            font-size: 21px;
            letter-spacing: -0.02em;
        }

        .count {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 28px;
            height: 25px;
            padding: 0 8px;
            border-radius: 999px;
            background: rgba(255,255,255,0.07);
            color: var(--muted);
            font-size: 12px;
            font-weight: 700;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
            gap: 22px;
        }

        .card {
            position: relative;
            overflow: hidden;
            min-width: 0;
            border: 1px solid var(--border);
            border-radius: 16px;
            background: var(--surface);
            box-shadow:
                0 14px 35px rgba(0, 0, 0, 0.24),
                inset 0 1px 0 rgba(255,255,255,0.025);
            backdrop-filter: blur(18px);
            transition:
                transform 180ms ease,
                border-color 180ms ease,
                background 180ms ease,
                box-shadow 180ms ease,
                opacity 220ms ease;
        }

        @media (hover: hover) {
            .card:hover {
                transform: translateY(-5px);
                border-color: var(--border-hover);
                background: var(--surface-hover);
                box-shadow:
                    0 20px 45px rgba(0, 0, 0, 0.34),
                    inset 0 1px 0 rgba(255,255,255,0.04);
            }

            .card:hover .poster {
                transform: scale(1.025);
            }
        }

        .poster-wrap {
            position: relative;
            overflow: hidden;
            aspect-ratio: 2 / 3;
            background: #18191d;
        }

        .keeper-badge {
            position: absolute;
            bottom: 10px;
            left: 10px;
            right: 10px;
            padding: 8px 10px;
            border-radius: 12px;
            background: rgba(18, 18, 22, 0.92);
            border: 1px solid rgba(255, 179, 43, 0.45);
            color: #ffd58a;
            font-size: 12px;
            font-weight: 650;
            line-height: 1.4;
            overflow-wrap: anywhere;
            box-shadow: 0 4px 14px rgba(0,0,0,0.35);
        }

        .days-left-badge {
            position: absolute;
            top: 10px;
            right: 10px;
            min-width: 34px;
            height: 34px;
            padding: 0 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 999px;
            background: rgba(18, 18, 22, 0.88);
            border: 1px solid rgba(255,255,255,0.14);
            box-shadow: 0 4px 14px rgba(0,0,0,0.35);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            color: #fff;
            font-size: 14px;
            font-weight: 800;
            line-height: 1;
            z-index: 2;
        }

        .poster {
            width: 100%;
            height: 100%;
            object-fit: cover;
            display: block;
            transition: transform 260ms ease;
        }

        .card-body {
            padding: 14px;
        }

        .title {
            min-height: 2.5em;
            margin-bottom: 5px;
            overflow: hidden;
            color: var(--text);
            font-size: 15px;
            font-weight: 700;
            line-height: 1.25;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
        }

        .year {
            margin-bottom: 13px;
            color: var(--muted);
            font-size: 13px;
        }

        .keep-button {
            width: 100%;
            min-height: 42px;
            border: 0;
            border-radius: 10px;
            background: linear-gradient(180deg, var(--accent-hover), var(--accent));
            color: #17120a;
            font-size: 13px;
            font-weight: 800;
            letter-spacing: 0.055em;
            cursor: pointer;
            box-shadow:
                0 6px 18px rgba(245, 166, 35, 0.18),
                inset 0 1px 0 rgba(255,255,255,0.42);
            transition:
                transform 120ms ease,
                filter 120ms ease,
                opacity 120ms ease;
        }

        .keep-button:hover {
            filter: brightness(1.06);
        }

        .keep-button:active {
            transform: scale(0.975);
        }

        .keep-button:disabled {
            opacity: 0.58;
            cursor: default;
            filter: none;
        }

        .empty {
            padding: 28px;
            border: 1px dashed rgba(255,255,255,0.09);
            border-radius: 14px;
            color: var(--muted);
            background: rgba(255,255,255,0.025);
            font-size: 14px;
        }

        .pull-refresh {
            position: fixed;
            top: 8px;
            left: 50%;
            z-index: 200;
            transform: translate(-50%, -70px);
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 9px 13px;
            border: 1px solid var(--border);
            border-radius: 999px;
            background: rgba(20, 21, 25, 0.94);
            color: var(--muted);
            backdrop-filter: blur(16px);
            font-size: 13px;
            font-weight: 700;
            transition: transform 160ms ease, color 160ms ease;
            pointer-events: none;
        }

        .pull-refresh.visible {
            transform: translate(-50%, 0);
        }

        .pull-refresh.ready {
            color: var(--text);
        }

        .pull-refresh-icon {
            display: inline-block;
            transition: transform 160ms ease;
        }

        .pull-refresh.ready .pull-refresh-icon {
            transform: rotate(180deg);
        }

        .toast {
            position: fixed;
            left: 50%;
            bottom: 28px;
            z-index: 100;
            transform: translate(-50%, 20px);
            display: flex;
            align-items: center;
            gap: 10px;
            max-width: calc(100vw - 32px);
            padding: 12px 17px;
            border: 1px solid rgba(55, 214, 122, 0.25);
            border-radius: 999px;
            background: rgba(20, 31, 25, 0.94);
            color: #dff9e9;
            box-shadow: 0 18px 50px rgba(0,0,0,0.45);
            backdrop-filter: blur(18px);
            font-size: 14px;
            font-weight: 600;
            opacity: 0;
            pointer-events: none;
            transition: opacity 180ms ease, transform 180ms ease;
        }

        .toast.visible {
            opacity: 1;
            transform: translate(-50%, 0);
        }

        .toast-check {
            color: var(--success);
            font-weight: 900;
        }

        .card.removing {
            opacity: 0;
            transform: scale(0.94);
        }

        @media (max-width: 700px) {
            .section-nav {
                gap: 6px;
                padding-right: 0;
                justify-content: center;
            }

            .section-nav a {
                padding: 8px 10px;
                font-size: 12px;
            }

            .media-search { display: block; margin-bottom: 28px; }
            .keep-scope-filter { margin-bottom: 10px; }
            .search-field { width: 100%; }
            .search-status { min-height: 16px; margin: 8px 2px 0; }

            .page {
                padding: 28px 16px 120px;
            }

            .header-actions {
                display: block;
                width: 100%;
            }

            .user-menu {
                width: 100%;
                max-width: 100%;
                margin-top: 18px;
                padding: 6px 9px;
                display: grid;
                grid-template-columns: auto minmax(0, 1fr);
                gap: 8px 10px;
            }

            .user-links {
                grid-column: 1 / -1;
                width: 100%;
                gap: 8px;
            }

            .user-avatar {
                width: 30px;
                height: 30px;
                font-size: 12px;
            }

            .user-name {
                max-width: 100%;
                font-size: 12px;
            }

            .logout-link {
                flex: 1 1 0;
                min-width: 0;
                min-height: 36px;
                padding: 0 8px;
                font-size: 11px;
            }

            .view-switcher {
                position: fixed;
                right: 16px;
                bottom: calc(30px + env(safe-area-inset-bottom));
                z-index: 180;
                margin: 0;
                background: rgba(24,24,28,0.88);
                backdrop-filter: blur(18px);
                -webkit-backdrop-filter: blur(18px);
                box-shadow: 0 10px 30px rgba(0,0,0,0.4);
            }

            .hero {
                display: block;
                margin-bottom: 38px;
            }

            .brand {
                align-items: flex-start;
            }

            .brand-mark {
                width: 46px;
                height: 46px;
                border-radius: 13px;
                font-size: 24px;
            }

            .subtitle {
                max-width: 280px;
                font-size: 14px;
            }

            .summary {
                display: inline-flex;
                margin-top: 20px;
            }

            section {
                margin-bottom: 42px;
            }

            h2 {
                font-size: 19px;
            }

            .grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 12px;
            }

            .card {
                border-radius: 13px;
            }

            .card-body {
                padding: 10px;
            }

            .title {
                min-height: 2.4em;
                font-size: 14px;
            }

            .year {
                margin-bottom: 10px;
                font-size: 12px;
            }

            .keep-button {
                min-height: 44px;
                font-size: 13px;
            }
        }

        @media (max-width: 370px) {
            .grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 9px;
            }

            .page {
                padding-left: 12px;
                padding-right: 12px;
            }
        }
    </style>
<link rel="stylesheet" href="/static/keep-ui.css?v={{ app_version }}">
<script defer src="/static/keep-toast.js?v=2.6.0"></script>
<script defer src="/static/keep-interactions.js?v={{ app_version }}"></script>
<script defer src="/static/keep-duration.js?v=2.6.0"></script>
<style>
@media (prefers-reduced-motion: no-preference) {
    @view-transition { navigation: auto; }
}
</style>
{% include 'shared_assets.html' %}
</head>

<body class="library-ui" data-csrf="{{ csrf_token }}">
<script defer src="/static/keep-pull-refresh.js?v=2.3.1"></script>
<script defer src="/static/keep-whats-new.js?v={{ app_version }}"></script>
    <a class="skip-link" href="#main-content">Skip to content</a>
    <main class="page" id="main-content" tabindex="-1">
        {% include 'shared_header.html' %}
        <div class="browse-controls">

        {% from 'shared_category_nav.html' import category_nav %}
        {{ category_nav(collections, 'collection') }}
        </div>

        <div class="media-search" role="search">
            {% if is_kept_view %}
            <div class="keep-scope-filter" role="group" aria-label="Filter kept titles">
                <button type="button" class="keep-scope-option" data-keep-scope="all" aria-pressed="true">All Keeps</button>
                <button type="button" class="keep-scope-option" data-keep-scope="mine" aria-pressed="false">My Keeps</button>
            </div>
            {% endif %}
            <div class="search-field">
                <svg class="search-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <circle cx="11" cy="11" r="6.5" stroke="currentColor" stroke-width="2"></circle>
                    <path d="m16 16 4 4" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>
                </svg>
                <input id="media-search" type="search"
                    placeholder="Search {{ 'kept' if is_kept_view else 'leaving' }} movies and shows"
                    aria-label="Search {{ 'kept' if is_kept_view else 'leaving' }} movies and shows"
                    autocomplete="off" spellcheck="false">
                <button id="search-clear" class="search-clear" type="button" aria-label="Clear search" hidden><svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="currentColor"/><path d="m7 7 6 6m0-6-6 6" fill="none" stroke="var(--surface)" stroke-width="1.7" stroke-linecap="round"/></svg></button>
            </div>
            <div id="search-status" class="search-status" aria-live="polite"></div>
        </div>
        <div id="search-empty" class="empty search-empty" hidden>
            No movies or shows match your search.
        </div>

        <div class="media-view active">
            {% for collection in collections %}
            <section id="collection-{{ collection.id }}">
                <div class="section-header">
                    <h2>
                        {% if is_kept_view %}
                            {{ collection.name
                                | replace(" Leaving Plex Soon", " Kept") }}
                        {% else %}
                            {{ collection.name }}
                        {% endif %}
                    </h2>
                    <span class="count">{{ collection["items"]|length }}</span>
                </div>

                {% if collection["items"] %}
                <div class="grid">
                    {% for item in collection["items"] %}
                    <article class="card"{% if is_kept_view %} data-kept-by-viewer="{{ 'true' if item.kept_by_viewer else 'false' }}"{% endif %}>
                        <div class="poster-wrap{% if not item.image_path %} poster-unavailable{% endif %}">
                            <button class="title-details-trigger" type="button" data-details-url="{{ url_for('get_title_details', source='kept' if is_kept_view else 'leaving', item_id=item.mediaServerId, collection=collection.id) }}" aria-label="Details for {{ item.mediaData.title }}" aria-haspopup="dialog"></button>
                            <span class="poster-placeholder" aria-hidden="true"><span>Artwork unavailable</span></span>
                            {% if item.image_path %}
                            <img
                                class="poster"
                                src="{{ item.image_path }}"
                                alt="{{ item.mediaData.title }}"
                                loading="lazy"
                                decoding="async"
                            >
                            {% endif %}

                            {% if is_kept_view %}
                            <div class="keeper-badge">
                                {% if item.keeper %}
                                Kept by {{ item.keeper.display_name }}
                                {% else %}
                                Keeper not recorded
                                {% endif %}
                            </div>
                            {% if item.keep_is_temporary %}
                            <div class="days-left-badge keep-policy-badge"
                                 aria-label="{{ item.keep_days_left }} days remaining. Expires {{ item.keep_expiry_label }}."
                                 title="Expires {{ item.keep_expiry_label }}">
                                {{ item.keep_days_left }}d
                            </div>
                            {% else %}
                            <div class="days-left-badge keep-policy-badge indefinite"
                                 aria-label="Kept indefinitely" title="Kept indefinitely">
                                <span aria-hidden="true">∞</span>
                            </div>
                            {% endif %}
                            {% endif %}
                            {% if not is_kept_view and item.days_left is not none %}
                            <div class="days-left-badge" aria-label="{{ item.days_left }} days remaining">
                                {{ item.days_left }}d
                            </div>
                            {% endif %}
                        </div>

                        <div class="card-body">
                            <div class="title"><button class="title-details-name" type="button" data-details-url="{{ url_for('get_title_details', source='kept' if is_kept_view else 'leaving', item_id=item.mediaServerId, collection=collection.id) }}" aria-haspopup="dialog">{{ item.mediaData.title }}</button></div>
                            <div class="year">{{ item.mediaData.year or "" }}</div>

                            {% if is_kept_view %}
                            {% if item.can_manage %}
                            <div class="keep-policy-actions">
                                <button type="button" class="keep-manage-button"
                                        data-media-id="{{ item.mediaServerId }}"
                                        data-collection-id="{{ collection.id }}"
                                        data-is-temporary="{{ 'true' if item.keep_is_temporary else 'false' }}"
                                        data-days-left="{{ item.keep_days_left if item.keep_is_temporary else '' }}"
                                        data-expiry-label="{{ item.keep_expiry_label or '' }}"
                                        data-next-temporary-label="{{ item.keep_next_temporary_label }}"
                                        data-can-extend="{{ 'true' if item.keep_can_extend else 'false' }}"
                                        data-extension-available-label="{{ item.keep_extension_available_label }}"
                                        aria-haspopup="dialog" aria-controls="manage-keep-dialog">
                                    MANAGE KEEP
                                </button>
                            </div>
                            {% endif %}
                            {% if item.can_remove %}
                            <button
                                class="keep-button remove-kept-button"
                                data-exclusion-id="{{ item.id }}"
                                data-media-id="{{ item.mediaServerId }}"
                                data-collection-id="{{ collection.id }}"
                            >
                                REMOVE FROM KEPT
                            </button>
                            {% endif %}
                            {% else %}
                            <button
                                class="keep-button new-keep-button"
                                data-media-id="{{ item.mediaServerId }}"
                                data-collection-id="{{ collection.id }}"
                                {% if not capabilities.keep_indefinitely %}data-direct-temporary="true"{% endif %}
                                {% if capabilities.keep_indefinitely %}
                                aria-haspopup="dialog"
                                aria-controls="keep-duration-dialog"
                                {% endif %}
                            >
                                KEEP
                            </button>
                            {% endif %}
                        </div>
                    </article>
                    {% endfor %}
                </div>
                {% else %}
                <div class="empty">
                    {% if is_kept_view %}
                    No titles are currently kept in this library.
                    {% else %}
                    No titles are currently in Leaving for this library.
                    {% endif %}
                </div>
                {% endif %}
            </section>
            {% endfor %}
        </div>
    </main>

    {% if capabilities.keep_indefinitely %}
    <dialog id="keep-duration-dialog" class="welcome-dialog keep-duration-dialog"
            aria-labelledby="keep-duration-title" aria-describedby="keep-duration-description"
            data-csrf="{{ csrf_token }}">
        <button type="button" class="welcome-close" aria-label="Cancel keep">×</button>
        <div class="dialog-eyebrow">Choose protection</div>
        <h2 id="keep-duration-title" tabindex="-1">How long should Keep protect this?</h2>
        <p id="keep-duration-description" class="welcome-intro">
            A 30-day Keep protects this title. When it expires, the title may return to Leaving if it still meets the library’s rules.
        </p>
        <div class="keep-duration-options">
            <button type="button" class="keep-duration-option recommended" data-duration="temporary">
                <span><strong>Keep for 30 days</strong><small>Recommended · expires automatically</small></span>
                <span aria-hidden="true">→</span>
            </button>
            {% if capabilities.keep_indefinitely %}
            <button type="button" class="keep-duration-option" data-duration="indefinite">
                <span><strong>Keep indefinitely</strong><small>Protected until someone removes the keep</small></span>
                <span aria-hidden="true">→</span>
            </button>
            {% endif %}
        </div>
        <p class="welcome-error" role="alert" hidden>Couldn’t protect this title. Please try again.</p>
        <button type="button" class="keep-duration-cancel">Cancel</button>
    </dialog>
    {% endif %}

    <dialog id="manage-keep-dialog" class="welcome-dialog keep-duration-dialog"
            aria-labelledby="manage-keep-title" aria-describedby="manage-keep-description"
            data-csrf="{{ csrf_token }}">
        <button type="button" class="welcome-close" aria-label="Cancel keep changes">×</button>
        <div class="dialog-eyebrow">Manage keep</div>
        <h2 id="manage-keep-title" tabindex="-1">Manage this keep</h2>
        <p id="manage-keep-description" class="welcome-intro"></p>
        <div class="keep-duration-options">
            <button type="button" class="keep-duration-option" data-duration="temporary">
                <span><strong data-option-title>Extend by 30 days</strong><small data-option-detail></small></span>
                <span aria-hidden="true">→</span>
            </button>
            {% if capabilities.keep_indefinitely %}
            <button type="button" class="keep-duration-option" data-duration="indefinite">
                <span><strong>Keep indefinitely</strong><small data-option-detail>Protected until someone removes the keep</small></span>
                <span aria-hidden="true">→</span>
            </button>
            {% endif %}
        </div>
        <p class="welcome-error" role="alert" hidden>Couldn’t update this keep. Please try again.</p>
        <button type="button" class="keep-duration-cancel">Cancel</button>
    </dialog>

    {% include 'shared_whats_new.html' %}

    <button id="back-to-top" class="back-to-top" type="button" aria-label="Back to top" title="Back to top" disabled>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m6 11 6-6 6 6M12 5v14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </button>
    <div id="pull-refresh" class="pull-refresh">
        <span class="pull-refresh-icon">↓</span>
        <span id="pull-refresh-text">Pull to refresh</span>
    </div>

    <div id="toast" class="toast" role="status" aria-live="polite" aria-atomic="true">
        <span class="toast-check">✓</span>
        <span id="toast-message">Protected</span>
    </div>

    <script>
        let countsRequest = null;
        let countsGeneration = 0;

        const mediaSearch = document.getElementById("media-search");
        const searchClear = document.getElementById("search-clear");
        const searchStatus = document.getElementById("search-status");
        const searchEmpty = document.getElementById("search-empty");
        const keepScopeButtons = [...document.querySelectorAll("[data-keep-scope]")];
        let keepScope = "all";

        function applyMediaSearch() {
            searchClear.hidden = mediaSearch.value.length === 0;
            const query = mediaSearch.value.trim().toLocaleLowerCase();
            const myKeeps = keepScope === "mine";
            const filtering = Boolean(query) || myKeeps;
            let totalMatches = 0;
            document.querySelectorAll(".media-view section").forEach((section) => {
                const cards = [...section.querySelectorAll(".card")];
                let sectionMatches = 0;
                cards.forEach((card) => {
                    const title = card.querySelector(".title")?.textContent || "";
                    const year = card.querySelector(".year")?.textContent || "";
                    const matchesSearch = !query || `${title} ${year}`.toLocaleLowerCase().includes(query);
                    const matchesScope = !myKeeps || card.dataset.keptByViewer === "true";
                    const matches = matchesSearch && matchesScope;
                    card.hidden = !matches;
                    if (matches) sectionMatches += 1;
                });
                section.hidden = filtering && sectionMatches === 0;
                const count = section.querySelector(".count");
                if (count) count.textContent = filtering ? sectionMatches : cards.length;
                totalMatches += sectionMatches;
            });
            searchEmpty.hidden = !filtering || totalMatches > 0;
            searchEmpty.textContent = myKeeps
                ? (query ? "No titles in My Keeps match your search." : "You haven’t kept any titles yet.")
                : "No movies or shows match your search.";
            searchStatus.textContent = filtering
                ? `${totalMatches} ${totalMatches === 1 ? "title" : "titles"}${myKeeps ? " in My Keeps" : " found"}`
                : "";
        }

        mediaSearch.addEventListener("input", applyMediaSearch);
        searchClear.addEventListener("click", () => {
            mediaSearch.value = "";
            applyMediaSearch();
            mediaSearch.focus({ preventScroll: true });
        });
        window.addEventListener("pageshow", applyMediaSearch);
        keepScopeButtons.forEach((button) => {
            button.addEventListener("click", () => {
                keepScope = button.dataset.keepScope;
                keepScopeButtons.forEach((option) => {
                    option.setAttribute("aria-pressed", String(option === button));
                });
                applyMediaSearch();
            });
        });

        async function refreshCounts(force = false) {
            if (document.hidden && !force) return;
            if (countsRequest && !force) return;
            if (countsRequest) countsRequest.abort();
            const controller = new AbortController();
            countsRequest = controller;
            const generation = ++countsGeneration;
            const timeout = setTimeout(() => controller.abort(), 20000);
            try {
                const response = await fetch("/api/counts", {
                    cache: "no-store",
                    signal: controller.signal
                });
                if (!response.ok || response.redirected) return;
                const counts = await response.json();
                if (generation !== countsGeneration) return;
                if (Number.isInteger(counts.leaving) && Number.isInteger(counts.kept)) {
                    document.getElementById("leaving-total").textContent = counts.leaving;
                    document.getElementById("kept-total").textContent = counts.kept;
                }
            } catch (error) {
                // Keep the last known totals during a temporary network failure.
            } finally {
                clearTimeout(timeout);
                if (countsRequest === controller) countsRequest = null;
            }
        }

        setInterval(refreshCounts, 30000);
        document.addEventListener("visibilitychange", () => {
            if (!document.hidden) refreshCounts(true);
        });
        window.addEventListener("focus", () => refreshCounts());
        window.addEventListener("pageshow", (event) => {
            if (event.persisted) refreshCounts();
        });

        window.addEventListener("load", () => {
            setTimeout(() => window.scrollTo(0, 0), 0);
        });

        document.querySelectorAll(".remove-kept-button").forEach((button) => {
            let confirmTimer;

            button.addEventListener("click", async () => {
                const card = button.closest(".card");
                const section = button.closest("section");
                const title = card.querySelector(".title").textContent.trim();

                if (button.dataset.confirming !== "true") {
                    button.dataset.confirming = "true";
                    button.textContent = "REMOVE FOR SURE?";

                    clearTimeout(confirmTimer);
                    confirmTimer = setTimeout(() => {
                        button.dataset.confirming = "false";
                        button.textContent = "REMOVE FROM KEPT";
                    }, 4000);

                    return;
                }

                clearTimeout(confirmTimer);

                const restoreFocus = document.activeElement === button;
                button.disabled = true;
                button.textContent = "REMOVING...";

                try {
                    const response = await fetch("/api/remove-kept", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "X-CSRF-Token": "{{ csrf_token }}"
                        },
                        body: JSON.stringify({
                            exclusionId: Number(button.dataset.exclusionId),
                            collectionId: Number(button.dataset.collectionId)
                        })
                    });

                    if (!response.ok) {
                        throw new Error("Remove request failed");
                    }

                    refreshCounts(true);
                    showToast(`${title} removed from Kept`);

                    await (window.KeepUI?.finishMediaAction || ((card, button, updateLayout) => {
                        card.remove(); updateLayout();
                    }))(card, button, () => {

                        const count = section.querySelector(".count");
                        const remaining = section.querySelectorAll(".card").length;

                        count.textContent = remaining;

                        if (remaining === 0) {
                            const grid = section.querySelector(".grid");

                            if (grid) {
                                grid.outerHTML = `
                                    <div class="empty">
                                        No titles are currently kept in this library.
                                    </div>
                                `;
                            }
                        }
                        applyMediaSearch();
                    }, "Removed ✓", restoreFocus);

                } catch (error) {
                    button.dataset.confirming = "false";
                    button.disabled = false;
                    button.textContent = "REMOVE FROM KEPT";
                    showToast("Could not remove this item from Kept. Please try again.", true);
                }
            });
        });

    </script>
</body>
</html>
        """,
        collections=collections,
        total_items=total_items,
        total_kept=total_kept,
        is_kept_view=is_kept_view,
        plex_user=plex_user,
        owner=is_owner(),
        capabilities=user_capabilities(),
        granted_libraries=granted_library_keys(),
        csrf_token=get_csrf_token(),
    )


def owner_denied():
    return render_auth_page(
        title="Owner access only",
        message="This page is available only to the Keep owner.",
        button_label="Back to Keep",
        button_url=url_for("home"),
        footnote="Your Plex account is signed in, but it cannot manage Keep settings.",
    ), 403


def require_owner():
    return None if is_owner() else owner_denied()


def redirect_to_settings_with_notice(notice_key):
    session["settings_notice"] = notice_key
    section = "email" if notice_key in ("recipient", "subscriptions") else "users"
    return redirect(url_for(f"settings_{section}"))


def redirect_to_settings_with_error(message, email_address=""):
    session["settings_error"] = message
    session["settings_error_email"] = email_address
    return redirect(url_for("settings_email"))


def require_form_csrf():
    expected = session.get("csrf_token")
    supplied = request.form.get("csrf_token", "")
    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        return "Invalid request token", 403
    return None


def current_profile():
    user = session.get("plex_user") or {}
    with closing(attribution_db()) as db:
        return db.execute("SELECT * FROM user_profiles WHERE plex_id = ?",
                          (str(user.get("id") or ""),)).fetchone()


def current_account_session():
    profile = current_profile()
    user = session.get('plex_user') or {}
    return bool(profile and profile['status'] == 'active'
                and profile['session_version'] == user.get('session_version')
                and plex_account_access_active(profile))


# Change this only for a meaningful user-facing announcement, not every app version.
ANNOUNCEMENT_VERSION = "title-status-2.16.0"


def announcement_seen(user_id):
    with closing(attribution_db()) as db:
        row = db.execute("""SELECT version FROM user_feature_acknowledgements
            WHERE user_id = ? AND feature_key = 'whats-new'""", (str(user_id),)).fetchone()
    return bool(row and row['version'] == ANNOUNCEMENT_VERSION)


@app.get('/help')
def help_faq():
    response = app.make_response(render_template('help_faq.html'))
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@app.get('/api/leaving-criteria')
def leaving_criteria():
    try:
        groups = leaving_forecast.read_rules(connection_value, get_collections())
    except (ValueError, requests.RequestException):
        return jsonify(error='Current Leaving criteria are temporarily unavailable.'), 503
    try:
        thresholds = (leaving_forecast.tautulli_thresholds(connection_value)
                      if connection_value('TAUTULLI_URL') and connection_value('TAUTULLI_API_KEY') else {})
    except (ValueError, requests.RequestException):
        thresholds = {}
    result = [{'name': group['name'].replace(' Leaving Plex Soon', ''),
               'kind': group['kind'],
               'paths': leaving_forecast.criteria(group),
               'watched_percent': thresholds.get(group['kind'])}
              for _, group in sorted(groups.items())]
    response = jsonify(result)
    response.headers['Cache-Control'] = 'private, no-store'
    return response


def leaving_membership():
    """Positive, display-only collection matches keyed by stable provider ID."""
    if not connection_value('MAINTAINERR_URL'):
        return {}
    matches = {}
    for cid in get_collections():
        for state, loader in (('leaving', get_collection_media), ('kept', get_collection_exclusions)):
            for row in loader(cid).get('items', []):
                if not isinstance(row, dict):
                    continue
                data = row.get('mediaData') or {}
                providers = (data.get('providerIds') or {}) if isinstance(data, dict) else {}
                media_type = data.get('type') if isinstance(data, dict) else None
                fields = (('movie', 'tmdbId'),) if media_type == 'movie' else (('tv', 'tvdbId'),) if media_type == 'show' else ()
                for kind, field in fields:
                    provider = 'tmdb' if kind == 'movie' else 'tvdb'
                    provider_ids = (providers.get(provider) or []) if isinstance(providers, dict) else []
                    identifier = row.get(field) or (data.get(field) if isinstance(data, dict) else None) or (provider_ids[0] if isinstance(provider_ids, list) and provider_ids else None)
                    if identifier:
                        key = (kind, str(identifier))
                        if key in matches and (matches[key] is None or matches[key]['collection_id'] != cid):
                            matches[key] = None  # Ambiguous across selected libraries.
                        elif key not in matches:
                            matches[key] = {'state': state, 'collection_id': cid, 'row': row}
    return matches


def title_forecast(details, source, item_id, collection_id=None, arr_data=None, membership_row=None):
    """All optional display data is recomputed for the authorized title request."""
    import leaving_forecast as forecast
    result = {'state': None, 'days': None, 'played': None, 'viewer': None,
              'forecast': None, 'reason': '', 'threshold': None, 'rule': None,
              'connected': bool(connection_value('TAUTULLI_URL') and connection_value('TAUTULLI_API_KEY'))}
    kind, external_id = details['kind'], details['external_id']
    if kind not in ('movie', 'tv'):
        return result
    try:
        matched = ({'state': source, 'collection_id': collection_id, 'row': membership_row}
                   if membership_row is not None and source in ('leaving', 'kept') else
                   leaving_membership().get((kind, str(external_id))) if external_id else None)
        if source in ('leaving', 'kept') and matched and (matched['state'] != source or matched['collection_id'] != collection_id):
            matched = None
        if matched:
            result['state'] = matched['state']
            if collection_id is None:
                collection_id = matched['collection_id']
            row = matched['row']
            if matched['state'] == 'leaving':
                if row.get('addDate'):
                    result['days'] = calculate_days_left(row['addDate'], get_collection_delete_after_days(collection_id))
            else:
                with closing(attribution_db()) as db:
                    schedule = db.execute('SELECT expires_at FROM keep_schedules WHERE collection_id=? AND media_id=?',
                                          (str(collection_id), str(row.get('mediaServerId')))).fetchone()
                if schedule and schedule['expires_at']:
                    expiry = forecast.parse_date(schedule['expires_at'])
                    if expiry:
                        result['days'] = max(0, math.ceil((expiry - datetime.now(timezone.utc)).total_seconds() / 86400))
                else:
                    result['days'] = '∞'
        elif source in ('leaving', 'kept'):
            result['state'] = source
    except (ValueError, requests.RequestException):
        if source in ('leaving', 'kept'):
            result['state'] = source

    if not result['connected']:
        result['reason'] = "A Leaving estimate needs watch history, which Keep can't check right now."
        return result
    try:
        rules = forecast.read_rules(connection_value, get_collections())
        plex_match = None
        if collection_id is None and arr_data is not None:
            plex_match = forecast.find_plex_media(connection_value, rules, kind, external_id, details['title'])
            if plex_match:
                collection_id = plex_match[0]
        if collection_id is None:
            result['reason'] = "We couldn't match this title to a selected Plex library, so a Leaving estimate isn't available."
            return result
        rule = rules[collection_id]
        if rule['kind'] != kind:
            raise forecast.ForecastUnavailable('Rule media type does not match')
        thresholds = forecast.tautulli_thresholds(connection_value)
        threshold = thresholds[kind]
        if rule['watch_override'] is not None and int(rule['watch_override']) != threshold:
            raise forecast.ForecastUnavailable('Maintainerr watch override differs from Tautulli')
        result['threshold'] = threshold
        result['rule'] = rule['name']
        plex_id = (item_id if source in ('leaving', 'kept') else
                   (matched or {}).get('row', {}).get('mediaServerId') or
                   (plex_match[1] if plex_match else None))
        if not plex_id:
            result['reason'] = "We couldn't match this title in Plex, so a Leaving estimate isn't available."
            return result
        history = forecast.watched_history(connection_value, plex_id, kind, threshold)
        recent = max(history, key=lambda row: int(row.get('date') or 0), default=None)
        if recent:
            result['played'] = forecast.parse_date(recent.get('date'))
            result['viewer'] = str(recent.get('friendly_name') or recent.get('user') or 'A viewer')[:80]
        views = len({str(row.get('rating_key')) for row in history}) if kind == 'tv' else len(history)
        service = 'radarr' if kind == 'movie' else 'sonarr'
        if arr_data is None:
            candidates = [row for row in media_services.list_media(service, connection_value)
                          if str(row.get('tmdbId' if kind == 'movie' else 'tvdbId') or '') == str(external_id)]
            arr_data = candidates[0] if len(candidates) == 1 else None
        values = {'views': views, 'last_viewed': result['played'],
                  'arr_added': arr_data.get('added') if arr_data else None}
        if kind == 'tv':
            response = requests.get(f"{connection_value('PLEX_SERVER_URL')}/library/metadata/{plex_id}/allLeaves",
                                    headers={**plex_headers(), 'Accept': 'application/xml',
                                             'X-Plex-Token': connection_value('PLEX_ADMIN_TOKEN')},
                                    timeout=8, allow_redirects=False)
            response.raise_for_status()
            if len(response.content) > 4 * 1024 * 1024:
                raise forecast.ForecastUnavailable('TV episode list is too large')
            root = ET.fromstring(response.content)
            dates = [int(node.get('addedAt')) for node in root.findall('Video')
                     if node.get('addedAt') and node.get('addedAt').isdigit()]
            values['last_episode_added'] = max(dates) if dates else None
        result['forecast'] = forecast.estimate(rule, values)
        if result['forecast']:
            result['forecast']['time_label'] = forecast.countdown_label(result['forecast']['days'])
        if result['forecast'] is None and result['state'] not in ('leaving', 'kept'):
            result['reason'] = "The current Leaving rules don't give an estimate for this title."
    except (forecast.ForecastUnavailable, ValueError, requests.RequestException, ET.ParseError) as exc:
        result['reason'] = "A Leaving estimate isn't available right now because we couldn't confirm the rules or watch history."
    return result


@app.get('/api/title-details/<source>/<int:item_id>')
def get_title_details(source, item_id):
    import title_details
    if item_id < 1:
        return 'Not found', 404
    collection_id = None
    arr_data = None
    membership_row = None
    try:
        if source in media_services.SERVICES:
            if not user_capabilities()['delete_media']:
                return 'Not found', 404
            libraries = [library for library in media_libraries()
                         if library['library_key'] in granted_library_keys() and library['service'] == source]
            if not libraries:
                return 'Not found', 404
            data = media_services.get_media(source, item_id, connection_value)
            if not media_item_library(data, libraries) or not media_has_files(source, data):
                return 'Not found', 404
            if not library_item_visible(source, data):
                return 'Not found', 404
            arr_data = data
            data = {**data, 'type': 'movie' if source == 'radarr' else 'show'}
        elif source in ('leaving', 'kept'):
            collection_id = request.args.get('collection', '')
            collection_id = next((cid for cid in get_collections() if str(cid) == collection_id), None)
            if collection_id is None:
                return 'Not found', 404
            loader = get_collection_exclusions if source == 'kept' else get_collection_media
            item = next((row for row in loader(collection_id).get('items', [])
                         if str(row.get('mediaServerId')) == str(item_id)), None)
            if not item:
                return 'Not found', 404
            membership_row = item
            data = item.get('mediaData') or {}
            def load_metadata():
                metadata = requests.get(f"{connection_value('MAINTAINERR_URL')}/api/media-server/meta/{item_id}", timeout=10, allow_redirects=False)
                metadata.raise_for_status()
                payload = metadata.json()
                if not isinstance(payload, dict):
                    raise ValueError('Invalid metadata')
                return {**data, **payload}
            # The membership check above is deliberately outside this display-only cache.
            details = title_details.cached_metadata(
                (str(KEEP_DB_PATH), artwork_cache.namespace('maintainerr', connection_value), item_id), load_metadata)
        else:
            return 'Not found', 404
        if source in media_services.SERVICES:
            # Fresh library inventory is required for access checks; reuse that response.
            details = title_details.normalize(data)
    except (ValueError, requests.RequestException):
        return 'Title details are temporarily unavailable. Please try again.', 503
    store = seerr_store()
    snapshot = store.read(connection_value)
    identities = store.identities(connection_value, snapshot, seerr_profiles())
    history = seerr.attribution(snapshot, identities, details['kind'], details['external_id'])
    if details['kind'] == 'tv':
        details['seasons'] = title_details.season_rows(details, snapshot, identities, seerr.attribution)
    keep_status = 'Kept' if source == 'kept' else 'Keep status unavailable'
    if source != 'kept':
        try:
            service = 'sonarr' if details['kind'] == 'tv' else 'radarr'
            target = {'title': details['title'], 'year': details['year'],
                      ('tvdbId' if service == 'sonarr' else 'tmdbId'): details['external_id']}
            keep_status = 'Kept' if media_matches_active_keep(service, target, budget=3) else 'Not kept'
        except (ValueError, requests.RequestException):
            pass  # Unknown is not an unprotected title; deletion checks remain independent.
    status = title_forecast(details, source, item_id, collection_id, arr_data, membership_row)
    response = app.make_response(render_template('title_details.html', details=details, history=history,
                                                keep_status=keep_status, title_status=status))
    response.headers['Cache-Control'] = 'private, no-store'
    return response


def media_item_library(item, libraries):
    root = str(item.get("rootFolderPath") or "").rstrip("/\\")
    path = str(item.get("path") or "").rstrip("/\\")
    matches = []
    for library in libraries:
        library_path = str(library["path"]).rstrip("/\\")
        if root == library_path or path == library_path or path.startswith(library_path + "/") \
                or path.startswith(library_path + "\\"):
            matches.append((len(library_path), library))
    return max(matches, default=(0, None), key=lambda match: match[0])[1]


def human_size(value):
    try:
        size = max(0, int(value or 0))
    except (TypeError, ValueError):
        size = 0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit in ("B", "KB") else f"{size:.1f} {unit}"
        size /= 1024


def media_has_files(service, item):
    stats = item.get("statistics") or {}
    if service == "radarr":
        return bool(item.get("hasFile") or stats.get("movieFileCount"))
    return bool(stats.get("episodeFileCount") or stats.get("sizeOnDisk"))


def media_matches_active_keep(service, item, *, budget=20):
    title = str(item.get("title") or "").casefold()
    year = item.get("year")
    external_field = "tmdbId" if service == "radarr" else "tvdbId"
    external_id = str(item.get(external_field) or "")
    deadline = time.monotonic() + budget
    # Selection controls browsing, not the protection promised by saved Keeps.
    # Include legacy attribution-only rows as well as current schedules.
    collection_ids = set(get_collections())
    with closing(attribution_db()) as db:
        for row in db.execute("""SELECT collection_id FROM keep_schedules
                UNION SELECT collection_id FROM keep_attribution"""):
            collection_id = str(row["collection_id"])
            if not collection_id.isdecimal():
                raise ValueError('Invalid saved Keep collection')
            collection_ids.add(int(collection_id))
    for collection_id in sorted(collection_ids):
        for kept in deletion_keep_inventory(collection_id, deadline):
            data = kept.get("mediaData") or {}
            if external_id and str(data.get(external_field) or "") == external_id:
                return True
            if title and str(data.get("title") or "").casefold() == title:
                kept_year = data.get("year")
                if not year or not kept_year or str(year) == str(kept_year):
                    return True
    return False


def deletion_keep_inventory(collection_id, deadline):
    """Deletion must check every Keep, not only the first browsing page."""
    seen = set()
    for page in range(1, 101):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('Keep verification timed out')
        response = requests.get(
            f"{connection_value('MAINTAINERR_URL')}/api/collections/exclusions/{collection_id}/content/{page}",
            params={'size': 100}, timeout=min(5, remaining), allow_redirects=False)
        response.raise_for_status()
        if response.status_code != 200:
            raise ValueError('Keep verification failed')
        payload = response.json()
        rows = payload.get('items') if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            raise ValueError('Incomplete Keep verification')
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get('mediaData'), dict):
                raise ValueError('Incomplete Keep metadata')
            key = row.get('mediaServerId')
            if not isinstance(key, (str, int)) or not str(key) or str(key) in seen:
                raise ValueError('Unstable Keep inventory')
            seen.add(str(key))
            yield row
        if len(rows) < 100:
            return
    raise ValueError('Keep verification exceeds pagination limit')


def library_deletion_access(service, item, snapshot=None, identities=None, *, capabilities=None):
    """UI hint only; deletion separately revalidates live history and access."""
    capabilities = capabilities if capabilities is not None else user_capabilities()
    if not capabilities['delete_media']:
        return False, 'Library permission required.'
    if capabilities['delete_any']:
        return True, 'You can delete titles in this library. Kept titles must be unprotected first.'
    if service == 'sonarr':
        allowed = any(seerr.season_deletion_access(snapshot or {}, identities or {}, item.get('tvdbId'), n,
                       (session.get('plex_user') or {}).get('id'))[0]
                      for n in media_services.downloaded_seasons(item))
        return allowed, ''
    return seerr.movie_deletion_access(snapshot or {}, identities or {}, item.get('tmdbId'),
                                       (session.get('plex_user') or {}).get('id'))


def library_item_visible(service, item):
    """Enforce the same requester filter on direct details/artwork requests."""
    resolved = media_item_library(item, [row for row in media_libraries() if row['service'] == service])
    if not resolved or resolved['library_key'] not in granted_library_keys():
        return False
    if user_capabilities()['delete_any']:
        return True
    store = seerr_store()
    snapshot = store.read(connection_value)
    identities = store.identities(connection_value, snapshot, seerr_profiles())
    return library_deletion_access(service, item, snapshot, identities)[0]


def build_library_sections():
    cache = library_artwork_cache()
    allowed = granted_library_keys()
    all_libraries = media_libraries()
    capabilities = user_capabilities()
    try:
        membership = leaving_membership()
    except (ValueError, requests.RequestException):
        membership = {}
    retention = {}
    with closing(attribution_db()) as db:
        schedules = {(row['collection_id'], row['media_id']): row['expires_at']
                     for row in db.execute('SELECT collection_id, media_id, expires_at FROM keep_schedules')}
    unrestricted = capabilities['delete_any']
    libraries = [library for library in all_libraries if library["library_key"] in allowed]
    by_service = {}
    for library in libraries:
        by_service.setdefault(library["service"], []).append(library)
    sections = []
    snapshot, identities = None, None
    if not unrestricted:
        store = seerr_store()
        snapshot = store.read(connection_value)
        identities = store.identities(connection_value, snapshot, seerr_profiles())
    for service, service_libraries in by_service.items():
        try:
            inventory = media_services.list_media(service, connection_value)
            cache.remember_inventory(artwork_cache.namespace(service, connection_value), inventory)
            error = ""
        except (ValueError, requests.RequestException):
            inventory, error = [], f"Could not load {service.title()} right now."
        grouped = {library["library_key"]: [] for library in service_libraries}
        for item in inventory:
            if not isinstance(item, dict) or not isinstance(item.get("id"), int):
                continue
            library = media_item_library(item, [row for row in all_libraries if row['service'] == service])
            if not library or library['library_key'] not in grouped or not media_has_files(service, item):
                continue
            can_delete = library_deletion_access(service, item, snapshot, identities, capabilities=capabilities)[0]
            if not unrestricted and not can_delete:
                continue
            stats = item.get("statistics") or {}
            kind = 'movie' if service == 'radarr' else 'tv'
            external_id = item.get('tmdbId' if service == 'radarr' else 'tvdbId')
            match = membership.get((kind, str(external_id))) if external_id else None
            badge = None
            if match:
                cid, row = match['collection_id'], match['row']
                if match['state'] == 'leaving':
                    if cid not in retention:
                        try:
                            retention[cid] = get_collection_delete_after_days(cid)
                        except (ValueError, requests.RequestException):
                            retention[cid] = None
                    days = calculate_days_left(row.get('addDate'), retention[cid])
                    badge = {'state': 'leaving', 'days': days}
                else:
                    expiry = schedules.get((str(cid), str(row.get('mediaServerId'))))
                    date = leaving_forecast.parse_date(expiry) if expiry else None
                    days = max(0, math.ceil((date - datetime.now(timezone.utc)).total_seconds() / 86400)) if date else '∞'
                    badge = {'state': 'kept', 'days': days}
            grouped[library["library_key"]].append({
                "id": item["id"], "title": item.get("title") or "Untitled",
                "year": item.get("year") or "", "service": service,
                "library_key": library["library_key"],
                "size": human_size(stats.get("sizeOnDisk")),
                "episode_count": stats.get("episodeFileCount") if service == "sonarr" else None,
                "can_delete": can_delete,
                "badge": badge,
            })
        for library in service_libraries:
            items = sorted(grouped[library["library_key"]],
                           key=lambda item: (item["title"].casefold(), str(item["year"])))
            access_unavailable = not unrestricted and snapshot['state'] != 'current'
            sections.append({**library, "items": items, "error": error,
                             "access_unavailable": access_unavailable})
    def label(name):
        return name.replace(" Leaving Plex Soon", "").replace("TV Shows", "Shows").casefold()
    order = {label(name): index for index, name in enumerate(get_collections().values())}
    return sorted(sections, key=lambda section: (order.get(label(section["name"]), len(order)), label(section["name"])))


@app.get("/library")
def library_management():
    capabilities = user_capabilities()
    if not capabilities["delete_media"] or not granted_library_keys():
        return render_auth_page(
            title="Library access unavailable",
            message="Your Keep account does not have permission to manage a media library.",
            button_label="Back to Keep", button_url=url_for("home"),
        ), 403
    response = app.make_response(render_template(
        "library.html", sections=build_library_sections(), plex_user=session["plex_user"],
        owner=is_owner(), csrf_token=get_csrf_token(), capabilities=capabilities,
    ))
    response.headers["Cache-Control"] = "no-store"
    return response


def library_artwork_cache():
    return artwork_cache.ArtworkCache(Path(KEEP_DB_PATH).with_name('artwork-cache.sqlite3'))


@app.get("/library/artwork/<service>/<int:item_id>")
def library_artwork(service, item_id):
    if service not in media_services.SERVICES or not user_capabilities()["delete_media"] \
            or not granted_library_keys():
        return "Not found", 404
    try:
        cache = library_artwork_cache()
        key = artwork_cache.namespace(service, connection_value) + ':' + str(item_id)
        metadata = cache.get(key + ':metadata')
        item = json.loads(metadata[0]) if metadata else media_services.get_media(service, item_id, connection_value)
        if metadata and (('tmdbId' if service == 'radarr' else 'seasons') not in item) and not user_capabilities()['delete_any']:
            # Old cache entries predate requester-based artwork authorization.
            item = media_services.get_media(service, item_id, connection_value)
            cache.remember_item(key, item)
        if not metadata:
            cache.remember_item(key, item)
        libraries = [library for library in media_libraries()
                     if library["library_key"] in granted_library_keys()
                     and library["service"] == service]
        if not media_item_library(item, libraries):
            return "Not found", 404
        if not library_item_visible(service, item):
            return "Not found", 404
        poster_key = key + ':poster:' + hashlib.sha256(json.dumps(item.get('images'), sort_keys=True).encode()).hexdigest()
        artwork, content_type = cache.load(poster_key, lambda: media_services.artwork(
            service, item_id, connection_value, item=item, thumbnail=True), 86400)
    except (ValueError, requests.RequestException):
        return "Not found", 404
    response = app.response_class(artwork, mimetype=content_type)
    response.headers["Cache-Control"] = "private, no-cache"
    response.set_etag(hashlib.sha256(artwork).hexdigest())
    response.make_conditional(request)
    return response


def season_plan_identity(item, library_key):
    user = session['plex_user']
    return {'user': str(user['id']), 'session': user.get('session_version'), 'library': library_key,
            'scope': artwork_cache.namespace('sonarr', connection_value),
            'request_scope': seerr.namespace(connection_value),
            'target': {key: item.get(key) for key in ('id', 'tvdbId', 'path', 'rootFolderPath')}}


def season_plan_signer():
    return URLSafeTimedSerializer(app.secret_key, salt='keep-season-delete-v1')


def selected_seasons_allowed(item, seasons, snapshot, identities):
    return all(seerr.season_deletion_access(snapshot, identities, item.get('tvdbId'), n,
               session['plex_user']['id'])[0] for n in seasons)


def season_context_current(item, library_key, seasons, live_snapshot):
    """Recheck mutable access after network work, immediately before writes."""
    current = connection_settings.snapshot()
    if any(current.get(key, globals().get(key, '')) != connection_value(key) for key in
           ('SEERR_URL', 'SEERR_API_KEY', 'SONARR_URL', 'SONARR_API_KEY', 'MAINTAINERR_URL', 'KEEP_COLLECTIONS')):
        return False
    user = session['plex_user']
    profile = current_profile()
    if not profile or profile['status'] != 'active' or profile['session_version'] != user.get('session_version') \
            or not plex_account_access_active(profile):
        return False
    cap = user_capabilities()
    library = media_item_library(item, [r for r in media_libraries() if r['service'] == 'sonarr'])
    if not cap['delete_media'] or library_key not in granted_library_keys() or not library or library['library_key'] != library_key:
        return False
    if cap['delete_any']:
        return True
    if live_snapshot is None:
        return False
    identities = seerr_store().identities(connection_value, live_snapshot, seerr_profiles())
    return selected_seasons_allowed(item, seasons, live_snapshot, identities)


@app.get('/api/library/sonarr/<int:item_id>/seasons')
def library_seasons(item_id):
    """A fresh file preview; saved attribution controls visibility, never deletion."""
    if not user_capabilities()['delete_media']:
        return jsonify(error='Library permission required'), 403
    try:
        item = media_services.get_media('sonarr', item_id, connection_value)
        if not library_item_visible('sonarr', item):
            return jsonify(error='Title not available'), 404
        library = media_item_library(item, [r for r in media_libraries() if r['service'] == 'sonarr'])
        inventory = media_services.season_inventory(item_id, connection_value)
        full = user_capabilities()['delete_any']
        snapshot, identities = {}, {}
        if not full:
            store = seerr_store()
            snapshot = store.read(connection_value)
            identities = store.identities(connection_value, snapshot, seerr_profiles())
        eligible = {n: row for n, row in inventory.items() if full or
                    selected_seasons_allowed(item, [n], snapshot, identities)}
        token = season_plan_signer().dumps({**season_plan_identity(item, library['library_key']),
                                           'seasons': {str(n): row['fingerprint'] for n, row in eligible.items()}})
        response = jsonify(title=item.get('title', 'Series'), libraryKey=library['library_key'], token=token,
                           seasons=[{'number': n, 'episodes': row['episodes'], 'size': human_size(row['bytes'])}
                                    for n, row in sorted(eligible.items())])
        response.headers['Cache-Control'] = 'private, no-store'
        return response
    except (ValueError, requests.RequestException):
        return jsonify(error='Could not load seasons. Please try again.'), 502


class KeepMutationBusy(Exception):
    pass


@contextmanager
def keep_mutation_lock():
    """Coordinate protection changes and deletion across web and worker processes."""
    with open(Path(KEEP_DB_PATH).with_suffix('.deletion.lock'), 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise KeepMutationBusy from error
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def serialized_keep_change(handler):
    @wraps(handler)
    def protected(*args, **kwargs):
        csrf_error = require_csrf()
        if csrf_error:
            return csrf_error
        try:
            with keep_mutation_lock():
                return handler(*args, **kwargs)
        except KeepMutationBusy:
            return jsonify(error='Another Keep or deletion change is in progress. Please wait and try again.'), 409
    return protected


@app.post("/api/library/delete")
@serialized_keep_change
def delete_library_media():
    with media_services.request_budget():
        return perform_library_deletion()


def perform_library_deletion():
    csrf_error = require_csrf()
    if csrf_error:
        return csrf_error
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify(error="invalid request"), 400
    service = payload.get("service")
    item_id = payload.get("itemId")
    library_key = payload.get("libraryKey")
    seasons = payload.get('seasons')
    season_mode = 'seasons' in payload
    if season_mode and (service != 'sonarr' or not isinstance(seasons, list) or not 1 <= len(seasons) <= 100
                        or any(type(n) is not int or n < 0 for n in seasons) or len(set(seasons)) != len(seasons)):
        return jsonify(error='Select valid seasons'), 400
    if not isinstance(service, str) or service not in media_services.SERVICES or type(item_id) is not int or item_id < 1 \
            or not isinstance(library_key, str):
        return jsonify(error="invalid request"), 400
    if not user_capabilities()["delete_media"] or library_key not in granted_library_keys():
        return jsonify(error="Library permission required"), 403
    with closing(attribution_db()) as db:
        library = db.execute("""SELECT * FROM media_libraries
            WHERE library_key = ? AND service = ?""", (library_key, service)).fetchone()
    if not library:
        return jsonify(error="Library not found"), 404
    try:
        item = media_services.get_media(service, item_id, connection_value)
        resolved = media_item_library(item, [row for row in media_libraries() if row['service'] == service])
        if not resolved or resolved['library_key'] != library_key or not media_has_files(service, item):
            return jsonify(error="Media is not present in this library"), 409
        # Cached attribution and all client-supplied ownership claims are ignored.
        capabilities = user_capabilities()
        live_snapshot = None
        season_files = None
        if season_mode:
            try:
                token = payload.get('previewToken')
                if not isinstance(token, str) or len(token) > 50000:
                    raise ValueError('Invalid preview')
                plan = season_plan_signer().loads(token, max_age=600)
                identity = season_plan_identity(item, library_key)
                if not isinstance(plan, dict) or any(plan.get(k) != v for k, v in identity.items()):
                    raise ValueError('Changed preview')
                season_files = media_services.season_inventory(item_id, connection_value)
                if any(n not in season_files or plan.get('seasons', {}).get(str(n)) != season_files[n]['fingerprint'] for n in seasons):
                    raise ValueError('Changed files')
            except (BadSignature, ValueError):
                return jsonify(error='Seasons changed or this preview expired. Reopen season selection.', refreshRequired=True), 409
        if not capabilities['delete_any']:
            if service != 'radarr' and not season_mode:
                return jsonify(error="Whole-series deletion requires Delete any title permission"), 403
            try:
                live_snapshot = {**seerr.Client(connection_value, timeout=20).snapshot(), 'state': 'current'}
            except (ValueError, requests.RequestException):
                log_activity('media-delete-blocked', 'Request verification unavailable; no media deleted')
                return jsonify(error="Cannot verify your request right now. Nothing was deleted. Try again shortly."), 503
            identities = seerr_store().identities(connection_value, live_snapshot, seerr_profiles())
            allowed, reason = ((selected_seasons_allowed(item, seasons, live_snapshot, identities),
                                'One or more selected seasons are no longer requested exclusively by you.') if season_mode else
                               seerr.movie_deletion_access(live_snapshot, identities, item.get('tmdbId'), session['plex_user']['id']))
            if not allowed:
                log_activity('media-delete-blocked', f'Request permission denied for movie {item_id}')
                return jsonify(error=reason), 403
        if media_matches_active_keep(service, item):
            log_activity("media-delete-blocked",
                         f"Blocked deletion of kept title {item.get('title') or item_id} from {library['name']}")
            return jsonify(error="Remove this title from Kept before deleting it"), 409
        # Network verification can take time: reject changes to the target,
        # connection, account, library grant or manual account link during it.
        fresh_item = media_services.get_media(service, item_id, connection_value)
        if any(fresh_item.get(key) != item.get(key) for key in ('id', 'tmdbId', 'tvdbId', 'path', 'rootFolderPath')) \
                or not media_has_files(service, fresh_item):
            return jsonify(error="This title changed. Reload before deleting."), 409
        if not season_mode and media_matches_active_keep(service, fresh_item):
            return jsonify(error='Remove this title from Kept before deleting it'), 409
        # Keep lookup is also network work; mutable authorization follows it.
        fresh_settings = connection_settings.snapshot()
        for name in ('SEERR_URL', 'SEERR_API_KEY', 'RADARR_URL', 'RADARR_API_KEY',
                     'SONARR_URL', 'SONARR_API_KEY', 'MAINTAINERR_URL', 'KEEP_COLLECTIONS'):
            if fresh_settings.get(name, globals().get(name, '')) != connection_value(name):
                return jsonify(error="Connection settings changed. Reload before deleting."), 409
        profile = current_profile()
        user = session['plex_user']
        if not profile or profile['status'] != 'active' or not plex_account_access_active(profile) \
                or profile['session_version'] != user.get('session_version'):
            return jsonify(error="Account access changed. Sign in again."), 403
        if not user_capabilities()['delete_media'] or library_key not in granted_library_keys():
            return jsonify(error="Library permission changed. Reload before deleting."), 403
        resolved = media_item_library(fresh_item, [row for row in media_libraries() if row['service'] == service])
        if not resolved or resolved['library_key'] != library_key:
            return jsonify(error="Library configuration changed. Reload before deleting."), 409
        if not user_capabilities()['delete_any']:
            if live_snapshot is None:
                return jsonify(error="Deletion permission changed. Reload before deleting."), 403
            identities = seerr_store().identities(connection_value, live_snapshot, seerr_profiles())
            allowed, reason = ((selected_seasons_allowed(fresh_item, seasons, live_snapshot, identities),
                                'Season request permissions changed. Reopen season selection.') if season_mode else
                               seerr.movie_deletion_access(live_snapshot, identities, fresh_item.get('tmdbId'), user['id']))
            if not allowed:
                return jsonify(error=reason), 403
        title = item.get("title") or f"{service.title()} item {item_id}"
        if season_mode:
            fresh_files = media_services.season_inventory(item_id, connection_value)
            if any(n not in fresh_files or fresh_files[n]['fingerprint'] != season_files[n]['fingerprint'] for n in seasons):
                return jsonify(error='Season files changed. Reopen season selection.', refreshRequired=True), 409
            known = set(media_services.season_monitoring(fresh_item))
            if not set(seasons).issubset(known):
                return jsonify(error='Series seasons changed. Reopen season selection.', refreshRequired=True), 409
            # Final Keep check after file inventory work, before the first write.
            if media_matches_active_keep(service, fresh_item):
                return jsonify(error='Remove this title from Kept before deleting it'), 409
            if not season_context_current(fresh_item, library_key, seasons, live_snapshot):
                return jsonify(error='Season access changed. Reopen season selection.', refreshRequired=True), 403
            file_ids = sorted({fid for n in seasons for fid in fresh_files[n]['fileIds']})
            try:
                media_services.unmonitor_seasons(item_id, seasons, connection_value)
                media_services.unmonitor_episodes(sorted({eid for n in seasons for eid in fresh_files[n]['episodeIds']}), connection_value)
                monitored = media_services.get_media('sonarr', item_id, connection_value)
                flags = media_services.season_monitoring(monitored)
                if any(flags.get(n) is not False for n in seasons) or any(monitored.get(k) != fresh_item.get(k)
                        for k in ('id', 'tvdbId', 'path', 'rootFolderPath')):
                    raise ValueError('Could not verify unmonitoring')
                final_files = media_services.season_inventory(item_id, connection_value)
                if any(n not in final_files or final_files[n]['fingerprint'] != fresh_files[n]['fingerprint']
                       or final_files[n]['monitoredEpisodeIds'] for n in seasons) \
                        or media_matches_active_keep(service, monitored) \
                        or not season_context_current(monitored, library_key, seasons, live_snapshot):
                    raise ValueError('Files or access changed')
                media_services.delete_episode_files(file_ids, connection_value)
                remaining = media_services.season_inventory(item_id, connection_value)
                if any(n in remaining for n in seasons):
                    raise ValueError('Season deletion incomplete')
            except (ValueError, requests.RequestException):
                library_artwork_cache().forget(artwork_cache.namespace(service, connection_value) + ':' + str(item_id) + ':')
                log_activity('season-delete-unconfirmed', f'Season deletion needs review for series {item_id}; seasons {sorted(seasons)}')
                return jsonify(error='Could not confirm complete deletion. Selected seasons may now be unmonitored and some files may have been deleted. Reload the library before trying again.', refreshRequired=True), 502
            library_artwork_cache().forget(artwork_cache.namespace(service, connection_value) + ':' + str(item_id) + ':')
            log_activity('seasons-deleted', f'Deleted seasons {sorted(seasons)} of {title} from {library["name"]}; series retained')
            queue_seerr_availability()
            return jsonify(status='seasons-deleted', title=title, seasons=sorted(seasons))
        media_services.delete_media(service, item_id, connection_value)
        library_artwork_cache().forget(artwork_cache.namespace(service, connection_value) + ':' + str(item_id) + ':')
        log_activity("media-deleted", f"Deleted {title} and its folder from {library['name']} via {service.title()}")
        queue_seerr_availability()
        return jsonify(status="deleted", title=title)
    except requests.HTTPError as error:
        status = getattr(error.response, "status_code", 502)
        if status == 404:
            return jsonify(error="Media no longer exists"), 404
        app.logger.error("%s deletion failed for item %s", service, item_id)
        log_activity("media-delete-failed",
                     f"Failed to delete {service.title()} item {item_id} from {library['name']}")
        return jsonify(error="The media service could not delete this title"), 502
    except (ValueError, requests.RequestException):
        log_activity("media-delete-failed",
                     f"Failed to delete {service.title()} item {item_id} from {library['name']}")
        return jsonify(error="The media service could not delete this title"), 502


@app.route("/preferences", methods=["GET", "POST"])
def email_preferences_page():
    profile = current_profile()
    user = session.get("plex_user") or {}
    email_address = ((profile["email"] if profile else "") or user.get("email") or "").strip().lower()
    theme = profile['theme_mode'] if profile else 'system'
    error = None
    saved = request.args.get("saved") == "1"

    if request.method == "POST":
        csrf_error = require_form_csrf()
        if csrf_error:
            return csrf_error
        requested_theme = request.form.get('theme_mode', theme)
        if requested_theme in ('system', 'light', 'dark'):
            theme = requested_theme
        receive_email = request.form.get("receive_email") == "1"
        try:
            selected = {int(value) for value in request.form.getlist("collection_id")}
        except ValueError:
            selected = set()
        if requested_theme not in ('system', 'light', 'dark'):
            error = 'Choose System, Light, or Dark appearance.'
        elif not profile:
            error = 'Your account is unavailable. Sign in again.'
        elif receive_email and (not email_address or not EMAIL_ADDRESS.fullmatch(email_address)):
            error = "Your Keep account does not have an email address. Ask the owner to add one."
        elif receive_email and (not selected or not selected.issubset(set(recipient_collection_ids()))):
            error = "Select at least one collection or turn off email delivery."
        elif selected and not selected.issubset(set(recipient_collection_ids())):
            error = "Invalid collection preference."
        else:
            with closing(attribution_db()) as db, db:
                db.execute('UPDATE user_profiles SET theme_mode=? WHERE plex_id=?',
                           (requested_theme, str(user['id'])))
                if email_address and EMAIL_ADDRESS.fullmatch(email_address):
                    if receive_email:
                        db.execute("""INSERT INTO email_recipients(email, enabled) VALUES (?, 1)
                            ON CONFLICT(email) DO UPDATE SET enabled = 1""", (email_address,))
                        ensure_recipient_subscriptions(db, email_address)
                        db.execute("UPDATE recipient_subscriptions SET enabled = 0 WHERE email = ?",
                                   (email_address,))
                        db.executemany("""UPDATE recipient_subscriptions SET enabled = 1
                            WHERE email = ? AND collection_id = ?""",
                            ((email_address, collection_id) for collection_id in selected))
                    else:
                        db.execute("UPDATE email_recipients SET enabled = 0 WHERE email = ?",
                                   (email_address,))
            log_activity('personal-preferences-updated', 'Updated personal preferences')
            return redirect(url_for("email_preferences_page", saved="1", **({"fragment": "1"} if request.args.get("fragment") == "1" else {})))

    enabled = False
    selected = set(recipient_collection_ids())
    if email_address:
        with closing(attribution_db()) as db:
            recipient = db.execute("SELECT enabled FROM email_recipients WHERE email = ?",
                                   (email_address,)).fetchone()
            rows = db.execute("""SELECT collection_id FROM recipient_subscriptions
                WHERE email = ? AND enabled = 1""", (email_address,)).fetchall()
        enabled = bool(recipient and recipient["enabled"])
        if rows:
            selected = {row["collection_id"] for row in rows}

    if request.args.get("fragment") == "1":
        return render_template("preferences_form.html", preference_id_prefix="dialog-", email=email_address, enabled=enabled,
            selected=selected, collections=get_collections(), error=error, saved=saved, theme=theme,
            csrf_token=get_csrf_token())

    return render_template_string("""
<!doctype html><html lang="en" data-theme="{{ theme_mode }}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1, viewport-fit=cover"><meta name="color-scheme" content="dark">
<script src="/static/keep-theme.js?v={{ app_version }}"></script>
<meta name="theme-color" content="#f5a623"><meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="Keep">
<link rel="icon" type="image/svg+xml" href="/static/keep-icon.svg?v=20260907-2">
<link rel="icon" type="image/png" sizes="32x32" href="/static/favicon-32.png?v=20260907-2">
<link rel="apple-touch-icon" sizes="180x180" href="/static/apple-touch-icon.png?v=20260907-2">
<link rel="manifest" href="/static/site.webmanifest">
<title>Preferences · Keep</title><style>
  :root{--bg:#090a0d;--surface:rgba(27,29,35,.84);--border:rgba(255,255,255,.09);
    --text:#f5f6f7;--muted:#969ba6;--accent:#f5a623;--surface2:#121318}
  *{box-sizing:border-box} body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;
    color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
    background:radial-gradient(circle at 15% -10%,rgba(245,166,35,.14),transparent 32rem),
      radial-gradient(circle at 85% 0%,rgba(92,82,255,.08),transparent 30rem),var(--bg)}
  main{width:min(560px,100%);padding:34px;border:1px solid var(--border);border-radius:24px;
    background:var(--surface);box-shadow:0 24px 70px rgba(0,0,0,.34)}
  .brand{display:flex;align-items:center;gap:15px;margin-bottom:28px}.mark{width:54px;height:54px;
    display:grid;place-items:center;border-radius:16px;background:linear-gradient(145deg,#ffbe52,#e78712);
    color:#111;font-size:29px;font-weight:900}h1{margin:0;font-size:30px;letter-spacing:-.04em}
  .subtitle,.email{color:var(--muted);font-size:13px;line-height:1.5}.subtitle{margin:6px 0 0}
  .email{padding:12px 14px;border:1px solid var(--border);border-radius:11px;background:var(--surface2);
    overflow-wrap:anywhere}.notice,.error{margin:0 0 18px;padding:12px 14px;border-radius:10px;font-size:13px}
  .notice{border:1px solid rgba(108,213,148,.28);background:rgba(108,213,148,.08);color:#b8f2ce}
  .error{border:1px solid rgba(255,118,118,.3);background:rgba(255,118,118,.08);color:#ffb0b0}
  form{display:grid;gap:12px;margin-top:18px}.choice{display:flex;align-items:center;gap:10px;padding:12px 13px;
    border:1px solid var(--border);border-radius:11px;background:var(--surface2);font-size:13px;font-weight:700}
  .choice input{width:auto;margin:0;accent-color:var(--accent)}.topics{display:grid;grid-template-columns:1fr 1fr;gap:10px;
    margin:0;padding:0;border:0;transition:opacity .18s ease}.topics:disabled{opacity:.42}.topics:disabled .choice{cursor:not-allowed}
  button,.back{min-height:46px;display:flex;align-items:center;justify-content:center;border:0;border-radius:11px;
    font:800 13px/1 inherit;text-decoration:none;cursor:pointer}button{margin-top:5px;background:var(--accent);color:#17120a}
  button:disabled{opacity:.45;cursor:not-allowed}
  .back{margin-top:10px;border:1px solid var(--border);background:rgba(255,255,255,.04);color:var(--text)}
  @media(max-width:520px){main{padding:26px 20px}.topics{grid-template-columns:1fr}}
</style>
<link rel="stylesheet" href="/static/keep-ui.css?v={{ app_version }}">
<script defer src="/static/keep-toast.js?v=2.4.6"></script>
<script defer src="/static/keep-interactions.js?v={{ app_version }}"></script>{% include 'shared_assets.html' %}
</head><body class="preferences-ui"><main>
  {% include 'shared_header.html' %}
  {% include 'shared_whats_new.html' %}
  <div class="page-heading"><h1>Preferences</h1><p class="subtitle">Choose Keep’s appearance and your email reminders.</p></div>
  {% include 'preferences_form.html' %}
  <a class="back" href="/">Back to Keep</a>
  <script>
    const receiveEmail = document.getElementById("receive-email");
    const emailTopics = document.getElementById("email-topics");
    receiveEmail.addEventListener("change", () => {
      emailTopics.disabled = !receiveEmail.checked;
    });
  </script>
</main></body></html>""", email=email_address, enabled=enabled, selected=selected, theme=theme,
        collections=get_collections(), error=error, saved=saved, csrf_token=get_csrf_token())


@app.get("/settings")
def settings_page():
    denied = require_owner()
    if denied:
        return denied
    return redirect(url_for("settings_users"))


def test_smtp_connection(getter=None):
    """Verify encrypted transport and optional authentication without sending mail."""
    import ssl
    getter = getter or connection_value
    host = getter('SMTP_HOST')
    if not host:
        raise ValueError('SMTP host is required')
    implicit = getter('SMTP_SECURITY') == 'ssl'
    transport = smtplib.SMTP_SSL if implicit else smtplib.SMTP
    options = {'context': ssl.create_default_context()} if implicit else {}
    with transport(host, int(getter('SMTP_PORT')), timeout=20, **options) as smtp:
        smtp.ehlo()
        if not implicit:
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        if getter('SMTP_USER'):
            smtp.login(getter('SMTP_USER'), getter('SMTP_PASSWORD') or '')


def owned_plex_servers(token):
    # The resource credential may still be broad. Never retain the account token
    # as a fallback or infer ownership merely from successful server access.
    from service_discovery import read_service
    from connection_settings import validate
    rows = json.loads(read_service(PLEX_API_BASE + '/resources?includeHttps=1',
                                  {**plex_headers(), 'X-Plex-Token': token}))
    if not isinstance(rows, list) or len(rows) > 200:
        raise ValueError('Unexpected Plex resources')
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Unexpected Plex resource')
        if row.get('owned') is not True or 'server' not in str(row.get('provides', '')).split(','):
            continue
        if row.get('product') != 'Plex Media Server':
            continue
        identifier, credential = row.get('clientIdentifier'), row.get('accessToken')
        if not isinstance(identifier, str) or not identifier or not isinstance(credential, str) or not credential:
            continue
        urls = []
        connections = row.get('connections', [])
        if not isinstance(connections, list):
            continue
        for connection in connections[:8]:
            try:
                url = validate('PLEX_SERVER_URL', connection.get('uri'))
                # Automatic discovery only sends credentials over verified TLS.
                # Private HTTP remains an explicit advanced/manual choice.
                if url.startswith('https://') and url not in urls:
                    urls.append(url)
            except (ValueError, AttributeError):
                continue
        if urls:
            result.append({'id': identifier, 'name': str(row.get('name') or 'Plex server')[:200],
                           'token': credential, 'urls': urls[:3]})
    return result


def setup_missing_configuration():
    """List saved settings needed before live setup verification can run."""
    missing = []
    if not all(connection_value(name) for name in PLEX_FIELDS):
        missing.append('Plex: connect your owned server and save its address, server identity, and credential.')
    if not connection_value('MAINTAINERR_URL'):
        missing.append('Maintainerr: save its address.')
    if not get_collections():
        missing.append('Collections: select and save at least one Maintainerr collection.')
    if email_enabled() and not all(connection_value(name) for name in ('SMTP_HOST', 'SMTP_FROM')):
        missing.append('Email: save an SMTP host and sender email address, or disable email.')
    return missing


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if owner_id():
        if not is_owner():
            return redirect('/login')
        if not onboarding.pending():
            return redirect('/settings/connections')
        message = ''
        missing_configuration = setup_missing_configuration()
        if request.method == 'POST':
            error = require_form_csrf()
            if error:
                return error
            try:
                if missing_configuration:
                    raise ValueError('Required setup settings are missing')
                test_plex(connection_value('PLEX_SERVER_URL'), connection_value('PLEX_ADMIN_TOKEN'), connection_value('PLEX_MACHINE_IDENTIFIER'))
                collections = discover_collections(connection_value('MAINTAINERR_URL'))
                if not get_collections() or any(cid not in collections for cid in get_collections()):
                    raise ValueError('Select current collections')
                if email_enabled():
                    test_smtp_connection()
                onboarding.finish()
                return render_template('setup.html', mode='complete', csrf_token=get_csrf_token(),
                    collections=get_collections(), email=email_enabled(),
                    plex_configured=True,
                    plex_url=connection_value('PLEX_SERVER_URL'),
                    maintainerr_url=connection_value('MAINTAINERR_URL'))
            except (ValueError, requests.RequestException, ET.ParseError, smtplib.SMTPException, OSError):
                message = ('Save the required settings in Connections before finishing setup.' if missing_configuration else
                           'Verification failed. Test each service in Connections and select current Maintainerr collections before finishing.')
        return render_template('setup.html', mode='summary', csrf_token=get_csrf_token(),
                               message=message, missing_configuration=missing_configuration,
                               collections=get_collections(), email=email_enabled(),
                               plex_configured=all(connection_value(name) for name in PLEX_FIELDS),
                               plex_url=connection_value('PLEX_SERVER_URL'),
                               maintainerr_url=connection_value('MAINTAINERR_URL'))
    message = ''
    if request.method == 'POST':
        error = require_form_csrf()
        if error:
            return error
        limited = persistent_rate_limit('bootstrap', 5, 60)
        if limited:
            return limited
        code = request.form.get('bootstrap_code', '')
        if not onboarding.valid_code(code):
            message = 'That setup code is invalid or expired. Generate a new code locally.'
        else:
            return begin_plex_flow('bootstrap', {'bootstrap': bootstrap_digest(code)})
    return render_template('setup.html', mode='bootstrap', message=message, csrf_token=get_csrf_token())


@app.post('/settings/connections/plex/connect')
def connect_plex():
    denied = require_owner() or require_form_csrf()
    if denied:
        return denied
    return begin_plex_flow('connect', {'owner': owner_id()})


@app.route('/settings/connections/plex/select', methods=['GET', 'POST'])
def select_plex():
    denied = require_owner()
    if denied:
        return denied
    if request.method == 'POST':
        denied = require_form_csrf()
        if denied:
            return denied
    key, binding = session.get('plex_selection', ''), session.get('plex_selection_binding', '')
    flow = onboarding.take_flow(key, binding, consume=request.method == 'POST')
    if not flow or flow[0] != 'selection' or flow[1].get('owner') != owner_id():
        return 'Plex selection expired or already used. Connect Plex again.', 400
    servers = flow[1]['servers']
    if request.method == 'POST':
        server = next((server for index, server in enumerate(servers) if str(index) == request.form.get('server')), None)
        if not server:
            return 'Choose an eligible owned server. Connect Plex again to retry.', 400
        deadline = time.monotonic() + 20
        for url in server['urls']:
            if time.monotonic() >= deadline:
                break
            try:
                test_plex(url, server['token'], server['id'])
            except (ValueError, requests.RequestException, ET.ParseError):
                continue
            connection_settings.save({'PLEX_SERVER_URL': url, 'PLEX_MACHINE_IDENTIFIER': server['id'],
                                      'PLEX_ADMIN_TOKEN': server['token']}, plex_override=True)
            _settings_snapshot.set(connection_settings.snapshot())
            connection_settings.record_check('plex', connection_settings.connection_fingerprint('plex', connection_value), True)
            session.pop('plex_selection', None)
            session.pop('plex_selection_binding', None)
            log_activity('configuration-updated', 'Owner connected a verified Plex server')
            return redirect('/setup' if onboarding.pending() else '/settings/connections')
        return 'Keep could not verify this server over TLS. Check server secure connections and runtime network access, then reconnect or use advanced manual settings.', 400
    # Pass only display-safe fields to the template.
    return render_template('setup.html', mode='selection', csrf_token=get_csrf_token(),
                           servers=[{'id': str(index), 'name': server['name']} for index, server in enumerate(servers)])


def connection_failure_message(service, error):
    """Return useful diagnostics without echoing URLs, credentials, or response bodies."""
    labels = {'plex': 'Plex', 'maintainerr': 'Maintainerr', 'radarr': 'Radarr',
              'sonarr': 'Sonarr', 'seerr': 'Seerr', 'tautulli': 'Tautulli',
              'email': 'mail server'}
    label = labels.get(service, 'service')

    chain = []
    pending = [error]
    seen = set()
    while pending and len(chain) < 12:
        current = pending.pop(0)
        if not isinstance(current, BaseException) or id(current) in seen:
            continue
        seen.add(id(current))
        chain.append(current)
        for nested in (getattr(current, '__cause__', None),
                       getattr(current, '__context__', None),
                       getattr(current, 'reason', None)):
            if isinstance(nested, BaseException):
                pending.append(nested)
        pending.extend(value for value in getattr(current, 'args', ())
                       if isinstance(value, BaseException))

    if any(isinstance(item, smtplib.SMTPAuthenticationError) for item in chain):
        return f'{label} rejected authentication. Check the saved username and password; Keep does not display credentials here.'
    smtp_response = next((item for item in chain
                          if isinstance(item, smtplib.SMTPResponseException)), None)
    if smtp_response is not None:
        smtp_code = smtp_response.smtp_code
        if isinstance(smtp_code, int) and 400 <= smtp_code < 500:
            return f'{label} temporarily rejected the request (SMTP {smtp_code}). Check mail service availability, then test again.'
        if isinstance(smtp_code, int) and 500 <= smtp_code < 600:
            return f'{label} rejected the request (SMTP {smtp_code}). Check the saved mail settings and the mail service policy.'
        return f'{label} returned an unexpected SMTP response. Check the saved mail settings and supported mail service configuration.'

    status = None
    response = getattr(error, 'response', None)
    if response is not None:
        status = getattr(response, 'status_code', None)
    if status is None and isinstance(error, seerr.ResponseError):
        match = re.search(r'HTTP\s+(\d{3})', str(error))
        status = int(match.group(1)) if match else None
    if status in (401, 403):
        return f'{label} rejected authentication. Check the saved credential and the account access; Keep does not display credentials here.'
    if status == 404:
        return f'Keep reached {label}, but its expected API path was not found. Check the saved service address and supported service version.'
    if status == 429:
        return f'{label} rate-limited the request. Wait briefly, then test again.'
    if isinstance(status, int) and status >= 500:
        return f'{label} returned a server error (HTTP {status}). Check that service health, then test again.'
    if isinstance(status, int) and 400 <= status < 500:
        return f'{label} rejected the request (HTTP {status}). Check its saved connection settings and API access.'

    names = {type(item).__name__.lower() for item in chain}
    messages = ' '.join(str(item).lower() for item in chain)
    errors = {getattr(item, 'errno', None) for item in chain}
    if any(isinstance(item, (socket.gaierror,)) for item in chain) or any(
            name in names for name in ('nameresolutionerror', 'gaierror')) or any(
            phrase in messages for phrase in ('getaddrinfo failed', 'failed to resolve',
                                               'name resolution', 'nodename nor servname')):
        return f'Keep could not resolve the {label} host. Check its saved hostname and container DNS/network access.'
    if any(isinstance(item, (requests.Timeout, TimeoutError, socket.timeout)) for item in chain) or any(
            number in errors for number in (errno.ETIMEDOUT,)) or 'timed out' in messages:
        return f'Keep timed out while reaching {label}. Check the saved address, service availability, firewall, and network route.'
    if any(isinstance(item, ConnectionRefusedError) for item in chain) or errno.ECONNREFUSED in errors or 'connection refused' in messages:
        return f'{label} refused the connection. Check that the service is running and that its saved port is reachable from Keep.'
    if any(isinstance(item, (ssl.SSLError, requests.exceptions.SSLError)) for item in chain) or any(
            'certificate' in name or 'sslerror' in name for name in names):
        return f'TLS verification failed while connecting to {label}. Check the service certificate and use a trusted HTTPS address.'
    if any(isinstance(item, ET.ParseError) for item in chain):
        return f'{label} returned invalid XML. Check the service response and supported version.'
    if any(isinstance(item, ValueError) for item in chain):
        if 'not configured' in messages:
            return f'{label} is missing required saved settings. Save its address and required credentials, then test again.'
        return f'{label} returned an unexpected response. Check its saved address, API access, and supported version.'
    if any(isinstance(item, requests.RequestException) for item in chain):
        return f'Keep could not complete the connection to {label}. Check the saved address, container network route, and TLS settings.'
    return f'Keep could not verify {label}. Check the saved connection settings, service status, and network access.'


@app.route("/settings/connections", methods=["GET", "POST"])
def settings_connections():
    denied = require_owner()
    if denied:
        return denied
    notice = ""
    error = False
    discovered = None
    collection_error = False
    collection_diagnostic = ''
    if request.method == "POST":
        csrf_error = require_form_csrf()
        if csrf_error:
            return csrf_error
        action = request.form.get("action")
        checked_service = {'plex': 'plex', 'maintainerr': 'maintainerr', 'discover-collections': 'maintainerr',
                           'collections': 'maintainerr',
                           'radarr': 'radarr', 'sonarr': 'sonarr', 'seerr': 'seerr', 'refresh-seerr': 'seerr',
                           'tautulli': 'tautulli', 'smtp': 'email'}.get(action)
        check_fingerprint = connection_settings.connection_fingerprint(checked_service, connection_value) if checked_service else None
        try:
            if action in ("save", "save-plex", "save-maintainerr", "save-radarr",
                          "save-sonarr", "save-seerr", "save-tautulli", "save-email"):
                allowed = {"save": CONNECTION_FIELDS + EMAIL_FIELDS,
                           "save-plex": ('PLEX_SERVER_URL', 'PLEX_MACHINE_IDENTIFIER', 'PLEX_ADMIN_TOKEN'),
                           "save-maintainerr": ('MAINTAINERR_URL',),
                           "save-radarr": ('RADARR_URL', 'RADARR_API_KEY'),
                           "save-sonarr": ('SONARR_URL', 'SONARR_API_KEY'),
                           "save-seerr": ('SEERR_URL', 'SEERR_API_KEY'),
                           "save-tautulli": ('TAUTULLI_URL', 'TAUTULLI_API_KEY'),
                           "save-email": EMAIL_FIELDS}[action]
                values, clear = {}, []
                for name in allowed:
                    if name in os.environ and name not in PLEX_FIELDS:
                        continue
                    if name in SECRETS:
                        mode = request.form.get(name + "_mode", "replace")
                        if mode not in ("keep", "replace", "clear"):
                            raise ValueError('Invalid credential action')
                        if mode == "clear":
                            clear.append(name)
                        elif mode == "replace" and request.form.get(name):
                            values[name] = request.form[name]
                    elif name == "EMAIL_ENABLED" and action == "save-email":
                        values[name] = "true" if request.form.get(name) == "true" else "false"
                    elif name in SERVICE_URL_PORTS:
                        address = service_url_from_form(name, request.form, connection_value(name))
                        if address is not None:
                            values[name] = address
                    elif name in request.form and (request.form[name].strip() or name in ("SMTP_USER", "SMTP_FROM", "SMTP_HOST", "SMTP_SENDER_NAME")):
                        values[name] = request.form[name]
                connection_settings.save(values, clear=clear, plex_override=action in ('save', 'save-plex'))
                _settings_snapshot.set(connection_settings.snapshot())
                log_activity("configuration-updated", "Updated service and email configuration")
                notice = "Settings saved. Future operations will use this configuration."
            elif action in ("remove-PLEX_ADMIN_TOKEN", "remove-SMTP_PASSWORD"):
                connection_settings.save({}, clear=[action.removeprefix("remove-")],
                                         plex_override=action == 'remove-PLEX_ADMIN_TOKEN')
                _settings_snapshot.set(connection_settings.snapshot())
                log_activity("configuration-updated", "Removed saved service credential")
                notice = "Credential removed."
            elif action == "seerr":
                seerr.Client(connection_value).test()
                notice = "Seerr checks passed. Request history refreshes automatically in the background."
            elif action == "tautulli":
                import leaving_forecast
                thresholds = leaving_forecast.tautulli_thresholds(connection_value)
                notice = f"Tautulli connected. Watched thresholds: movies {thresholds['movie']}%, TV {thresholds['tv']}%."
            elif action == "refresh-seerr":
                snapshot = seerr_store().refresh(connection_value)
                notice = f"Attribution refreshed: {len(snapshot['requests'])} requests and {len(snapshot['users'])} accounts. Deletion permissions are unchanged."
                log_activity('seerr-refreshed', 'Owner refreshed read-only requester attribution')
            elif action == "link-seerr":
                raw = request.form.get('seerr_id', '')
                seerr_id = seerr.identifier(int(raw)) if raw else None
                seerr_store().link(connection_value, request.form.get('keep_id', ''), seerr_id, seerr_profiles())
                notice = "Seerr account link saved. This does not grant deletion access."
            elif action == "save-seerr-links":
                profiles = seerr_profiles()
                links = {key.removeprefix('seerr-link-'): (seerr.identifier(int(value)) if value else None)
                         for key, value in request.form.items() if key.startswith('seerr-link-')}
                seerr_store().save_links(connection_value, links, profiles, request.form.get('seerr_scope', ''))
                notice = "Account links saved. Deletion permissions are unchanged."
                log_activity('seerr-linked', 'Owner updated local account requester links')
                log_activity('seerr-linked', 'Owner updated a local account requester link')
            elif action == "smtp":
                test_smtp_connection()
                notice = "SMTP connection, encryption and configured authentication checks passed. No email was sent."
            elif action in ("plex", "maintainerr", "discover-collections", "radarr", "sonarr"):
                if action == "plex":
                    test_plex(connection_value('PLEX_SERVER_URL'), connection_value('PLEX_ADMIN_TOKEN'), connection_value('PLEX_MACHINE_IDENTIFIER'))
                    notice = "Plex identity and account-access checks passed."
                elif action in ("radarr", "sonarr"):
                    status = media_services.test_connection(action, connection_value)
                    found = refresh_media_libraries(action)
                    notice = (f"{action.title()} {status['version']} connection succeeded. "
                              f"Discovered {len(found)} media {'library' if len(found) == 1 else 'libraries'}.")
                else:
                    discovered = discover_collections(connection_value('MAINTAINERR_URL'))
                    notice = "Maintainerr connection succeeded. Select the collections to show in Keep."
            elif action == "collections":
                if 'KEEP_COLLECTIONS' in os.environ:
                    return "Collections are managed by environment", 400
                discovered = discover_collections(connection_value('MAINTAINERR_URL'))
                selected = request.form.getlist('collection_id')
                if any(not value.isdecimal() or int(value) not in discovered for value in selected):
                    return "Select collections returned by Maintainerr", 400
                connection_settings.save({'KEEP_COLLECTIONS': json.dumps({value: discovered[int(value)] for value in selected})})
                _settings_snapshot.set(connection_settings.snapshot())
                log_activity("configuration-updated", "Updated collection selection")
                notice = "Collection selection saved. Existing keeps and subscriptions have been retained."
            else:
                return "Unknown action", 400
        except seerr.RefreshBusy:
            error = True
            notice = 'A Seerr refresh is already running. Wait for it to finish, then try again.'
        except seerr.ResponseError as exc:
            error = True
            notice = connection_failure_message('seerr', exc)
        except (ValueError, ET.ParseError) as exc:
            error = True
            notice = ("Seerr request history could not be imported. Its response was incomplete, changed during refresh, or exceeded import limits. Try Refresh attribution again; any previous snapshot has been preserved."
                      if action == 'refresh-seerr' else
                      "Account links could not be saved. Reload this page, check that the request history is current, and select a different Seerr account for each local user."
                      if action == 'save-seerr-links' else
                      connection_failure_message(checked_service, exc)
                      if checked_service else
                      "Could not complete this action. Check the settings and service response, then try again.")
        except requests.RequestException as exc:
            error = True
            notice = connection_failure_message(checked_service, exc)
        except (smtplib.SMTPException, OSError) as exc:
            error = True
            notice = connection_failure_message(checked_service or 'email', exc)
        if checked_service:
            connection_settings.record_check(checked_service, check_fingerprint, not error)
    if error and request.form.get('action') in ('maintainerr', 'discover-collections', 'collections'):
        collection_error = True
        collection_diagnostic = notice
    labels = dict(zip(CONNECTION_FIELDS + EMAIL_FIELDS, (
        'Maintainerr URL', 'Plex server URL', 'Plex machine identifier', 'Plex administrator token',
        'Radarr URL', 'Radarr API key', 'Sonarr URL', 'Sonarr API key',
        'Seerr URL', 'Seerr API key', 'Tautulli URL', 'Tautulli API key',
        'Email delivery', 'SMTP host', 'SMTP port', 'SMTP encryption', 'SMTP username',
        'SMTP password', 'Sender email address', 'Sender display name')))
    fields = [{"name": name, "label": labels[name], "managed": name in os.environ and name not in PLEX_FIELDS,
               "secret": name in MASKED_CONNECTION_FIELDS,
               "removable": name in SECRETS,
               "configured": name in MASKED_CONNECTION_FIELDS and bool(connection_value(name)),
               "value": "" if name in MASKED_CONNECTION_FIELDS else connection_value(name)}
              for name in CONNECTION_FIELDS + EMAIL_FIELDS]
    response = app.make_response(render_template("connections.html", fields={field['name']: field for field in fields},
        url_parts={name: split_service_url(name, connection_value(name)) for name in SERVICE_URL_PORTS},
        open_services=connection_open_services(request.form, request.form.get('action')),
        seerr_review=seerr_review(),
        automatic_states=connection_settings.automatic_states(connection_value),
        notice=notice, error=error, csrf_token=get_csrf_token(), setup_pending=onboarding.pending(),
        discovered=discovered, collection_error=collection_error,
        collection_diagnostic=collection_diagnostic,
        selected=get_collections(), collections_managed='KEEP_COLLECTIONS' in os.environ))
    response.headers["Cache-Control"] = "no-store"
    return response


def seerr_store():
    return seerr.Store(KEEP_DB_PATH)


def seerr_profiles():
    with closing(attribution_db()) as db:
        return [dict(row) for row in db.execute(
            "SELECT plex_id,auth_type,display_name,plex_username FROM user_profiles ORDER BY display_name")]


def seerr_review():
    store = seerr_store()
    snapshot = store.read(connection_value)
    profiles = seerr_profiles()
    identities = store.identities(connection_value, snapshot, profiles)
    links = {str(profile['plex_id']): key for key, profile in identities.items()}
    return {**snapshot, 'profiles': profiles, 'links': links,
            'scope': seerr.namespace(connection_value),
            'linked_count': len(identities),
            'stamp': datetime.fromtimestamp(snapshot['updated'], timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if snapshot['updated'] else 'Not refreshed'}


@app.post("/settings/connections/reveal")
def reveal_connection_secret():
    denied = require_owner()
    if denied:
        response = app.make_response(denied)
    else:
        csrf_error = require_form_csrf()
        name = request.form.get("name")
        if csrf_error:
            response = app.make_response(csrf_error)
        elif name not in MASKED_CONNECTION_FIELDS:
            response = app.make_response(("Credential cannot be revealed here", 403))
        else:
            response = jsonify(value=connection_settings.get(name))
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/settings/users")
def settings_users():
    return render_settings_section("users")


@app.get("/settings/email")
def settings_email():
    return render_settings_section("email")


@app.get("/settings/activity")
def settings_activity():
    return render_settings_section("activity")


@app.get("/settings/jobs")
def settings_jobs():
    denied = require_owner()
    if denied:
        return denied
    snapshot = job_store().snapshot(connection_value, connection_settings,
        heartbeat_path=DIGEST_WORKER_HEARTBEAT_PATH,
        plex_interval=max(30, PLEX_ACCESS_SYNC_SECONDS), reminder_interval=REMINDER_SCAN_SECONDS)
    response = app.make_response(render_template("jobs.html", jobs_snapshot=snapshot))
    response.headers['Cache-Control'] = 'no-store'
    return response


def render_settings_section(section):
    denied = require_owner()
    if denied:
        return denied
    activity_filters = {
        "all": ("All activity", ""),
        "users": ("Users & access", "WHERE action LIKE 'user-%' OR action LIKE 'password-%' OR action IN ('login', 'plex-access-changed')"),
        "api": ("API keys", "WHERE action LIKE 'api-key-%'"),
        "email": ("Email", "WHERE action LIKE 'recipient-%' OR action LIKE 'digest-%' OR action IN ('subscriptions-updated', 'personal-preferences-updated')"),
        "keeps": ("Keeps", "WHERE action LIKE 'keep-%' OR action LIKE 'api-keep-%'"),
        "library": ("Library deletion", "WHERE action LIKE 'media-%'"),
    }
    activity_filter = request.args.get("filter", "all")
    if activity_filter not in activity_filters:
        activity_filter = "all"
    try:
        activity_page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        activity_page = 1
    activity_page_size = 50
    activity_where = activity_filters[activity_filter][1]
    with closing(attribution_db()) as db:
        users = [dict(row) for row in db.execute("""
            SELECT plex_id, plex_username, email, full_name, display_name,
                   can_remove_any, can_keep_indefinitely, can_delete_media, can_delete_any,
                   auth_type, status, password_hash,
                   invite_expires_at, last_seen_at, plex_access, plex_checked_at
            FROM user_profiles
            ORDER BY COALESCE(NULLIF(full_name, ''), NULLIF(display_name, ''), plex_username)
            COLLATE NOCASE
        """)]
        libraries = [dict(row) for row in db.execute(
            "SELECT * FROM media_libraries ORDER BY name COLLATE NOCASE, service")]
        library_grants = {}
        for row in db.execute("SELECT user_id, library_key FROM user_library_permissions"):
            library_grants.setdefault(row["user_id"], set()).add(row["library_key"])
        recipients = [dict(row) for row in db.execute(
            "SELECT email, enabled FROM email_recipients ORDER BY email COLLATE NOCASE"
        )]
        subscriptions = db.execute("""SELECT email, collection_id FROM recipient_subscriptions
            WHERE enabled = 1""").fetchall()
        subscription_map = {}
        for subscription in subscriptions:
            subscription_map.setdefault(subscription["email"].casefold(), set()).add(
                subscription["collection_id"])
        for recipient in recipients:
            recipient["subscriptions"] = subscription_map.get(recipient["email"].casefold(), set())
        activity_count = db.execute(
            f"SELECT COUNT(*) FROM activity_log {activity_where}"
        ).fetchone()[0]
        activity_pages = max(1, (activity_count + activity_page_size - 1) // activity_page_size)
        activity_page = min(activity_page, activity_pages)
        activities = [dict(row) for row in db.execute(f"""SELECT occurred_at, actor_id, actor_name,
            action, description FROM activity_log {activity_where}
            ORDER BY id DESC LIMIT ? OFFSET ?""",
            (activity_page_size, (activity_page - 1) * activity_page_size))]
        # Older API-key events recorded only an opaque ID and a different alias.
        # Improve their presentation without changing the original audit rows.
        verbs = {'api-key-create': 'Created', 'api-key-revoke': 'Revoked',
                 'api-key-rotate': 'Replaced', 'api-key-remove': 'Removed'}
        for activity in activities:
            if activity['action'] not in verbs:
                continue
            match = re.fullmatch(r'API key ([0-9a-f]{32})', activity['description'])
            if not match:
                continue
            key = db.execute('SELECT name FROM api_keys WHERE id=? AND user_id=?',
                             (match[1], activity['actor_id'])).fetchone()
            activity['description'] = verbs[activity['action']] + ' API key' + (f' “{key[0]}”' if key else '')
            profile = db.execute('SELECT * FROM user_profiles WHERE plex_id=?',
                                 (activity['actor_id'],)).fetchone()
            if profile:
                actor = (local_session_user(profile) if profile['auth_type'] == 'local' else
                         {'username': profile['plex_username']})
                activity['actor_name'] = activity_actor(actor)[1]
        pending = db.execute("SELECT COUNT(*) FROM notification_queue").fetchone()[0]
        held = db.execute(
            "SELECT COUNT(*) FROM notification_batches WHERE status = 'review'"
        ).fetchone()[0]
        newest = db.execute(
            "SELECT MAX(received_at) FROM notification_queue WHERE batch_id IS NULL"
        ).fetchone()[0]
    for user in users:
        user["last_seen_label"] = relative_timestamp(user["last_seen_at"])
        user["invite_label"] = invite_expiry_label(user["invite_expires_at"])
        user["is_owner"] = str(user["plex_id"]) == owner_id()
        if user["is_owner"]:
            user["access_label"], user["access_tone"] = "Active", "on"
        elif user["status"] == "disabled":
            user["access_label"], user["access_tone"] = "Disabled", "off"
        elif user["auth_type"] == "plex" and user["plex_access"] == "revoked":
            user["access_label"], user["access_tone"] = "No Plex access", "warn"
        else:
            user["access_label"] = user["status"].title()
            user["access_tone"] = "on" if user["status"] == "active" else "warn"
        user["plex_checked_label"] = relative_timestamp(user["plex_checked_at"])
        user["library_grants"] = ({library["library_key"] for library in libraries}
                                  if user["is_owner"] else
                                  library_grants.get(user["plex_id"], set()))
    for activity in activities:
        activity["when"] = relative_timestamp(activity["occurred_at"])
    due_text = "No email pending"
    if newest:
        seconds = max(0, int(newest + DIGEST_QUIET_SECONDS - time.time()))
        due_text = "Sending soon" if seconds == 0 else f"About {(seconds + 59) // 60} min remaining"
    notices = {
        "user": "User names saved.",
        "recipient": "Recipient settings saved.",
        "local": "Local user created and setup email sent.",
        "invite": "A new password setup link was emailed.",
        "access": "User access updated.",
        "deleted": "Local user deleted. Their recipient entry, if any, remains separate.",
        "subscriptions": "Email collection preferences saved.",
    }
    notice = notices.get(session.pop("settings_notice", None))
    settings_error = session.pop("settings_error", None)
    settings_error_email = session.pop("settings_error_email", "")
    return render_template_string("""
<!doctype html>
<html lang="en" data-theme="{{ theme_mode }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <script src="/static/keep-theme.js?v={{ app_version }}"></script>
    <meta name="color-scheme" content="dark">
    <meta name="theme-color" content="#f5a623">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-title" content="Keep">
    <link rel="icon" type="image/svg+xml" href="/static/keep-icon.svg?v=20260907-2">
    <link rel="icon" type="image/png" sizes="32x32" href="/static/favicon-32.png?v=20260907-2">
    <link rel="apple-touch-icon" sizes="180x180" href="/static/apple-touch-icon.png?v=20260907-2">
    <link rel="manifest" href="/static/site.webmanifest">
    <title>{{ section_title }} · Keep Admin</title>
    <style>
        * { box-sizing: border-box; }
        :root {
            --background:#090a0d; --surface:rgba(27,29,35,.82); --surface-2:#121318;
            --border:rgba(255,255,255,.09); --text:#f5f6f7; --muted:#969ba6;
            --accent:#f5a623; --accent-hover:#ffb638; --danger:#ff7676;
        }
        html { background:var(--background); }
        body {
            margin:0; min-height:100vh; color:var(--text);
            font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
            background:radial-gradient(circle at 15% -10%,rgba(245,166,35,.13),transparent 32rem),
                       radial-gradient(circle at 85% 0%,rgba(92,82,255,.08),transparent 30rem),
                       var(--background);
        }
        .page { width:min(1180px,100%); margin:auto; padding:44px 28px 80px; }
        .topbar { display:flex; justify-content:space-between; align-items:center; gap:20px; margin-bottom:40px; }
        .brand { display:flex; align-items:center; gap:15px; }
        .mark { width:52px; height:52px; display:grid; place-items:center; border-radius:15px;
            background:linear-gradient(145deg,#ffbe52,#e78712); color:#111; font-size:28px;
            font-weight:900; box-shadow:0 12px 34px rgba(245,166,35,.2); }
        h1 { margin:0; font-size:34px; line-height:1; letter-spacing:-.04em; }
        .subtitle { margin:7px 0 0; color:var(--muted); font-size:14px; }
        .back { padding:11px 16px; border:1px solid var(--border); border-radius:11px;
            color:var(--text); background:rgba(255,255,255,.04); text-decoration:none; font-weight:700; }
        .admin-nav { display:flex; gap:8px; margin:-18px 0 30px; padding:5px;
            width:max-content; max-width:100%; border:1px solid var(--border); border-radius:13px;
            background:rgba(18,19,24,.72); overflow-x:auto; }
        .admin-nav a { padding:10px 16px; border-radius:9px; color:var(--muted);
            text-decoration:none; font-size:13px; font-weight:800; white-space:nowrap; }
        .admin-nav a:hover { color:var(--text); background:rgba(255,255,255,.04); }
        .admin-nav a.active { color:#17120a; background:linear-gradient(180deg,var(--accent-hover),var(--accent)); }
        .notice { margin:0 0 22px; padding:13px 16px; border:1px solid rgba(245,166,35,.35);
            border-radius:12px; background:rgba(245,166,35,.1); color:#ffd58a;
            transition:opacity .25s ease, transform .25s ease; }
        .notice.dismissed { opacity:0; transform:translateY(-6px); }
        .settings-error { margin:0 0 22px; padding:13px 16px; border:1px solid rgba(255,118,118,.42);
            border-radius:12px; background:rgba(255,118,118,.1); color:#ffb0b0; }
        .summary { display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin-bottom:28px; }
        .stat,.panel { border:1px solid var(--border); border-radius:18px; background:var(--surface);
            box-shadow:0 16px 38px rgba(0,0,0,.22); }
        .stat { padding:18px 20px; }
        .stat-value { margin-top:6px; font-size:22px; font-weight:800; }
        .eyebrow { color:var(--muted); font-size:12px; font-weight:800; letter-spacing:.06em; text-transform:uppercase; }
        .panel { padding:24px; margin-top:20px; }
        .panel-head { display:flex; justify-content:space-between; align-items:flex-start; gap:15px; margin-bottom:18px; }
        h2 { margin:0; font-size:22px; letter-spacing:-.025em; }
        .help { margin:6px 0 0; color:var(--muted); font-size:13px; line-height:1.5; }
        .user-card,.recipient-row { border-top:1px solid var(--border); padding:18px 0; }
        .user-card:first-of-type,.recipient-row:first-of-type { border-top:0; }
        .identity { display:grid; grid-template-columns:1fr 1fr; gap:4px 18px; margin-bottom:13px;
            color:var(--muted); font-size:12px; }
        .identity strong { color:var(--text); font-size:14px; overflow-wrap:anywhere; }
        .account-meta { display:flex; flex-wrap:wrap; gap:8px 18px; margin:-4px 0 14px;
            color:var(--muted); font-size:11px; }
        .source { display:inline-flex; margin-left:7px; padding:3px 7px; border:1px solid var(--border);
            border-radius:999px; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; }
        .source-plex { border-color:rgba(245,166,35,.45); background:rgba(245,166,35,.12); color:#ffc45f; }
        .source-local { border-color:rgba(82,168,255,.42); background:rgba(82,168,255,.12); color:#8bc7ff; }
        .source-owner { border-color:rgba(172,140,255,.48); background:rgba(172,140,255,.14); color:#c9b6ff; }
        .fields { display:grid; grid-template-columns:1fr 1fr minmax(210px,auto) auto; gap:12px; align-items:end; }
        .fields.local-fields { grid-template-columns:1fr 1fr 1fr minmax(210px,auto) auto; }
        label { display:block; color:var(--muted); font-size:12px; font-weight:750; }
        input { width:100%; margin-top:7px; padding:12px 13px; border:1px solid var(--border);
            border-radius:10px; background:var(--surface-2); color:var(--text); font:inherit; }
        input:focus { outline:2px solid rgba(245,166,35,.35); border-color:var(--accent); }
        .permission { min-height:43px; margin:0; padding:9px 12px; display:flex; align-items:center;
            gap:10px; border:1px solid var(--border); border-radius:10px; background:var(--surface-2);
            color:var(--text); font-size:12px; line-height:1.35; }
        .permission input { width:auto; margin:0; accent-color:var(--accent); }
        .permission small { display:block; color:var(--muted); font-size:10px; font-weight:600; }
        button { min-height:43px; padding:0 16px; border:0; border-radius:10px; cursor:pointer;
            background:linear-gradient(180deg,var(--accent-hover),var(--accent)); color:#17120a;
            font:800 13px/1 inherit; }
        .secondary { border:1px solid var(--border); background:rgba(255,255,255,.05); color:var(--text); }
        .danger { border:1px solid rgba(255,118,118,.28); background:rgba(255,118,118,.08); color:#ffaaaa; }
        .recipient-row { display:grid; grid-template-columns:minmax(180px,1fr) minmax(360px,2fr) auto;
            align-items:center; gap:18px; }
        .recipient-address { font-weight:700; overflow-wrap:anywhere; }
        .status { margin-top:4px; color:var(--muted); font-size:12px; }
        .status.on { color:#69db9b; }
        .status.off { color:#ff9292; }
        .status.warn { color:#ffc45f; }
        .recipient-actions { display:flex; gap:8px; flex-shrink:0; }
        .subscriptions { display:flex; flex-wrap:wrap; align-items:center; gap:8px; }
        .subscriptions.disabled { opacity:.48; }
        .subscriptions.disabled .subscription { color:var(--muted); cursor:not-allowed; }
        .subscriptions.disabled button { cursor:not-allowed; }
        .subscription { display:flex; align-items:center; gap:6px; padding:7px 9px;
            border:1px solid var(--border); border-radius:9px; background:var(--surface-2);
            color:var(--text); font-size:11px; transition:border-color .18s ease,background .18s ease; }
        .subscription input { width:auto; margin:0; accent-color:var(--accent); }
        .subscription-error { display:none; flex-basis:100%; margin:0; color:#ff9b9b;
            font-size:12px; font-weight:700; }
        .subscriptions.invalid .subscription { border-color:rgba(255,118,118,.72);
            background:rgba(255,118,118,.08); }
        .subscriptions.invalid .subscription-error { display:block; }
        .activity-list { display:grid; }
        .activity-row { display:grid; grid-template-columns:120px 150px 1fr; gap:14px;
            padding:13px 0; border-top:1px solid var(--border); font-size:13px; }
        .activity-row:first-child { border-top:0; }
        .activity-when,.activity-actor { color:var(--muted); }
        .activity-filters { display:flex; flex-wrap:wrap; gap:8px; margin-top:16px; }
        .activity-filters a,.pager a,.pager span { padding:8px 11px; border:1px solid var(--border);
            border-radius:9px; color:var(--muted); background:var(--surface-2);
            text-decoration:none; font-size:11px; font-weight:750; }
        .activity-filters a.active { border-color:rgba(245,166,35,.45); color:#ffc45f;
            background:rgba(245,166,35,.1); }
        .pager { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-top:18px; }
        .pager span { border-color:transparent; background:transparent; }
        .pager .disabled { opacity:.38; pointer-events:none; }
        .add-form { display:grid; grid-template-columns:1fr auto; gap:12px; margin-top:16px; }
        .add-form input { margin:0; }
        .account-actions { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
        .permissions { grid-column:1 / -1; margin:4px 0 0; padding:16px; border:1px solid var(--border);
            border-radius:12px; background:var(--surface-2); }
        .permissions legend { padding:0 7px; color:var(--text); font-size:13px; font-weight:750; }
        .permissions .permission { margin-top:10px; }
        .library-permissions { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px 16px;
            margin:12px 0 0 28px; padding-top:10px; border-top:1px solid var(--border); }
        .library-permissions[hidden] { display:none; }
        .library-permission small { display:block; color:var(--muted); }
        .account-actions form { margin:0; }
        .add-user-form { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)) minmax(190px,auto) auto;
            gap:12px; align-items:end; }
        .empty { padding:18px 0; color:var(--muted); }
        @media(max-width:700px) {
            .page { padding:26px 16px 60px; } .topbar { align-items:flex-start; margin-bottom:32px; }
            .admin-nav { width:100%; margin-top:-12px; }
            .summary { grid-template-columns:1fr; } .fields,.fields.local-fields { grid-template-columns:1fr; }
            .identity { grid-template-columns:1fr; } .recipient-row { display:flex; align-items:flex-start; flex-direction:column; }
            .recipient-actions { width:100%; } .recipient-actions form { flex:1; }
            .recipient-actions button { width:100%; } .add-form { grid-template-columns:1fr; }
            .add-user-form { grid-template-columns:1fr; }
            .library-permissions { grid-template-columns:1fr; margin-left:0; }
            .activity-row { grid-template-columns:1fr; gap:3px; }
        }
    </style>
<link rel="stylesheet" href="/static/keep-ui.css?v={{ app_version }}">
<script defer src="/static/keep-toast.js?v=2.4.6"></script>
<script defer src="/static/keep-interactions.js?v={{ app_version }}"></script>
{% include 'shared_assets.html' %}
</head>
<body class="admin-ui">{% include 'shared_whats_new.html' %}<a class="skip-link" href="#main-content">Skip to content</a>
    <main class="page" id="main-content" tabindex="-1">
    {% include 'shared_header.html' %}
    <div class="page-heading"><h2>{{ {'users':'Users', 'email':'Email', 'activity':'Activity'}[section] }}</h2><p class="subtitle">{{ {'users':'Manage accounts, library access, and Keep permissions. Display names appear publicly; full names stay here.', 'email':'Manage digest recipients and the collections they follow.', 'activity':'Review account, library, and email activity.'}[section] }}</p></div>
    {% include 'shared_admin_tabs.html' %}
    {% if notice %}<div class="notice" id="settings-saved-notice" role="status">{{ notice }}</div>{% endif %}
    {% if settings_error %}<div class="settings-error" role="alert">{{ settings_error }}</div>{% endif %}
    {% if section == "users" %}
    {% include 'admin_toolbar.html' %}
    <details class="panel creation-panel" hidden>
        <summary><span>Add local user</span><svg class="creation-chevron" width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m6 9 6 6 6-6" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg></summary>
        <div class="creation-content"><p class="help">{% if email_delivery_enabled %}Keep emails a single-use setup link.{% else %}Keep provides a private, single-use setup link for you to share.{% endif %} You never create or see the user’s password.</p>
        <form class="add-user-form" method="post" action="/settings/users/local">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label>Email<input type="email" name="email" maxlength="254" required placeholder="name@example.com"></label>
            <label>Full name<input name="full_name" maxlength="120" required placeholder="Alex Johnson"></label>
            <label>Display name<input name="display_name" maxlength="60" required placeholder="Alex J"></label>
            <label class="permission"><input type="checkbox" name="add_recipient" value="1">
                <span>Add to email recipients<small>Enable consolidated digest emails</small></span></label>
            <button type="submit">Add and invite</button>
        </form>
        </div>
    </details>
    <section class="panel admin-card-list">
        {% for user in users %}
        <article class="user-card">
                        <button type="button" class="admin-card-header" data-user-toggle aria-expanded="false" aria-controls="user-editor-{{ user.plex_id }}" aria-label="Edit {{ user.display_name or user.plex_username or 'user' }}">
            <span class="identity">
                <span>Account <span class="source source-{{ user.auth_type }}">{{ user.auth_type }}</span>{% if user.is_owner %}<span class="source source-owner"><svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m12 3 8 3v6c0 4-5 7-8 9-3-2-8-5-8-9V6l8-3Z" stroke="currentColor" stroke-width="1.7"/><path d="m8 12 3 3 5-6" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>Owner</span>{% endif %}<br><strong>{{ user.plex_username or user.display_name or "Local user" }}</strong></span>
                <span>Email<br><strong>{{ user.email or "Not provided" }}</strong><br>
                    <span class="status {{ user.access_tone }}">{{ user.access_label }}</span></span>
            </span>
            <span class="visually-hidden" data-edit-label>Edit</span>{% include "admin_chevron.html" %}</button>
            <div class="user-editor" id="user-editor-{{ user.plex_id }}" hidden>
            <div class="account-meta">
                <span>Last sign-in: {{ user.last_seen_label }}</span>
                {% if user.auth_type == "plex" %}<span>Plex access checked: {{ user.plex_checked_label }}</span>{% endif %}
                {% if user.auth_type == "local" and user.status == "pending" %}<span>{{ user.invite_label }}</span>{% endif %}
            </div>
            <form data-save-key="user-{{ user.plex_id }}" class="fields{% if user.auth_type == 'local' %} local-fields{% endif %}" method="post" action="/settings/users/{{ user.plex_id }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                {% if user.auth_type == "local" %}<label>Email<input type="email" name="email" maxlength="254" required value="{{ user.email }}"></label>{% endif %}
                <label>Full name<input name="full_name" maxlength="120" value="{{ user.full_name }}" placeholder="Alex Morgan"></label>
                <label>Display name<input name="display_name" maxlength="60" value="{{ user.display_name }}" placeholder="Alex M"></label>
                <fieldset class="permissions"><legend>Permissions</legend>
                <label class="permission"><input type="checkbox" name="can_keep_indefinitely" value="1"
                    {% if user.is_owner or user.can_keep_indefinitely %}checked{% endif %}
                    {% if user.is_owner %}disabled{% endif %}>
                    <span>Can keep titles indefinitely{% if user.is_owner %}<small>Owner permission is permanent</small>{% endif %}</span></label>
                <label class="permission"><input type="checkbox" name="can_remove_any" value="1"
                    {% if user.plex_id == owner_plex_id or user.can_remove_any %}checked{% endif %}
                    {% if user.plex_id == owner_plex_id %}disabled{% endif %}>
                    <span>Can manage anyone’s keeps<small>{% if user.plex_id == owner_plex_id %}Owner permission is permanent{% else %}Includes changing duration and removing the keep{% endif %}</small></span></label>
                <label class="permission"><input type="checkbox" name="can_delete_media" value="1" data-library-permission-toggle
                    {% if user.is_owner or user.can_delete_media %}checked{% endif %}
                    {% if user.is_owner %}disabled{% endif %}>
                    <span>Library access<small>{% if user.is_owner %}Owner permission is permanent{% else %}See and delete only movies and TV seasons requested exclusively by this user, within selected libraries{% endif %}</small></span></label>
                <label class="permission"><input type="checkbox" name="can_delete_any" value="1"
                    {% if user.is_owner or user.can_delete_any %}checked{% endif %}
                    {% if user.is_owner %}disabled{% endif %}>
                    <span>Delete any title<small>{% if user.is_owner %}Owner permission is permanent{% else %}Requires library access. Includes shared or unknown requests and whole series, within selected libraries only{% endif %}</small></span></label>
                {% if libraries %}<div class="library-permissions" data-library-permissions aria-label="Libraries this user can manage">
                    {% for library in libraries %}<label class="permission library-permission"><input type="checkbox" name="library_key" value="{{ library.library_key }}"
                        {% if user.is_owner or library.library_key in user.library_grants %}checked{% endif %}
                        {% if user.is_owner %}disabled{% endif %}>
                        <span>{{ library.name }}<small>{{ library.service|title }}</small></span></label>{% endfor %}
                </div>{% else %}<p class="help">Connect Radarr or Sonarr to discover libraries.</p>{% endif %}
                </fieldset>
                <div class="user-save-row">
                    {% if not user.is_owner %}
                    <div class="account-actions">
                        {% if user.auth_type == "local" and user.status != "disabled" %}
                        <button form="user-{{ user.plex_id }}-invite" class="secondary" type="submit">{{ ("Send password reset" if user.password_hash else "Resend setup link") if email_delivery_enabled else ("Get password reset link" if user.password_hash else "Get setup link") }}</button>
                        {% endif %}
                        {% if user.status != "disabled" %}
                        <button form="user-{{ user.plex_id }}-disable" class="danger" type="submit">Disable access</button>
                        {% else %}
                        <button form="user-{{ user.plex_id }}-enable" class="secondary" type="submit">Enable access</button>
                        {% endif %}
                        {% if user.auth_type == "local" %}
                        <button form="user-{{ user.plex_id }}-delete" class="danger" type="submit">Delete user</button>
                        {% endif %}
                    </div>
                    {% endif %}
                    <button class="save-button" type="submit">Save</button>
                </div>
            </form>
            {% if not user.is_owner %}
            {% if user.auth_type == "local" and user.status != "disabled" %}
            <form id="user-{{ user.plex_id }}-invite" method="post" action="/settings/users/{{ user.plex_id }}/access">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <input type="hidden" name="action" value="invite">
            </form>
            {% endif %}
            {% if user.status != "disabled" %}
            <form id="user-{{ user.plex_id }}-disable" method="post" action="/settings/users/{{ user.plex_id }}/access">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <input type="hidden" name="action" value="disable">
            </form>
            {% endif %}
            {% if user.status == "disabled" %}
            <form id="user-{{ user.plex_id }}-enable" method="post" action="/settings/users/{{ user.plex_id }}/access">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <input type="hidden" name="action" value="enable">
            </form>
            {% endif %}
            {% if user.auth_type == "local" %}
            <form id="user-{{ user.plex_id }}-delete" method="post" action="/settings/users/{{ user.plex_id }}/access"
                  onsubmit="return confirm('Delete this local user? Their email recipient entry will remain separate.');">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <input type="hidden" name="action" value="delete">
            </form>
            {% endif %}
            {% endif %}
            </div>
        </article>
        {% else %}<div class="empty">No linked Plex users have been imported yet.</div>{% endfor %}
    </section>
    {% endif %}
    {% if section == "email" %}
    {% include 'admin_toolbar.html' %}
    <details class="panel creation-panel" hidden>
        <summary><span>Add email recipient</span><svg class="creation-chevron" width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m6 9 6 6 6-6" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg></summary>
        <div class="creation-content"><p class="help">Add an address to the consolidated Keep digest. New recipients receive all configured collection topics by default.</p>
        <form class="add-form" method="post" action="/settings/recipients">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="action" value="add">
            <input type="email" name="email" maxlength="254" required placeholder="name@example.com" aria-label="New recipient email">
            <button type="submit">Add recipient</button>
        </form>
        </div>
    </details>
    <div class="summary">
        <div class="stat"><div class="eyebrow">Active recipients</div><div class="stat-value">{{ active_recipients }}</div></div>
        <div class="stat"><div class="eyebrow">Queued titles</div><div class="stat-value">{{ pending }}</div></div>
        <div class="stat"><div class="eyebrow">Next digest</div><div class="stat-value">{{ due_text }}</div></div>
    </div>
    {% if held %}<div class="notice">{{ held }} email batch requires review before automatic delivery can continue.</div>{% endif %}
    <section class="panel admin-card-list">
        <div class="panel-head"><div><h2>Email recipients</h2><p class="help">Enabled recipients receive consolidated Keep emails. At least one must remain enabled.</p></div></div>
        {% for recipient in recipients %}
        <div class="recipient-row">
                        <button type="button" class="admin-card-header" data-user-toggle aria-expanded="false" aria-controls="recipient-editor-{{ loop.index }}" aria-label="Edit {{ recipient.email }}">
            <span><span class="recipient-address">{{ recipient.email }}</span>
                <span class="status{% if recipient.enabled %} on{% endif %}">{{ "Enabled" if recipient.enabled else "Disabled" }} · {{ recipient.subscriptions|length }} topics</span></span>
            <span class="visually-hidden" data-edit-label>Edit</span>{% include "admin_chevron.html" %}</button>
            <div class="user-editor" id="recipient-editor-{{ loop.index }}" {% if settings_error_email != recipient.email %}hidden{% endif %}>
            <form data-save-key="recipient-{{ loop.index }}" class="subscriptions{% if not recipient.enabled %} disabled{% endif %}{% if settings_error_email == recipient.email %} invalid{% endif %}" method="post" action="/settings/recipients/preferences" novalidate
                {% if not recipient.enabled %}aria-disabled="true"{% endif %}>
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <input type="hidden" name="email" value="{{ recipient.email }}">
                {% for collection_id, collection_name in collections.items() %}
                <label class="subscription"><input type="checkbox" name="collection_id" value="{{ collection_id }}"
                    {% if collection_id in recipient.subscriptions %}checked{% endif %}{% if not recipient.enabled %} disabled{% endif %}>
                    {{ collection_name.replace(" Leaving Plex Soon", "") }}</label>
                {% endfor %}
                <button class="save-button" type="submit"{% if not recipient.enabled %} disabled{% endif %}>Save</button>
                <p class="subscription-error" role="alert" aria-live="polite">Choose at least one email topic.</p>
            </form>
            <div class="recipient-actions">
                <form method="post" action="/settings/recipients">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <input type="hidden" name="email" value="{{ recipient.email }}">
                    <input type="hidden" name="action" value="{{ 'disable' if recipient.enabled else 'enable' }}">
                    <button class="secondary" type="submit">{{ "Disable" if recipient.enabled else "Enable" }}</button>
                </form>
                <form method="post" action="/settings/recipients">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <input type="hidden" name="email" value="{{ recipient.email }}">
                    <input type="hidden" name="action" value="remove">
                    <button class="danger" type="submit">Remove</button>
                </form>
            </div>
            </div>
        </div>
        {% endfor %}
    </section>
    {% endif %}
    {% if section == "activity" %}
    <section class="panel">
        <div class="panel-head"><div><h2>Recent activity</h2><p class="help">Security, user, recipient, email, and Keep actions.</p>
            <label class="activity-mobile-filter">Activity type<select>{% for filter_key, filter_data in activity_filters.items() %}<option value="/settings/activity?filter={{ filter_key }}" {% if activity_filter == filter_key %}selected{% endif %}>{{ filter_data[0] }}</option>{% endfor %}</select></label>
            <div class="activity-filters">
            {% for filter_key, filter_data in activity_filters.items() %}
                <a href="/settings/activity?filter={{ filter_key }}" class="{% if activity_filter == filter_key %}active{% endif %}">{{ filter_data[0] }}</a>
            {% endfor %}
            </div></div></div>
        <div class="activity-list">
        {% for activity in activities %}
            <div class="activity-row"><span class="activity-when">{{ activity.when }}</span>
                <span class="activity-actor">{{ activity.actor_name }}</span>
                <span>{{ activity.description }}</span></div>
        {% else %}<div class="empty">No activity has been recorded yet.</div>{% endfor %}
        </div>
        <div class="pager">
            {% if activity_page > 1 %}<a href="/settings/activity?filter={{ activity_filter }}&amp;page={{ activity_page - 1 }}">Previous</a>{% else %}<a class="disabled" aria-disabled="true">Previous</a>{% endif %}
            <span>Page {{ activity_page }} of {{ activity_pages }}</span>
            {% if activity_page < activity_pages %}<a href="/settings/activity?filter={{ activity_filter }}&amp;page={{ activity_page + 1 }}">Next</a>{% else %}<a class="disabled" aria-disabled="true">Next</a>{% endif %}
        </div>
    </section>
    {% endif %}
    <script>
        const savedNotice = document.getElementById("settings-saved-notice");
        if (savedNotice) {
            window.setTimeout(() => {
                savedNotice.classList.add("dismissed");
                window.setTimeout(() => savedNotice.remove(), 250);
            }, 3500);
        }
        const currentUrl = new URL(window.location.href);
        if (currentUrl.searchParams.has("saved")) {
            currentUrl.searchParams.delete("saved");
            window.history.replaceState({}, "", currentUrl);
        }
        document.querySelectorAll(".subscriptions").forEach((form) => {
            const topicInputs = [...form.querySelectorAll('input[name="collection_id"]')];
            const validateTopics = () => {
                const valid = topicInputs.some((input) => input.checked);
                form.classList.toggle("invalid", !valid);
                return valid;
            };
            topicInputs.forEach((input) => input.addEventListener("change", validateTopics));
            form.addEventListener("submit", (event) => {
                if (!validateTopics()) {
                    event.preventDefault();
                    form.querySelector(".subscription-error").scrollIntoView({behavior:"smooth", block:"center"});
                }
            });
        });
        document.querySelectorAll(".permissions").forEach((group) => {
            const toggle = group.querySelector("[data-library-permission-toggle]");
            const libraryPermissions = group.querySelector("[data-library-permissions]");
            if (!toggle || !libraryPermissions) return;
            const syncLibraryPermissions = () => {
                const visible = toggle.checked;
                libraryPermissions.hidden = !visible;
                libraryPermissions.querySelectorAll("input").forEach((input) => {
                    input.disabled = !visible || toggle.disabled;
                });
            };
            toggle.addEventListener("change", syncLibraryPermissions);
            syncLibraryPermissions();
        });
    </script>
</main></body></html>
    """, section=section, section_title={"users": "Users", "email": "Email",
                                          "activity": "Activity"}[section],
        users=users, recipients=recipients, activities=activities,
        activity_filters=activity_filters, activity_filter=activity_filter,
        activity_page=activity_page, activity_pages=activity_pages,
        collections=get_collections(), active_recipients=sum(r["enabled"] for r in recipients),
        pending=pending, held=held, due_text=due_text, notice=notice,
        settings_error=settings_error, settings_error_email=settings_error_email,
        owner_plex_id=owner_id(), email_delivery_enabled=email_enabled(), csrf_token=get_csrf_token(),
        libraries=libraries)


@app.post("/settings/users/<plex_id>")
def save_user_settings(plex_id):
    denied = require_owner()
    if denied:
        return denied
    csrf_error = require_form_csrf()
    if csrf_error:
        return csrf_error
    full_name = " ".join(request.form.get("full_name", "").split())
    display_name = " ".join(request.form.get("display_name", "").split())
    with closing(attribution_db()) as db:
        profile = db.execute("SELECT auth_type, email FROM user_profiles WHERE plex_id = ?",
                             (str(plex_id),)).fetchone()
    if not profile:
        return "Plex user not found", 404
    email_address = profile["email"]
    if profile["auth_type"] == "local":
        email_address = request.form.get("email", "").strip().lower()
        if len(email_address) > 254 or not EMAIL_ADDRESS.fullmatch(email_address):
            return "Enter a valid email address", 400
    can_remove_any = int(
        str(plex_id) != owner_id() and request.form.get("can_remove_any") == "1"
    )
    can_keep_forever = int(
        str(plex_id) != owner_id() and request.form.get("can_keep_indefinitely") == "1"
    )
    can_delete = int(
        str(plex_id) != owner_id() and request.form.get("can_delete_media") == "1"
    )
    selected_libraries = set(request.form.getlist("library_key")) if can_delete else set()
    can_delete_any = int(can_delete and request.form.get('can_delete_any') == '1')
    available_libraries = {library["library_key"] for library in media_libraries()}
    if not selected_libraries.issubset(available_libraries):
        return "Select configured media libraries", 400
    if len(full_name) > 120 or len(display_name) > 60:
        return "Name is too long", 400
    try:
        with closing(attribution_db()) as db, db:
            changed = db.execute(
                """UPDATE user_profiles
                   SET email = ?, full_name = ?, display_name = ?, can_remove_any = ?,
                       can_keep_indefinitely = ?, can_delete_media = ?, can_delete_any = ?
                   WHERE plex_id = ?""",
                (email_address, full_name, display_name, can_remove_any,
                 can_keep_forever, can_delete, can_delete_any, str(plex_id)),
            ).rowcount
            if str(plex_id) != owner_id():
                db.execute("DELETE FROM user_library_permissions WHERE user_id = ?", (str(plex_id),))
                db.executemany("""INSERT INTO user_library_permissions(user_id, library_key)
                    VALUES (?, ?)""", ((str(plex_id), key) for key in selected_libraries))
    except sqlite3.IntegrityError:
        return "A local user with that email address already exists", 409
    if not changed:
        return "Plex user not found", 404
    log_activity("user-updated", f"Updated user profile for {display_name or full_name or email_address}")
    return redirect_to_settings_with_notice("user")


EMAIL_ADDRESS = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.post("/settings/users/local")
def create_local_user():
    denied = require_owner()
    if denied:
        return denied
    csrf_error = require_form_csrf()
    if csrf_error:
        return csrf_error
    email_address = request.form.get("email", "").strip().lower()
    full_name = " ".join(request.form.get("full_name", "").split())
    display_name = " ".join(request.form.get("display_name", "").split())
    add_recipient = request.form.get("add_recipient") == "1"
    if len(email_address) > 254 or not EMAIL_ADDRESS.fullmatch(email_address):
        return "Enter a valid email address", 400
    if not full_name or not display_name:
        return "Full name and display name are required", 400
    if len(full_name) > 120 or len(display_name) > 60:
        return "Name is too long", 400
    local_id = f"local:{uuid.uuid4().hex}"
    try:
        with closing(attribution_db()) as db, db:
            db.execute("""INSERT INTO user_profiles
                (plex_id, email, full_name, display_name, auth_type, status)
                VALUES (?, ?, ?, ?, 'local', 'pending')""",
                (local_id, email_address, full_name, display_name))
            if add_recipient:
                db.execute("""INSERT INTO email_recipients(email, enabled) VALUES (?, 1)
                    ON CONFLICT(email) DO UPDATE SET enabled = 1""", (email_address,))
                ensure_recipient_subscriptions(db, email_address)
    except sqlite3.IntegrityError:
        return "A local user with that email address already exists", 409
    log_activity("user-created", f"Added local user {full_name}")
    if add_recipient:
        log_activity("recipient-added", f"Enabled digest email for {email_address}")
    try:
        token = issue_local_setup(local_id)
        if not email_enabled():
            return private_setup_link(token)
    except Exception:
        app.logger.error("Local account created but setup email failed for %s", local_id)
        return "The account was created, but the setup email could not be sent. Use Resend setup link in Settings.", 502
    return redirect_to_settings_with_notice("local")


@app.post("/settings/users/<path:user_id>/access")
def update_user_access(user_id):
    denied = require_owner()
    if denied:
        return denied
    csrf_error = require_form_csrf()
    if csrf_error:
        return csrf_error
    with closing(attribution_db()) as db:
        profile = db.execute("SELECT * FROM user_profiles WHERE plex_id = ?",
                             (user_id,)).fetchone()
    if not profile:
        return "User not found", 404
    if str(user_id) == owner_id():
        return "Owner access cannot be changed", 400
    action = request.form.get("action")
    if action == "invite":
        if profile["auth_type"] != "local":
            return "Password links are only available for local users", 400
        if profile["status"] == "disabled":
            return "Enable this account before sending a setup link", 400
        try:
            token = issue_local_setup(user_id, reset=bool(profile["password_hash"]))
            if not email_enabled():
                return private_setup_link(token)
        except Exception:
            app.logger.error("Could not send local setup email for %s", user_id)
            return "The setup email could not be sent", 502
        log_activity("password-link-sent", f"Sent a password link to {profile['email']}")
        return redirect_to_settings_with_notice("invite")
    if action == "delete":
        if profile["auth_type"] != "local":
            return "Plex users cannot be deleted manually", 400
        label = profile["full_name"] or profile["display_name"] or profile["email"]
        with closing(attribution_db()) as db, db:
            db.execute("DELETE FROM user_library_permissions WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM user_feature_acknowledgements WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM user_profiles WHERE plex_id = ?", (user_id,))
        log_activity("user-deleted", f"Deleted local user {label}")
        return redirect_to_settings_with_notice("deleted")
    if action not in ("disable", "enable"):
        return "Invalid access action", 400
    with closing(attribution_db()) as db, db:
        if action == "disable":
            db.execute("""UPDATE user_profiles SET status = 'disabled',
                invite_token_hash = NULL, invite_expires_at = NULL,
                session_version = session_version + 1 WHERE plex_id = ?""", (user_id,))
        else:
            next_status = ("active" if profile["auth_type"] == "plex" or profile["password_hash"]
                           else "pending")
            db.execute("UPDATE user_profiles SET status = ? WHERE plex_id = ?",
                       (next_status, user_id))
    label = (profile["full_name"] or profile["display_name"] or
             profile["plex_username"] or profile["email"])
    log_activity(f"user-{action}d", f"{action.title()}d access for {label}")
    return redirect_to_settings_with_notice("access")


@app.post("/settings/recipients")
def save_recipient_settings():
    denied = require_owner()
    if denied:
        return denied
    csrf_error = require_form_csrf()
    if csrf_error:
        return csrf_error
    action = request.form.get("action")
    address = request.form.get("email", "").strip().lower()
    if len(address) > 254 or not EMAIL_ADDRESS.fullmatch(address):
        return "Enter a valid email address", 400
    with closing(attribution_db()) as db, db:
        db.execute("BEGIN IMMEDIATE")
        if action == "add":
            db.execute("""INSERT INTO email_recipients(email, enabled) VALUES (?, 1)
                          ON CONFLICT(email) DO UPDATE SET enabled = 1""", (address,))
            ensure_recipient_subscriptions(db, address)
        elif action == "enable":
            if not db.execute("UPDATE email_recipients SET enabled = 1 WHERE email = ?", (address,)).rowcount:
                return "Recipient not found", 404
        elif action in ("disable", "remove"):
            recipient = db.execute(
                "SELECT enabled FROM email_recipients WHERE email = ?", (address,)
            ).fetchone()
            if not recipient:
                return "Recipient not found", 404
            enabled_count = db.execute(
                "SELECT COUNT(*) FROM email_recipients WHERE enabled = 1"
            ).fetchone()[0]
            if recipient["enabled"] and enabled_count <= 1:
                return "At least one email recipient must remain enabled", 400
            if action == "disable":
                db.execute("UPDATE email_recipients SET enabled = 0 WHERE email = ?", (address,))
            else:
                db.execute("DELETE FROM email_recipients WHERE email = ?", (address,))
                db.execute("DELETE FROM recipient_subscriptions WHERE email = ?", (address,))
        else:
            return "Invalid recipient action", 400
    action_words = {"add": "Added", "enable": "Enabled", "disable": "Disabled", "remove": "Removed"}
    log_activity(f"recipient-{action}", f"{action_words[action]} email recipient {address}")
    return redirect_to_settings_with_notice("recipient")


@app.post("/settings/recipients/preferences")
def save_recipient_preferences():
    denied = require_owner()
    if denied:
        return denied
    csrf_error = require_form_csrf()
    if csrf_error:
        return csrf_error
    address = request.form.get("email", "").strip().lower()
    try:
        selected = {int(value) for value in request.form.getlist("collection_id")}
    except ValueError:
        return redirect_to_settings_with_error("Choose at least one valid email topic.", address)
    if not selected or not selected.issubset(set(recipient_collection_ids())):
        return redirect_to_settings_with_error(
            "Choose at least one email topic for this recipient.", address
        )
    with closing(attribution_db()) as db, db:
        if not db.execute("SELECT 1 FROM email_recipients WHERE email = ?", (address,)).fetchone():
            return "Recipient not found", 404
        ensure_recipient_subscriptions(db, address)
        db.execute("UPDATE recipient_subscriptions SET enabled = 0 WHERE email = ?",
                   (address,))
        db.executemany("""UPDATE recipient_subscriptions SET enabled = 1
            WHERE email = ? AND collection_id = ?""",
            ((address, collection_id) for collection_id in selected))
    labels = ", ".join(get_collections()[cid].replace(" Leaving Plex Soon", "")
                       for cid in sorted(selected))
    log_activity("subscriptions-updated", f"Set {address} email topics to {labels}")
    return redirect_to_settings_with_notice("subscriptions")



def require_csrf():
    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token")

    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        return jsonify({"error": "invalid csrf token"}), 403

    return None


@app.post("/api/announcements/seen")
def mark_announcement_seen():
    csrf_error = require_csrf()
    if csrf_error:
        return csrf_error
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or payload.get("version") != ANNOUNCEMENT_VERSION:
        return jsonify(error="This announcement has changed. Refresh the page and try again."), 409
    user_id = str(session["plex_user"]["id"])
    with closing(attribution_db()) as db, db:
        db.execute("""INSERT INTO user_feature_acknowledgements
            (user_id, feature_key, version, acknowledged_at)
            VALUES (?, 'whats-new', ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id, feature_key) DO UPDATE SET
                version=excluded.version, acknowledged_at=CURRENT_TIMESTAMP""",
            (user_id, ANNOUNCEMENT_VERSION))
    response = jsonify(status="seen")
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@app.post("/api/remove-kept")
@serialized_keep_change
def remove_kept():
    csrf_error = require_csrf()
    if csrf_error:
        return csrf_error
    payload = request.get_json(silent=True) or {}

    exclusion_id = payload.get("exclusionId")
    collection_id = payload.get("collectionId")

    if not exclusion_id or collection_id not in get_collections():
        return jsonify({"error": "invalid request"}), 400

    try:
        exclusion = next((item for item in get_collection_exclusions(collection_id).get("items", [])
                          if str(item.get("id")) == str(exclusion_id)), None)
        if exclusion is None:
            return jsonify({"error": "exclusion not found in collection"}), 404

        media_id = str(exclusion["mediaServerId"])
        if not current_account_session():
            return jsonify(error="Account access changed. Sign in again."), 403
        if not can_remove_keep(collection_id, media_id):
            return jsonify({"error": "Only the user who kept this item or a Keep manager can remove it"}), 403

        change_maintainerr_exclusion(media_id, collection_id, 1)

        with closing(attribution_db()) as db, db:
            db.execute("DELETE FROM keep_attribution WHERE collection_id = ? AND media_id = ?",
                       (str(collection_id), media_id))
            db.execute("DELETE FROM keep_schedules WHERE collection_id = ? AND media_id = ?",
                       (str(collection_id), media_id))

        title = (exclusion.get("mediaData") or {}).get("title") or f"Plex item {media_id}"
        log_activity("keep-removed", f"Removed {title} from Kept in {get_collections()[collection_id]}")

        return jsonify({"status": "removed"})
    except requests.RequestException:
        return jsonify({"error": "Keep could not remove this title. Please try again."}), 502


@app.post("/api/update-keep")
@serialized_keep_change
def update_keep():
    csrf_error = require_csrf()
    if csrf_error:
        return csrf_error
    payload = request.get_json(silent=True) or {}
    collection_id = payload.get("collectionId")
    media_id = str(payload.get("mediaId") or "")
    duration = payload.get("duration")
    if not media_id or collection_id not in get_collections() or duration not in {"temporary", "indefinite"}:
        return jsonify({"error": "invalid request"}), 400

    try:
        exclusion = next((item for item in get_collection_exclusions(collection_id).get("items", [])
                          if str(item.get("mediaServerId")) == media_id), None)
        if exclusion is None:
            return jsonify({"error": "exclusion not found in collection"}), 404
        if not current_account_session():
            return jsonify(error="Account access changed. Sign in again."), 403
        if not can_manage_keep(collection_id, media_id):
            return jsonify({"error": "Only the user who kept this item or a Keep manager can change its duration"}), 403
        if duration == "indefinite" and not can_keep_indefinitely():
            return jsonify({"error": "Indefinite keeps require permission"}), 403

        expires_at = None
        extension_available_at = None
        if duration == "temporary":
            now = datetime.now(timezone.utc)
            with closing(attribution_db()) as db, db:
                db.execute("BEGIN IMMEDIATE")
                existing = db.execute("""SELECT expires_at, extension_available_at
                    FROM keep_schedules WHERE collection_id = ? AND media_id = ?""",
                    (str(collection_id), media_id)).fetchone()
                if existing and existing["expires_at"]:
                    available_text = existing["extension_available_at"]
                    if available_text:
                        available = datetime.strptime(
                            available_text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                        if now < available:
                            return jsonify({"error": "Extension is not available yet",
                                            "availableAt": available_text}), 409
                    current = datetime.strptime(
                        existing["expires_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    expires_at = temporary_keep_expiry(max(now, current))
                    extension_available_at = db_timestamp(current)
                else:
                    expires_at = temporary_keep_expiry(now)
                db.execute("""INSERT INTO keep_schedules
                    (collection_id, media_id, expires_at, extension_available_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(collection_id, media_id) DO UPDATE SET
                        expires_at=excluded.expires_at,
                        extension_available_at=excluded.extension_available_at""",
                    (str(collection_id), media_id, expires_at, extension_available_at))
        else:
            with closing(attribution_db()) as db, db:
                db.execute("""INSERT INTO keep_schedules
                    (collection_id, media_id, expires_at, extension_available_at)
                    VALUES (?, ?, NULL, NULL)
                    ON CONFLICT(collection_id, media_id) DO UPDATE SET
                        expires_at=NULL, extension_available_at=NULL""",
                    (str(collection_id), media_id))

        title = (exclusion.get("mediaData") or {}).get("title") or f"Plex item {media_id}"
        action = "Extended" if duration == "temporary" else "Made indefinite"
        log_activity("keep-updated", f"{action} keep for {title} in {get_collections()[collection_id]}")
        return jsonify({"status": "updated", "duration": duration, "expiresAt": expires_at,
                        "extensionAvailableAt": extension_available_at})
    except requests.RequestException:
        return jsonify({"error": "Keep could not update this title. Please try again."}), 502


@app.get("/health")
def health():
    return {"status": "ok"}, 200


@app.get("/api/counts")
def media_counts():
    try:
        counts = {
            "leaving": sum(len(get_collection_media(cid).get("items", [])) for cid in get_collections()),
            "kept": sum(len(get_collection_exclusions(cid).get("items", [])) for cid in get_collections()),
        }
    except requests.RequestException:
        return jsonify({"error": "Counts temporarily unavailable"}), 502
    response = jsonify(counts)
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.get("/api/media")
def media():
    result = {}

    for collection_id, collection_name in get_collections().items():
        data = get_collection_media(collection_id)

        result[str(collection_id)] = {
            "name": collection_name,
            "total": data.get("totalSize", 0),
            "items": data.get("items", []),
        }

    return jsonify(result)


@app.post("/api/keep")
@serialized_keep_change
def keep():
    csrf_error = require_csrf()
    if csrf_error:
        return csrf_error

    data = request.get_json(silent=True) or {}

    media_id = data.get("mediaId")
    collection_id = data.get("collectionId")
    duration = data.get("duration", "temporary")

    if not media_id or collection_id not in get_collections() or duration not in {"temporary", "indefinite"}:
        return {"error": "Invalid request"}, 400
    if duration == "indefinite" and not can_keep_indefinitely():
        return {"error": "Indefinite keeps require permission"}, 403

    collection_data = get_collection_media(collection_id)

    valid_media_ids = {
        str(item.get("mediaServerId"))
        for item in collection_data.get("items", [])
    }

    if str(media_id) not in valid_media_ids:
        return {"error": "Media item is not eligible for KEEP"}, 400
    media_item = next(item for item in collection_data.get("items", [])
                      if str(item.get("mediaServerId")) == str(media_id))

    if not current_account_session():
        return jsonify(error="Account access changed. Sign in again."), 403
    change_maintainerr_exclusion(media_id, collection_id, 0)

    record_keeper(collection_id, media_id, session["plex_user"], duration=duration)
    cancel_queued_notifications(collection_id, media_id)

    # Remove only this title's collection membership. A full rule execution
    # would also re-add unrelated titles whose exclusions were just removed.
    removal = requests.delete(
        f"{connection_value('MAINTAINERR_URL')}/api/collections/media",
        params={"mediaId": str(media_id), "collectionId": collection_id},
        timeout=30,
    )
    removal.raise_for_status()

    title = (media_item.get("mediaData") or {}).get("title") or f"Plex item {media_id}"
    duration_label = "for 30 days" if duration == "temporary" else "indefinitely"
    log_activity("keep-added", f"Kept {title} {duration_label} from {get_collections()[collection_id]}")

    return {"status": "protected", "duration": duration}, 200

# Webhook events are durably queued; only the dedicated worker sends mail.
DIGEST_QUIET_SECONDS = max(60, int(os.environ.get("DIGEST_QUIET_SECONDS", "600")))
DIGEST_WORKER_HEARTBEAT_PATH = os.environ.get(
    "DIGEST_WORKER_HEARTBEAT_PATH",
    os.path.join(os.path.dirname(os.path.abspath(KEEP_DB_PATH)), "digest-worker.heartbeat"),
)
REMINDER_SCAN_SECONDS = 15 * 60
REMINDER_KIND = "MEDIA_ABOUT_TO_BE_HANDLED"
DIGEST_TYPES = {"MEDIA_ADDED_TO_COLLECTION", "MEDIA_ABOUT_TO_BE_HANDLED"}


def job_store():
    store = app.extensions.get('keep_jobs')
    if store is None or store.path != KEEP_DB_PATH:
        store = background_jobs.Store(KEEP_DB_PATH, logger=app.logger)
        app.extensions['keep_jobs'] = store
    return store


def background_maintenance_once(state):
    """One existing worker pass, with durable, credential-free job results."""
    jobs = job_store()
    jobs.run('onboarding-cleanup', onboarding.cleanup)
    _settings_snapshot.set(connection_settings.snapshot())
    if time.monotonic() - state['plex_sync'] >= PLEX_ACCESS_SYNC_SECONDS:
        changed = jobs.run('plex-access-sync', sync_plex_user_access,
            interval=max(30, PLEX_ACCESS_SYNC_SECONDS) if PLEX_ACCESS_SYNC_SECONDS <= 604800 else None,
            result_fn=lambda count: ('failed', 'Connection unavailable') if count is None
                else ('success', f'Updated {count} accounts'))
        state['plex_sync'] = time.monotonic()
        if changed:
            app.logger.warning("Updated Plex access for %s Keep users", changed)
    expiry = jobs.run('keep-expiry', expire_due_keeps,
        result_fn=lambda result: ('failed', 'Some Keeps will be retried') if result['failed']
            else ('success', f"Released {result['released']} Keeps"))
    if expiry['released'] or expiry['missing']:
        app.logger.warning("Processed temporary keeps: %s released, %s already absent",
                           expiry['released'], expiry['missing'])
    if expiry['failed']:
        app.logger.error("Could not process %s temporary keeps; retrying", expiry['failed'])
    if state['reminder_scan'] is None or time.monotonic() - state['reminder_scan'] >= REMINDER_SCAN_SECONDS:
        try:
            queued = jobs.run('reminder-scan', queue_due_reminders,
                interval=REMINDER_SCAN_SECONDS,
                result_fn=lambda count: ('success', f'Queued {count} reminders'))
            state['reminder_scan'] = time.monotonic()
            if queued:
                app.logger.warning("Queued %s seven-day catch-up reminders", queued)
        except Exception:
            app.logger.error("Seven-day reminder scan failed; retrying in 30 seconds")
    jobs.run('reminder-reconcile', reconcile_reminder_queue)
    removed = jobs.run('queue-cleanup', prune_notification_queue,
        result_fn=lambda count: ('success', f'Removed {count} titles'))
    if removed:
        app.logger.warning("Removed %s stale titles from the digest queue", removed)
    result = jobs.run('email-digest', process_digest, result_fn=digest_job_result)
    if result == 'review':
        app.logger.error("Digest delivery requires review; automatic sending paused")


def digest_job_result(state):
    if state == 'review':
        return 'review', 'Delivery needs review'
    if state == 'disabled':
        return 'disabled', 'Email is disabled'
    if state == 'sent':
        return 'success', 'Completed'
    if state == 'empty':
        return 'success', 'No changes'
    return 'waiting', 'Waiting for queued work'


def seerr_job_due(kind, getter, now=None):
    """Use Seerr's own persisted schedule; polling is not a completed job run."""
    now = time.time() if now is None else now
    scope = seerr.namespace(getter)
    with closing(attribution_db()) as db:
        if kind == 'availability':
            row = db.execute('SELECT due FROM seerr_availability_queue WHERE scope=?', (scope,)).fetchone()
            return bool(row and now >= row['due'])
        if kind != 'history':
            raise ValueError('Unknown Seerr job')
        row = db.execute('SELECT next_attempt FROM seerr_refresh WHERE scope=?', (scope,)).fetchone()
        if row:
            return now >= row['next_attempt']
        row = db.execute('SELECT updated FROM seerr_cache WHERE scope=?', (scope,)).fetchone()
        return not row or now >= row['updated'] + seerr.REFRESH_INTERVAL

with closing(attribution_db()) as db, db:
    db.execute("BEGIN IMMEDIATE")
    db.execute("""CREATE TABLE IF NOT EXISTS notification_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        collection_id INTEGER NOT NULL,
        media_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        received_at REAL NOT NULL,
        batch_id TEXT
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS notification_batches (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        created_at REAL NOT NULL,
        detail TEXT
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS notification_deliveries (
        batch_id TEXT NOT NULL,
        email TEXT NOT NULL COLLATE NOCASE,
        sent_at REAL NOT NULL,
        PRIMARY KEY (batch_id, email)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS notification_reminders (
        collection_id INTEGER NOT NULL,
        media_id TEXT NOT NULL,
        episode TEXT NOT NULL,
        queue_id INTEGER NOT NULL,
        queued_at REAL NOT NULL,
        PRIMARY KEY (collection_id, media_id, episode)
    )""")
    db.execute("""CREATE INDEX IF NOT EXISTS notification_pending
                  ON notification_queue(batch_id, received_at)""")


def cancel_queued_notifications(collection_id, media_id):
    """Remove every unsent notification for one title."""
    with closing(attribution_db()) as db, db:
        return db.execute(
            "DELETE FROM notification_queue WHERE collection_id = ? AND media_id = ?",
            (collection_id, str(media_id)),
        ).rowcount


def queue_notifications(collection_id, media_ids, kind, now=None):
    now = time.time() if now is None else now
    with closing(attribution_db()) as db, db:
        db.execute("BEGIN IMMEDIATE")
        for media_id in set(media_ids):
            existing = db.execute("""SELECT id FROM notification_queue
                WHERE collection_id = ? AND media_id = ? AND kind = ? AND batch_id IS NULL
                """, (collection_id, str(media_id), kind)).fetchone()
            if existing:
                # Retransmitted reminders must not keep extending the quiet window.
                if kind != REMINDER_KIND:
                    db.execute("UPDATE notification_queue SET received_at = ? WHERE id = ?",
                               (now, existing["id"]))
            else:
                db.execute("""INSERT INTO notification_queue
                    (collection_id, media_id, kind, received_at) VALUES (?, ?, ?, ?)""",
                           (collection_id, str(media_id), kind, now))


def prune_notification_queue():
    """Drop pending titles that are no longer active in their collection."""
    with closing(attribution_db()) as db:
        pending = [dict(row) for row in db.execute("""SELECT id, collection_id, media_id
            FROM notification_queue WHERE batch_id IS NULL""")]
    if not pending:
        return 0

    active_by_collection = {
        collection_id: set(digest_collection_items(collection_id))
        for collection_id in {row["collection_id"] for row in pending}
    }
    stale_ids = [
        row["id"] for row in pending
        if row["media_id"] not in active_by_collection[row["collection_id"]]
    ]
    if not stale_ids:
        return 0
    with closing(attribution_db()) as db, db:
        db.executemany(
            "DELETE FROM notification_queue WHERE id = ? AND batch_id IS NULL",
            ((row_id,) for row_id in stale_ids),
        )
    return len(stale_ids)


@app.post("/api/webhooks/maintainerr")
def maintainerr_webhook():
    supplied = request.headers.get("Authorization", "")
    if not KEEP_WEBHOOK_SECRET or not secrets.compare_digest(supplied, f"Bearer {KEEP_WEBHOOK_SECRET}"):
        return {"error": "Unauthorized"}, 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return {"error": "Invalid webhook payload"}, 400
    kind = data.get("notificationType")
    if kind not in DIGEST_TYPES:
        return {"status": "ignored"}, 200
    collection_id = next((cid for cid, name in get_collections().items()
                          if name == data.get("collectionName")), None)
    if collection_id is None:
        if kind == REMINDER_KIND:
            # Maintainerr's timer aggregates media across collections and omits
            # collectionName. Resolve membership in the worker, never in HTTP.
            collection_id = 0
        else:
            return {"error": "Unknown collection"}, 400
    media_items = data.get("mediaItems", [])
    if isinstance(media_items, str):
        try:
            media_items = json.loads(media_items)
        except ValueError:
            return {"error": "Invalid mediaItems"}, 400
    if isinstance(media_items, dict):
        media_items = [media_items]
    ids = [data.get("mediaServerId")]
    if isinstance(media_items, list):
        ids.extend(item.get("mediaServerId") for item in media_items if isinstance(item, dict))
    ids = {str(value) for value in ids if isinstance(value, (str, int)) and str(value).strip()}
    if not ids:
        return {"error": "Missing media IDs"}, 400
    queue_notifications(collection_id, ids, kind)
    return {"status": "queued", "items": len(ids)}, 200


def digest_collection_items(collection_id):
    # Rule runs can add more than the first 100 titles returned by Maintainerr.
    def pages(category):
        result = []
        page = 1
        seen = set()
        while True:
            response = requests.get(
                f"{connection_value('MAINTAINERR_URL')}/api/collections/{category}/{collection_id}/content/{page}",
                params={"size": 100}, timeout=15)
            response.raise_for_status()
            items = response.json().get("items", [])
            if not items:
                return result
            marker = tuple(str(item.get("mediaServerId")) for item in items)
            if marker in seen:
                raise RuntimeError("Maintainerr pagination repeated a page")
            seen.add(marker)
            result.extend(items)
            if len(items) < 100:
                return result
            page += 1
    excluded = {str(item.get("mediaServerId")) for item in pages("exclusions")}
    return {str(item.get("mediaServerId")): item for item in pages("media")
            if str(item.get("mediaServerId")) not in excluded}


def reminder_episode(item):
    """Canonical Leaving entry time; never guess an episode from missing data."""
    try:
        added = datetime.fromisoformat(item["addDate"].replace("Z", "+00:00"))
        if added.tzinfo is None:
            return None
        return added.astimezone(timezone.utc).isoformat()
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def reconcile_reminder_queue():
    """Resolve aggregate webhooks and deduplicate warnings before any batch sends.

    Claims survive completed queue cleanup. Existing in-flight batches take
    precedence over new pending events, including batches held for SMTP review.
    """
    with closing(attribution_db()) as db:
        unscoped = [dict(row) for row in db.execute(
            "SELECT * FROM notification_queue WHERE kind = ? AND collection_id = 0",
            (REMINDER_KIND,))]
    if unscoped:
        # Gather all snapshots before changing the aggregate event. An upstream
        # failure retains it intact for the next worker attempt.
        snapshots = {cid: digest_collection_items(cid) for cid in get_collections()}
        with closing(attribution_db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            for row in unscoped:
                for cid, items in snapshots.items():
                    if row["media_id"] not in items:
                        continue
                    if not db.execute("""SELECT 1 FROM notification_queue WHERE
                        collection_id = ? AND media_id = ? AND kind = ?""",
                        (cid, row["media_id"], REMINDER_KIND)).fetchone():
                        db.execute("""INSERT INTO notification_queue
                            (collection_id, media_id, kind, received_at) VALUES (?, ?, ?, ?)""",
                            (cid, row["media_id"], REMINDER_KIND, row["received_at"]))
                db.execute("DELETE FROM notification_queue WHERE id = ?", (row["id"],))
    with closing(attribution_db()) as db:
        warnings = [dict(row) for row in db.execute("""SELECT * FROM notification_queue
            WHERE kind = ? ORDER BY batch_id IS NULL, received_at, id""", (REMINDER_KIND,))]
    snapshots = {cid: digest_collection_items(cid) for cid in
                 {row["collection_id"] for row in warnings} if cid in get_collections()}
    with closing(attribution_db()) as db, db:
        db.execute("BEGIN IMMEDIATE")
        for row in warnings:
            item = snapshots.get(row["collection_id"], {}).get(row["media_id"])
            if item is None:
                if row["batch_id"] is None:
                    db.execute("DELETE FROM notification_queue WHERE id = ?", (row["id"],))
                continue
            episode = reminder_episode(item)
            if episode is None:
                # A malformed date must not permit an untracked reminder send.
                raise ValueError("Reminder missing a valid Leaving entry timestamp")
            db.execute("""INSERT OR IGNORE INTO notification_reminders
                (collection_id, media_id, episode, queue_id, queued_at) VALUES (?, ?, ?, ?, ?)""",
                (row["collection_id"], row["media_id"], episode, row["id"], row["received_at"]))
            claim = db.execute("""SELECT queue_id FROM notification_reminders
                WHERE collection_id = ? AND media_id = ? AND episode = ?""",
                (row["collection_id"], row["media_id"], episode)).fetchone()
            if claim["queue_id"] != row["id"] and row["batch_id"] is None:
                db.execute("DELETE FROM notification_queue WHERE id = ?", (row["id"],))


def queue_due_reminders(now=None):
    """Catch up active, unprotected titles with at most seven days remaining.

    Only queues mail; normal recipient preferences, batching and SMTP safeguards
    still apply. Dates, retention and collection membership must be known.
    """
    if not email_enabled():
        return 0
    now = time.time() if now is None else now
    reconcile_reminder_queue()
    candidates = []
    for cid in get_collections():
        retention = get_collection_delete_after_days(cid)
        if isinstance(retention, bool) or not isinstance(retention, (int, float)) or not math.isfinite(retention) or retention <= 0:
            raise ValueError("Reminder scan needs a valid collection retention")
        for media_id, item in digest_collection_items(cid).items():
            episode = reminder_episode(item)
            if episode is None:
                continue
            added = datetime.fromisoformat(episode).timestamp()
            remaining = added + retention * 86400 - now
            if 0 < remaining <= 7 * 86400:
                candidates.append((cid, media_id, episode))
    queued = 0
    with closing(attribution_db()) as db, db:
        db.execute("BEGIN IMMEDIATE")
        for cid, media_id, episode in candidates:
            if db.execute("""SELECT 1 FROM notification_reminders
                WHERE collection_id = ? AND media_id = ? AND episode = ?""",
                (cid, media_id, episode)).fetchone():
                continue
            result = db.execute("""INSERT INTO notification_queue
                (collection_id, media_id, kind, received_at) VALUES (?, ?, ?, ?)""",
                (cid, media_id, REMINDER_KIND, now))
            db.execute("""INSERT INTO notification_reminders
                (collection_id, media_id, episode, queue_id, queued_at) VALUES (?, ?, ?, ?, ?)""",
                (cid, media_id, episode, result.lastrowid, now))
            queued += 1
    return queued


def resolve_digest(events):
    resolved = {}
    for cid in sorted({event["collection_id"] for event in events}):
        if cid not in get_collections():
            continue
        current = digest_collection_items(cid)
        retention = get_collection_delete_after_days(cid)
        for event in events:
            if event["collection_id"] != cid:
                continue
            item = current.get(event["media_id"])
            if item is None:  # Already kept or removed while the batch was waiting.
                continue
            key = (cid, event["media_id"])
            urgent = event["kind"] == "MEDIA_ABOUT_TO_BE_HANDLED"
            if key in resolved:
                resolved[key]["urgent"] |= urgent
                continue
            media = item.get("mediaData") or {}
            add_date = item.get("addDate")
            resolved[key] = {
                "collection_id": cid,
                "collection": get_collections()[cid].replace(" Leaving Plex Soon", ""),
                "title": media.get("title") or f"Plex item {event['media_id']}",
                "year": media.get("year"),
                "poster_url": item.get("image_path") or "",
                "days": calculate_days_left(add_date, retention),
                "removal_date": calculate_removal_date(add_date, retention),
                "urgent": urgent,
            }
    return sorted(resolved.values(), key=lambda item: (item["collection"], item["title"].casefold()))


def build_digest_email(items, keep_url):
    return email_templates.digest_email(items, keep_url)


def process_digest(now=None):
    if not email_enabled():
        return "disabled"
    # A filesystem lock in digest_worker prevents two workers from claiming/sending.
    now = time.time() if now is None else now
    reconcile_reminder_queue()
    with closing(attribution_db()) as db, db:
        db.execute("BEGIN IMMEDIATE")
        # SMTP cannot guarantee exactly-once delivery after a crash. Hold uncertain
        # batches for review rather than resend a potentially delivered email.
        db.execute("UPDATE notification_batches SET status = 'review', detail = 'Worker interrupted during SMTP delivery' WHERE status = 'sending'")
        if db.execute("SELECT 1 FROM notification_batches WHERE status = 'review'").fetchone():
            return "review"
        batch = db.execute("SELECT id FROM notification_batches WHERE status = 'building' ORDER BY created_at LIMIT 1").fetchone()
        if batch:
            batch_id = batch["id"]
        else:
            newest = db.execute("SELECT MAX(received_at) FROM notification_queue WHERE batch_id IS NULL").fetchone()[0]
            if newest is None or now - newest < DIGEST_QUIET_SECONDS:
                return "waiting"
            batch_id = uuid.uuid4().hex
            db.execute("INSERT INTO notification_batches(id, status, created_at) VALUES (?, 'building', ?)", (batch_id, now))
            db.execute("UPDATE notification_queue SET batch_id = ? WHERE batch_id IS NULL", (batch_id,))
        events = [dict(row) for row in db.execute("SELECT * FROM notification_queue WHERE batch_id = ?", (batch_id,))]
    items = resolve_digest(events)  # Failures here are safe to retry; no mail sent.
    delivery_target_count = 0
    if items:
        preferences = get_recipient_delivery_preferences()
        if preferences and not connection_value('KEEP_URL'):
            raise RuntimeError('Digest needs KEEP_URL')
        with closing(attribution_db()) as db:
            delivered = {row["email"].casefold() for row in db.execute(
                "SELECT email FROM notification_deliveries WHERE batch_id = ?", (batch_id,)
            )}
        for email_address, collection_ids in preferences.items():
            recipient_items = [item for item in items
                               if item["collection_id"] in collection_ids]
            if recipient_items:
                delivery_target_count += 1
            if not recipient_items or email_address.casefold() in delivered:
                continue
            subject, body, plain = build_digest_email(recipient_items, connection_value('KEEP_URL'))
            with closing(attribution_db()) as db, db:
                db.execute("UPDATE notification_batches SET status = 'sending' WHERE id = ?",
                           (batch_id,))
            try:
                send_email([email_address], subject, body, plain)
            except Exception:
                with closing(attribution_db()) as db, db:
                    db.execute("""UPDATE notification_batches SET status = 'review',
                        detail = 'SMTP delivery failed or is uncertain; check logs before retrying'
                        WHERE id = ?""", (batch_id,))
                app.logger.error("Digest %s held for review after SMTP error", batch_id)
                return "review"
            with closing(attribution_db()) as db, db:
                db.execute("""INSERT OR IGNORE INTO notification_deliveries
                    (batch_id, email, sent_at) VALUES (?, ?, ?)""",
                    (batch_id, email_address, time.time()))
                db.execute("UPDATE notification_batches SET status = 'building' WHERE id = ?",
                           (batch_id,))
    with closing(attribution_db()) as db, db:
        db.execute("UPDATE notification_batches SET status = 'sent', detail = ? WHERE id = ?", (f"{len(items)} titles", batch_id))
        db.execute("DELETE FROM notification_queue WHERE batch_id = ?", (batch_id,))
        db.execute("DELETE FROM notification_deliveries WHERE batch_id = ?", (batch_id,))
    app.logger.warning("Digest %s completed: %s titles", batch_id, len(items))
    log_activity("digest-completed",
                 f"Completed digest with {len(items)} titles for {delivery_target_count} recipients",
                 actor={"username": "Keep email worker"})
    return "sent" if delivery_target_count else "empty"


def update_digest_worker_heartbeat(now=None):
    heartbeat_dir = os.path.dirname(os.path.abspath(DIGEST_WORKER_HEARTBEAT_PATH))
    os.makedirs(heartbeat_dir, exist_ok=True)
    with open(DIGEST_WORKER_HEARTBEAT_PATH, "a", encoding="utf-8"):
        pass
    timestamp = time.time() if now is None else now
    os.utime(DIGEST_WORKER_HEARTBEAT_PATH, (timestamp, timestamp))


def expire_due_keeps(now=None):
    """Release due exclusions, retaining local state whenever Maintainerr fails."""
    migrate_existing_keep_schedules()
    now = now or datetime.now(timezone.utc)
    with closing(attribution_db()) as db:
        due = [dict(row) for row in db.execute("""SELECT collection_id, media_id, expires_at
            FROM keep_schedules WHERE expires_at IS NOT NULL AND expires_at <= ?
            ORDER BY expires_at, collection_id, media_id""", (db_timestamp(now),))]

    released = 0
    missing = 0
    failed = 0
    configured = get_collections()
    for collection_id in sorted({row["collection_id"] for row in due}):
        try:
            numeric_collection_id = int(collection_id)
        except ValueError:
            failed += sum(row["collection_id"] == collection_id for row in due)
            continue
        collection_rows = [row for row in due if row["collection_id"] == collection_id]
        collection_label = configured.get(numeric_collection_id, f"collection {numeric_collection_id}")
        try:
            exclusions = {
                str(item.get("mediaServerId")): item
                for item in get_collection_exclusions(numeric_collection_id).get("items", [])
            }
        except requests.RequestException:
            failed += len(collection_rows)
            continue

        for row in collection_rows:
            try:
                with keep_mutation_lock():
                    # A renewal may have completed while the due snapshot or
                    # collection response was being read. Check under the same
                    # lock held by every user protection change.
                    with closing(attribution_db()) as db:
                        still_due = db.execute("""SELECT 1 FROM keep_schedules
                            WHERE collection_id = ? AND media_id = ?
                            AND expires_at IS NOT NULL AND expires_at <= ?""",
                            (collection_id, row["media_id"], db_timestamp(now))).fetchone()
                    if not still_due:
                        continue
                    exclusion = exclusions.get(row["media_id"])
                    title = ((exclusion or {}).get("mediaData") or {}).get("title") or f"Plex item {row['media_id']}"
                    if exclusion is not None:
                        try:
                            change_maintainerr_exclusion(row["media_id"], numeric_collection_id, 1)
                        except requests.RequestException:
                            failed += 1
                            continue
                        released += 1
                        log_activity(
                            "keep-expired",
                            f"30-day keep expired for {title} in {collection_label}",
                            actor={"username": "Keep maintenance worker"},
                        )
                    else:
                        missing += 1

                    with closing(attribution_db()) as db, db:
                        db.execute("DELETE FROM keep_schedules WHERE collection_id = ? AND media_id = ?",
                                   (collection_id, row["media_id"]))
                        db.execute("DELETE FROM keep_attribution WHERE collection_id = ? AND media_id = ?",
                                   (collection_id, row["media_id"]))
            except KeepMutationBusy:
                # Keep the due row intact; the next maintenance pass retries it.
                failed += 1

    return {"released": released, "missing": missing, "failed": failed}


def queue_seerr_availability():
    try:
        seerr_store().queue_availability(connection_value)
    except Exception:
        # Media deletion has already succeeded; never turn it into a false failure.
        app.logger.warning('Could not queue Seerr availability sync; scheduled Seerr sync remains available')


def seerr_refresh_worker():
    """Isolate bounded Seerr I/O from mail delivery and keep maintenance."""
    while True:
        try:
            settings = connection_settings.snapshot()
            getter = lambda key: settings.get(key, '')
            store = seerr_store()
            availability = (job_store().run('seerr-availability', lambda: store.process_availability(getter),
                scope=seerr.namespace(getter),
                result_fn=lambda result: ('success', 'Completed') if result
                    else ('waiting', 'Waiting for queued work')) if seerr_job_due('availability', getter)
                else store.process_availability(getter))
            if availability:
                app.logger.info('Seerr availability sync requested after media deletion')
        except Exception:
            app.logger.warning('Seerr availability sync deferred; background retry pending')
        try:
            settings = connection_settings.snapshot()
            getter = lambda key: settings.get(key, '')
            if connection_settings.configured('seerr', getter):
                fingerprint = connection_settings.connection_fingerprint('seerr', getter)
                try:
                    store = seerr_store()
                    refreshed = (job_store().run('seerr-history', lambda: store.refresh(getter, automatic=True),
                        interval=seerr.REFRESH_INTERVAL,
                        scope=seerr.namespace(getter),
                        result_fn=lambda result: ('success', 'Completed') if result is not None
                            else ('waiting', 'Waiting for the next scheduled check'))
                        if seerr_job_due('history', getter) else store.refresh(getter, automatic=True))
                except Exception:
                    before, after = connection_settings.record_automatic_check('seerr', fingerprint, False)
                    if after == 2:
                        app.logger.warning('Seerr automatic connection check failed twice')
                    raise
                if refreshed is not None:
                    before, _ = connection_settings.record_automatic_check('seerr', fingerprint, True)
                    if before:
                        app.logger.info('Seerr automatic connection check recovered')
        except Exception:
            # No URLs, credentials, upstream response bodies, or account data.
            app.logger.warning('Seerr background refresh deferred; retaining previous history')
        time.sleep(30)


def digest_worker():
    import fcntl
    lock_path = os.path.join(os.path.dirname(KEEP_DB_PATH), "digest-worker.lock")
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        job_store().interrupt_running()
        app.logger.warning("Digest worker started; quiet window %s seconds", DIGEST_QUIET_SECONDS)
        import threading
        threading.Thread(target=seerr_refresh_worker, name='seerr-refresh', daemon=True).start()
        threading.Thread(target=connection_monitor_worker, name='connection-monitor', daemon=True).start()
        state = {'plex_sync': 0, 'reminder_scan': None}
        while True:
            update_digest_worker_heartbeat()
            try:
                background_maintenance_once(state)
            except Exception:
                app.logger.error("Keep background work failed; retrying in 30 seconds")
            update_digest_worker_heartbeat()
            time.sleep(30)


def connection_monitor_worker():
    """Keep connection I/O out of digest processing and use persisted due times."""
    while True:
        try:
            settings = connection_settings.snapshot()
            getter = lambda key: settings.get(key, globals().get(key, ''))
            job_store().run('connection-monitor', lambda:
                connection_monitor.run_due(connection_settings, getter, test_smtp_connection, app.logger))
        except Exception:
            app.logger.warning('Automatic connection checks deferred; retrying')
        time.sleep(30)


job_store()
api_v1.ApiV1(sys.modules[__name__])

if __name__ == "__main__":
    if "--digest-worker" in sys.argv:
        digest_worker()
    else:
        app.run(host="0.0.0.0", port=5000)
