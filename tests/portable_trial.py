#!/usr/bin/env python3
"""Seed and verify a disposable synthetic Keep recovery trial database.

Run inside the packaged Keep Python environment, with KEEP_DB_PATH pointing at
the isolated trial database. Modes are seed, verify and fingerprint. This tool
never calls external services or prints fixture credentials or database rows.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path.cwd()))
script_root = Path(__file__).resolve().parents[1]
if (script_root / "app.py").is_file():
    sys.path.insert(0, str(script_root))
from connection_settings import validate as validate_setting


FIXTURE_ID = "keep-portable-recovery-trial-v1"
FIXTURE_PASSWORD = "synthetic-recovery-trial-password-2026"
COLLECTIONS = {"901": "Recovery Trial Movies", "902": "Recovery Trial Series"}
LOCAL_ID = "local-trial"
LOCAL_EMAIL = "local-trial@example.com"
# Public deterministic API bearers belong only to the isolated offline fixture.
# Production key generation uses secrets.token_urlsafe; these values never go
# into a deployment environment, image or reported database output.
# Their SHA-256 lookup hashes match the API protocol; account passwords use Argon2.
RECOVERY_BEARERS = {name: 'keep_' + letter * 43 for name, letter in (
    ('active', 'A'), ('expired', 'B'), ('revoked', 'C'), ('changed', 'D'),
    ('disabled', 'E'), ('replacement', 'F'))}
SEERR_URL = "https://seerr.example.invalid"
SEERR_KEY = "synthetic-seerr-key-for-recovery-trial-only"
SEERR_SCOPE = hashlib.sha256(json.dumps([SEERR_URL, SEERR_KEY]).encode()).hexdigest()
TRIAL_SETTINGS = {
    "KEEP_URL": "https://keep.example.invalid",
    "KEEP_COLLECTIONS": json.dumps(COLLECTIONS, sort_keys=True),
    "EMAIL_ENABLED": "false",
    "SMTP_HOST": "smtp.example.invalid",
    "SMTP_PORT": "587",
    "SMTP_SECURITY": "starttls",
    "SMTP_USER": "recovery-trial@example.invalid",
    "SMTP_PASSWORD": "synthetic-smtp-password-for-recovery-trial-only",
    "SMTP_FROM": "keep-recovery-trial@example.invalid",
    "SMTP_SENDER_NAME": "Keep Recovery Trial",
    "PLEX_SERVER_URL": "https://plex.example.invalid",
    "PLEX_MACHINE_IDENTIFIER": "recovery-trial-machine",
    "PLEX_ADMIN_TOKEN": "synthetic-plex-resource-token-for-recovery-trial-only",
    "MAINTAINERR_URL": "https://maintainerr.example.invalid",
    "RADARR_URL": "https://radarr.example.invalid",
    "RADARR_API_KEY": "synthetic-radarr-key-for-recovery-trial-only",
    "SONARR_URL": "https://sonarr.example.invalid",
    "SONARR_API_KEY": "synthetic-sonarr-key-for-recovery-trial-only",
    "SEERR_URL": SEERR_URL,
    "SEERR_API_KEY": SEERR_KEY,
    "TAUTULLI_URL": "https://tautulli.example.invalid",
    "TAUTULLI_API_KEY": "synthetic-tautulli-key-for-recovery-trial-only",
}

# The projection deliberately includes credential-bearing values in memory before
# hashing. It excludes volatile timestamps updated by ordinary logins/workers.
FINGERPRINT_COLUMNS = {
    "portable_trial_marker": ("fixture_id",),
    "installation": ("id", "owner", "complete"),
    "installation_metadata": ("name", "value"),
    "portable_configuration": ("version",),
    "user_profiles": (
        "plex_id", "plex_username", "email", "full_name", "display_name",
        "can_remove_any", "can_keep_indefinitely", "can_delete_media",
        "can_delete_any", "auth_type", "status", "password_hash",
        "invite_token_hash", "invite_expires_at", "session_version",
        "plex_access", "plex_sync_visible", "theme_mode", "welcome_version",
    ),
    "keep_attribution": ("collection_id", "media_id", "user_id", "username", "kept_at"),
    "keep_schedules": ("collection_id", "media_id", "expires_at", "extension_available_at", "created_at"),
    "email_recipients": ("email", "enabled", "created_at"),
    "recipient_subscriptions": ("email", "collection_id", "enabled"),
    "media_libraries": ("library_key", "service", "external_id", "name", "path"),
    "user_library_permissions": ("user_id", "library_key"),
    "connection_settings": ("name", "value"),
    "plex_connection_overrides": ("name",),
    "portable_trial_plex_override_marker": ("fixture_id",),
    "connection_checks": ("service", "fingerprint", "passed"),
    "automatic_connection_checks": ("service", "fingerprint", "last_success", "failures"),
    "seerr_links": ("scope", "keep_id", "seerr_id"),
    "seerr_cache": ("scope", "payload", "updated", "failed"),
    "seerr_refresh": ("scope", "next_attempt", "failures"),
    "seerr_availability_queue": ("scope", "generation", "due", "failures"),
    "notification_queue": ("id", "collection_id", "media_id", "kind", "received_at", "batch_id"),
    "notification_batches": ("id", "status", "created_at", "detail"),
    "notification_deliveries": ("batch_id", "email", "sent_at"),
    "notification_reminders": ("collection_id", "media_id", "episode", "queue_id", "queued_at"),
    "user_feature_acknowledgements": ("user_id", "feature_key", "version", "acknowledged_at"),
    "api_keys": ("id", "user_id", "name", "prefix", "secret_hash", "scopes", "account_version",
                 "created_at", "expires_at", "revoked_at"),
    "api_idempotency": ("key_id", "request_key_hash", "request_hash", "status",
                        "response_status", "response_json", "created_at"),
    "portable_trial_api_marker": ("fixture_id",),
    "background_jobs": ("job_id", "run_token", "started", "finished", "last_success",
                        "duration", "status", "result", "next_run", "scope"),
    "portable_trial_jobs_marker": ("fixture_id",),
}


class TrialError(RuntimeError):
    pass


def database_path():
    path = Path(os.environ.get("KEEP_DB_PATH", "/app/data/keep.sqlite3"))
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise TrialError("KEEP_DB_PATH must identify a regular, non-symlink database file")
    return path


def existing_tables(path):
    if not path.exists():
        return set(), None
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as db:
        names = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        marker = None
        if "portable_trial_marker" in names:
            marker = db.execute("SELECT fixture_id FROM portable_trial_marker LIMIT 1").fetchone()
    return names, marker[0] if marker else None


def preflight_seed(path):
    tables, marker = existing_tables(path)
    if not tables:
        return False
    if "portable_trial_marker" in tables and marker == FIXTURE_ID:
        return True
    raise TrialError("seed refuses a non-empty database without the exact recovery-trial marker")


def configure_synthetic_environment(path):
    os.environ["KEEP_DB_PATH"] = str(path)
    os.environ["PLEX_OWNER_ID"] = "7"
    os.environ["FLASK_SECRET_KEY"] = "synthetic-flask-signing-secret-for-recovery-trial-only"
    os.environ["KEEP_WEBHOOK_SECRET"] = "synthetic-webhook-secret-for-recovery-trial-only"
    # Prevent real delivery or use of deployment-provided service endpoints.
    for name in (
        "EMAIL_ENABLED", "SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "SMTP_USER",
        "SMTP_PASSWORD", "SMTP_FROM", "SMTP_SENDER_NAME", "PLEX_SERVER_URL",
        "PLEX_MACHINE_IDENTIFIER", "PLEX_ADMIN_TOKEN", "MAINTAINERR_URL",
        "RADARR_URL", "RADARR_API_KEY", "SONARR_URL", "SONARR_API_KEY",
        "SEERR_URL", "SEERR_API_KEY", "TAUTULLI_URL", "TAUTULLI_API_KEY",
        "KEEP_COLLECTIONS", "KEEP_URL",
    ):
        os.environ[name] = TRIAL_SETTINGS[name]
    os.environ["EMAIL_ENABLED"] = "false"


def app_module():
    # Import only after the trial database and synthetic configuration are set.
    import app
    return app


def seed(app):
    path = Path(app.KEEP_DB_PATH)
    if existing_tables(path)[1] == FIXTURE_ID:
        print("Recovery trial fixture already seeded; no changes made.")
        return
    # App import initialized all current schemas. Initialize Seerr's durable store too.
    app.seerr_store()
    now = 1_798_200_000.0
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("CREATE TABLE portable_trial_marker (fixture_id TEXT PRIMARY KEY NOT NULL)")
        db.execute("INSERT INTO portable_trial_marker VALUES (?)", (FIXTURE_ID,))
        db.execute("INSERT OR REPLACE INTO installation(id,owner,complete) VALUES (1,'7',1)")
        db.execute("INSERT OR IGNORE INTO user_profiles(plex_id,plex_username,email,full_name,display_name,auth_type,status,password_hash,session_version,plex_access,theme_mode,can_remove_any,can_keep_indefinitely,can_delete_media,can_delete_any) VALUES ('7','Recovery Owner','owner-trial@example.com','Recovery Trial Owner','Trial Owner','plex','active','',0,'active','dark',0,0,0,0)")
        password_hash = app.password_hasher.hash(FIXTURE_PASSWORD)
        db.execute("""INSERT OR REPLACE INTO user_profiles
            (plex_id,plex_username,email,full_name,display_name,auth_type,status,password_hash,
             session_version,plex_access,theme_mode,can_remove_any,can_keep_indefinitely,
             can_delete_media,can_delete_any)
            VALUES (?,?,?,?,?,'local','active',?,0,'active','light',0,0,1,0)""",
                   (LOCAL_ID, "Recovery Local", LOCAL_EMAIL, "Recovery Trial Local",
                    "Trial Local", password_hash))
        db.execute("INSERT OR REPLACE INTO email_recipients(email,enabled,created_at) VALUES (?,1,'2026-10-01 12:00:00')",
                   (LOCAL_EMAIL,))
        db.execute("INSERT OR REPLACE INTO recipient_subscriptions(email,collection_id,enabled) VALUES (?,901,1)",
                   (LOCAL_EMAIL,))
        db.execute("INSERT OR REPLACE INTO recipient_subscriptions(email,collection_id,enabled) VALUES (?,902,0)",
                   (LOCAL_EMAIL,))
        db.execute("INSERT OR REPLACE INTO media_libraries(library_key,service,external_id,name,path,last_seen_at) VALUES ('radarr:trial-700','radarr','trial-700','Recovery Trial Movies','/trial/movies','2026-10-01 12:00:00')")
        db.execute("INSERT OR REPLACE INTO user_library_permissions(user_id,library_key) VALUES (?, 'radarr:trial-700')",
                   (LOCAL_ID,))
        db.execute("INSERT OR REPLACE INTO keep_attribution(collection_id,media_id,user_id,username,kept_at) VALUES ('901','991001',?,'Trial Local','2026-10-01 12:00:00')",
                   (LOCAL_ID,))
        db.execute("INSERT OR REPLACE INTO keep_schedules(collection_id,media_id,expires_at,extension_available_at,created_at) VALUES ('901','991001','2099-01-01 00:00:00','2026-12-01 00:00:00','2026-10-01 12:00:00')")
        db.execute("INSERT OR REPLACE INTO keep_attribution(collection_id,media_id,user_id,username,kept_at) VALUES ('902','991002','7','Recovery Owner','2026-10-01 12:05:00')")
        db.execute("INSERT OR REPLACE INTO keep_schedules(collection_id,media_id,expires_at,extension_available_at,created_at) VALUES ('902','991002',NULL,NULL,'2026-10-01 12:05:00')")
        for name, value in TRIAL_SETTINGS.items():
            validated = validate_setting(name, value)
            db.execute("INSERT OR REPLACE INTO connection_settings(name,value) VALUES (?,?)", (name, validated))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='plex_connection_overrides'").fetchone():
            db.execute('CREATE TABLE portable_trial_plex_override_marker (fixture_id TEXT PRIMARY KEY NOT NULL)')
            db.execute('INSERT INTO portable_trial_plex_override_marker VALUES (?)', (FIXTURE_ID,))
            db.executemany("INSERT OR IGNORE INTO plex_connection_overrides(name) VALUES (?)",
                           ((name,) for name in ('PLEX_SERVER_URL', 'PLEX_MACHINE_IDENTIFIER', 'PLEX_ADMIN_TOKEN')))
        for service in ("plex", "maintainerr", "radarr", "sonarr", "seerr", "tautulli", "email"):
            fingerprint = app.connection_settings.connection_fingerprint(service, app.connection_value)
            db.execute("INSERT OR REPLACE INTO connection_checks(service,fingerprint,passed,checked) VALUES (?,?,1,?)",
                       (service, fingerprint, now))
            db.execute("INSERT OR REPLACE INTO automatic_connection_checks(service,fingerprint,checked,last_success,failures,next_attempt) VALUES (?,?,?, ?,0,?)",
                       (service, fingerprint, now, now, now + 3600))
        db.execute("INSERT OR REPLACE INTO seerr_links(scope,keep_id,seerr_id) VALUES (?, ?, 777)",
                   (SEERR_SCOPE, LOCAL_ID))
        cache = {"users": [{"id": 777, "name": "Trial Seerr User", "plex_id": None}],
                 "requests": [{"id": 778, "kind": "movie", "tmdb": 779,
                               "tvdb": None, "user": 777, "status": 2, "seasons": [], "is4k": False}]}
        db.execute("INSERT OR REPLACE INTO seerr_cache(scope,payload,updated,failed) VALUES (?,?,?,0)",
                   (SEERR_SCOPE, json.dumps(cache, sort_keys=True), now))
        db.execute("INSERT OR REPLACE INTO seerr_refresh(scope,next_attempt,failures) VALUES (?,?,0)",
                   (SEERR_SCOPE, now + 900))
        db.execute("INSERT OR REPLACE INTO seerr_availability_queue(scope,generation,due,failures) VALUES (?,2,?,1)",
                   (SEERR_SCOPE, now + 300))
        db.execute("INSERT OR REPLACE INTO notification_batches(id,status,created_at,detail) VALUES ('trial-held-batch','review',?,'Synthetic recovery review state')",
                   (now,))
        db.execute("INSERT OR REPLACE INTO notification_queue(id,collection_id,media_id,kind,received_at,batch_id) VALUES (88001,901,'991001','MEDIA_ABOUT_TO_BE_HANDLED',?,NULL)",
                   (now,))
        db.execute("INSERT OR REPLACE INTO notification_queue(id,collection_id,media_id,kind,received_at,batch_id) VALUES (88002,902,'991002','MEDIA_ABOUT_TO_BE_HANDLED',?,'trial-held-batch')",
                   (now + 30,))
        db.execute("INSERT OR REPLACE INTO notification_deliveries(batch_id,email,sent_at) VALUES ('trial-held-batch','review-recipient@example.com',?)",
                   (now + 20,))
        db.execute("INSERT OR REPLACE INTO notification_reminders(collection_id,media_id,episode,queue_id,queued_at) VALUES (902,'991002','leaving-entry-2026-10-01',88002,?)",
                   (now + 30,))
        db.execute("INSERT OR REPLACE INTO user_feature_acknowledgements(user_id,feature_key,version,acknowledged_at) VALUES ('7','recovery-trial','1','2026-10-01 12:00:00')")
        if 'keep_api' in app.app.extensions:
            seed_api_credentials(db)
        if hasattr(app, 'job_store'):
            db.execute('CREATE TABLE portable_trial_jobs_marker (fixture_id TEXT PRIMARY KEY NOT NULL)')
            db.execute('INSERT INTO portable_trial_jobs_marker VALUES (?)', (FIXTURE_ID,))
            for job_id, status, result in (
                ('keep-expiry', 'success', 'Released 2 Keeps'),
                ('seerr-history', 'failed', 'Connection unavailable'),
                ('email-digest', 'review', 'Delivery needs review'),
            ):
                db.execute('''INSERT OR REPLACE INTO background_jobs
                    (job_id,run_token,started,finished,last_success,duration,status,result,next_run)
                    VALUES (?,?,?,?,?,?,?,?,?)''',
                    (job_id, 'synthetic-recovery-run', now, now + 2,
                     now + 2 if status == 'success' else None, 2, status, result, now + 32))
    assert_saved_state(app)
    print("Recovery trial fixture seeded. Synthetic SMTP is disabled; no services were contacted.")


def require(condition, message):
    if not condition:
        raise TrialError(message)


def api_request_hash(payload):
    return hashlib.sha256(json.dumps(['POST', '/api/v1/keeps', payload],
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def seed_api_credentials(db):
    now = time.time()
    db.execute('CREATE TABLE portable_trial_api_marker (fixture_id TEXT PRIMARY KEY)')
    db.execute('INSERT INTO portable_trial_api_marker VALUES (?)', (FIXTURE_ID,))
    db.execute("""INSERT INTO user_profiles(plex_id,plex_username,email,display_name,
        auth_type,status,password_hash,session_version,plex_access)
        VALUES ('local-api-disabled','Recovery disabled','disabled-trial@example.invalid',
        'Recovery Trial Disabled','local','disabled','',0,'active')""")
    for name, token in RECOVERY_BEARERS.items():
        db.execute('INSERT INTO api_keys VALUES (?,?,?,?,?,?,?,?,?,?,NULL)', (
            'recovery-api-' + name, 'local-api-disabled' if name == 'disabled' else LOCAL_ID,
            'Recovery trial ' + name, token[:13], hashlib.sha256(token.encode()).hexdigest(),
            json.dumps(['collections:read', 'keeps:read', 'keeps:write'] if name == 'active' else ['collections:read']),
            9 if name == 'changed' else 0, now - 3600,
            now - 86400 if name == 'expired' else now + 90 * 86400,
            now - 60 if name == 'revoked' else None))
    payload = {'collection_id':901, 'media_id':'991001', 'duration':'temporary'}
    response = {'data': {'id':'901:991001', 'collection_id':901, 'media_id':'991001',
        'duration':'temporary', 'expires_at':'2099-01-01T00:00:00Z',
        'extension_available_at':'2026-12-01T00:00:00Z', 'owned_by_current_user':True}}
    db.execute('INSERT INTO api_idempotency VALUES (?,?,?,?,?,?,?)', (
        'recovery-api-active', hashlib.sha256(b'portable-api-saved-response').hexdigest(),
        api_request_hash(payload), 'succeeded', 201, json.dumps(response), now - 3600))
    payload = {'collection_id':901, 'media_id':'991003', 'duration':'temporary'}
    db.execute('INSERT INTO api_idempotency VALUES (?,?,?,?,NULL,NULL,?)', (
        'recovery-api-active', hashlib.sha256(b'portable-api-uncertain-request').hexdigest(),
        api_request_hash(payload), 'uncertain', now - 3600))


def verify_api_credentials(app):
    if 'keep_api' not in app.app.extensions:
        return 'pre-API image'
    blocked = TrialError('API recovery verification attempted upstream I/O')
    with patch('api_v1.requests.get', side_effect=blocked), patch('api_v1.requests.post', side_effect=blocked), patch('api_v1.requests.delete', side_effect=blocked):
        return verify_api_credential_state(app)


def verify_api_credential_state(app):
    if 'keep_api' not in app.app.extensions:
        return 'pre-API image'
    with closing(sqlite3.connect(app.KEEP_DB_PATH)) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'portable_trial_api_marker' not in tables:
            require(db.execute('SELECT count(*) FROM api_keys').fetchone()[0] == 0,
                    'pre-API snapshot unexpectedly gained credentials')
            return 'pre-API snapshot; new credential tables empty'
        rows = db.execute('SELECT * FROM api_keys').fetchall()
        require(len(rows) == len(RECOVERY_BEARERS), 'persistent fixture API keys are missing')
        for token in RECOVERY_BEARERS.values():
            require(all(token not in row for row in rows), 'a usable fixture API key was stored')
            require(any(hashlib.sha256(token.encode()).hexdigest() in row for row in rows),
                    'a fixture API key hash changed')
    client = app.app.test_client()
    for name, token in RECOVERY_BEARERS.items():
        response = client.get('/api/v1/collections', headers={'Authorization':'Bearer ' + token})
        require(response.status_code == (200 if name in ('active', 'replacement') else 401),
                'restored API credential lifecycle failed')
        if response.status_code == 200:
            require({row['collection_id'] for row in response.json['data']} == {901,902},
                    'restored API collection settings differ')
        require(response.headers.get('Cache-Control') == 'no-store', 'API response is cacheable')
    headers = {'Authorization':'Bearer ' + RECOVERY_BEARERS['active']}
    response = client.get('/api/v1/keeps', headers=headers)
    require(response.status_code == 200 and len(response.json['data']) == 1 and
            response.json['data'][0]['id'] == '901:991001', 'restored API object ownership differs')
    # Both calls must resolve from their restored ledger without any upstream I/O.
    for key, media_id, expected in (('portable-api-saved-response', '991001', 201),
                                    ('portable-api-uncertain-request', '991003', 409)):
        response = client.post('/api/v1/keeps', headers={**headers, 'Idempotency-Key':key},
            json={'collection_id':901, 'media_id':media_id, 'duration':'temporary'})
        require(response.status_code == expected, 'restored API retry ledger did not protect the write')
        if expected == 201:
            require(response.headers.get('Idempotency-Replayed') == 'true',
                    'saved API response was not replayed')
        else:
            require(response.json['error']['code'] == 'operation_uncertain',
                    'uncertain API write became retryable')
    return 'six hashed credentials, lifecycle/ownership checks and both durable retry states passed'


def assert_saved_state(app, *, worker_started=False):
    path = app.KEEP_DB_PATH
    with closing(sqlite3.connect(path)) as db:
        db.row_factory = sqlite3.Row
        owner = db.execute("SELECT owner,complete FROM installation WHERE id=1").fetchone()
        require(tuple(owner) == ("7", 1), "persisted synthetic owner does not match")
        local = db.execute("SELECT * FROM user_profiles WHERE plex_id=?", (LOCAL_ID,)).fetchone()
        require(local is not None and local["auth_type"] == "local" and
                local["status"] == "active" and local["password_hash"] and
                local["email"] == LOCAL_EMAIL, "synthetic local account is missing")
        require(app.password_hasher.verify(local["password_hash"], FIXTURE_PASSWORD),
                "synthetic local password hash does not verify")
        plex_owner = db.execute("SELECT auth_type,status,session_version,plex_access FROM user_profiles WHERE plex_id='7'").fetchone()
        require(plex_owner is not None and tuple(plex_owner) == ("plex", "active", 0, "active"),
                "synthetic Plex owner profile does not match")
        expected_settings = {k: validate_setting(k, v)
                             for k, v in TRIAL_SETTINGS.items()}
        saved_settings = dict(db.execute("SELECT name,value FROM connection_settings"))
        for key, expected in expected_settings.items():
            require(saved_settings.get(key) == expected,
                    "synthetic saved service settings do not match")
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='portable_trial_plex_override_marker'").fetchone():
            require({row[0] for row in db.execute('SELECT name FROM plex_connection_overrides')} ==
                    {'PLEX_SERVER_URL', 'PLEX_MACHINE_IDENTIFIER', 'PLEX_ADMIN_TOKEN'},
                    "saved Plex override markers do not match")
        require(saved_settings.get("EMAIL_ENABLED") == "false",
                "saved email delivery is not disabled")
        keeps = {row[0]: tuple(row[1:]) for row in db.execute(
            "SELECT media_id,collection_id,user_id,username FROM keep_attribution ORDER BY media_id")}
        require(keeps == {
            "991001": ("901", LOCAL_ID, "Trial Local"),
            "991002": ("902", "7", "Recovery Owner"),
        }, "trial Keep attribution rows do not match")
        schedules = {row[0]: tuple(row[1:]) for row in db.execute(
            "SELECT media_id,collection_id,expires_at,extension_available_at FROM keep_schedules ORDER BY media_id")}
        require(schedules == {
            "991001": ("901", "2099-01-01 00:00:00", "2026-12-01 00:00:00"),
            "991002": ("902", None, None),
        }, "trial Keep schedules do not match")
        subscriptions = {tuple(row) for row in db.execute(
            "SELECT email,collection_id,enabled FROM recipient_subscriptions WHERE email=?", (LOCAL_EMAIL,))}
        require(subscriptions == {(LOCAL_EMAIL, 901, 1), (LOCAL_EMAIL, 902, 0)},
                "trial subscriptions do not match")
        require(db.execute("SELECT COUNT(*) FROM user_library_permissions WHERE user_id=? AND library_key='radarr:trial-700'", (LOCAL_ID,)).fetchone()[0] == 1,
                "trial library grant is missing")
        require(db.execute("SELECT seerr_id FROM seerr_links WHERE scope=? AND keep_id=?", (SEERR_SCOPE, LOCAL_ID)).fetchone()[0] == 777,
                "trial Seerr link is missing")
        cached = db.execute("SELECT payload,failed FROM seerr_cache WHERE scope=?", (SEERR_SCOPE,)).fetchone()
        expected_cache = json.dumps({
            "users": [{"id": 777, "name": "Trial Seerr User", "plex_id": None}],
            "requests": [{"id": 778, "kind": "movie", "tmdb": 779, "tvdb": None,
                          "user": 777, "status": 2, "seasons": [], "is4k": False}],
        }, sort_keys=True)
        require(cached is not None and tuple(cached) == (expected_cache, 0),
                "trial Seerr cache does not match")
        queue = db.execute("SELECT generation,failures FROM seerr_availability_queue WHERE scope=?", (SEERR_SCOPE,)).fetchone()
        require(queue is not None and tuple(queue) == (2, 1),
                "trial Seerr sync queue is missing")
        pending = db.execute("SELECT collection_id,media_id,kind,batch_id FROM notification_queue WHERE id=88001").fetchone()
        held = db.execute("SELECT collection_id,media_id,kind,batch_id FROM notification_queue WHERE id=88002").fetchone()
        require(pending is not None and tuple(pending) ==
                (901, "991001", "MEDIA_ABOUT_TO_BE_HANDLED", None),
                "trial pending notification does not match")
        require(held is not None and tuple(held) ==
                (902, "991002", "MEDIA_ABOUT_TO_BE_HANDLED", "trial-held-batch"),
                "trial batched notification does not match")
        require(db.execute("SELECT status FROM notification_batches WHERE id='trial-held-batch'").fetchone()[0] == "review",
                "trial held notification batch is missing")
        require(db.execute("SELECT COUNT(*) FROM notification_deliveries WHERE batch_id='trial-held-batch'").fetchone()[0] == 1,
                "trial delivery state is missing")
        require(db.execute("SELECT COUNT(*) FROM notification_reminders WHERE queue_id=88002").fetchone()[0] == 1,
                "trial reminder claim is missing")
        # Seeded observations are checked before starting the actual worker. Its
        # ordinary runs replace these rows; exact restore proof is provided by
        # the runner's full stopped-database fingerprints before each startup.
        if not worker_started and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='portable_trial_jobs_marker'").fetchone():
            records = {row[0]: tuple(row[1:]) for row in db.execute(
                'SELECT job_id,status,result,duration FROM background_jobs')}
            require(records == {
                'keep-expiry': ('success', 'Released 2 Keeps', 2),
                'seerr-history': ('failed', 'Connection unavailable', 2),
                'email-digest': ('review', 'Delivery needs review', 2),
            }, 'trial background job observations were not restored')


def verify(app, *, worker_started=False):
    with closing(sqlite3.connect(app.KEEP_DB_PATH)) as db:
        marker = db.execute("SELECT fixture_id FROM portable_trial_marker").fetchone()
        require(marker is not None and tuple(marker) == (FIXTURE_ID,),
                "expected portable recovery-trial marker is absent")
        result = db.execute("PRAGMA integrity_check").fetchone()[0]
        require(result == "ok", "SQLite integrity_check failed")
    assert_saved_state(app, worker_started=worker_started)
    test_auth_and_permissions(app)
    print('API recovery: ' + verify_api_credentials(app))
    print("Recovery trial verification passed: integrity, restored fields, local login, owner boundary (simulated owner session, not live Plex), and synthetic permissions.")


def test_auth_and_permissions(app):
    client = app.app.test_client()
    with client.session_transaction() as state:
        state["csrf_token"] = "portable-trial-csrf"
    response = client.post("/auth/local", data={
        "csrf_token": "portable-trial-csrf", "email": LOCAL_EMAIL,
        "password": FIXTURE_PASSWORD,
    })
    require(response.status_code in (302, 303), "synthetic local password login failed")
    require(response.headers.get("Location", "").endswith("/"),
            "synthetic local login did not reach the app")
    with client.session_transaction() as state:
        require((state.get("plex_user") or {}).get("id") == LOCAL_ID,
                "local login session was not established")
    require(client.get("/settings/users").status_code == 403,
            "local account unexpectedly has owner administration access")
    local_user = {"id": LOCAL_ID, "auth_type": "local"}
    caps = app.user_capabilities(local_user)
    require(not caps["owner"] and not caps["manage_any"] and not caps["keep_indefinitely"],
            "local account has unexpected owner or Keep permissions")
    require(caps["delete_media"] and not caps["delete_any"],
            "local library permissions do not match fixture")
    require(app.granted_library_keys(local_user) == {"radarr:trial-700"},
            "local account library grant was not restored")

    owner_client = app.app.test_client()
    with owner_client.session_transaction() as state:
        # Simulated persisted owner identity; this is not a live Plex login.
        state["plex_user"] = {"id": "7", "username": "Recovery Trial Owner",
                              "auth_type": "plex", "session_version": 0}
        state["csrf_token"] = "portable-trial-owner-csrf"
    admin = owner_client.get("/settings/users")
    require(admin.status_code == 200 and b"Recovery Trial" in admin.data,
            "simulated owner session cannot access the administration view")
    owner_caps = app.user_capabilities({"id": "7", "auth_type": "plex"})
    require(owner_caps["owner"] and owner_caps["manage_any"] and owner_caps["keep_indefinitely"],
            "persisted owner permissions do not match")
    require(app.granted_library_keys({"id": "7", "auth_type": "plex"}) == {"radarr:trial-700"},
            "owner library visibility is incorrect")


def fingerprints(app):
    summaries = {}
    with closing(sqlite3.connect(app.KEEP_DB_PATH)) as db:
        db.row_factory = sqlite3.Row
        for table, columns in sorted(FINGERPRINT_COLUMNS.items()):
            actual = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
            if not actual:
                continue
            require(set(columns) <= actual,
                    f"database schema changed for fingerprinted table {table}")
            projection = ",".join(f'"{column}"' for column in columns)
            rows = []
            for row in db.execute(f'SELECT {projection} FROM "{table}"'):
                values = []
                for value in tuple(row):
                    if isinstance(value, bytes):
                        value = {"bytes": value.hex()}
                    values.append(value)
                rows.append(json.dumps(values, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False))
            rows.sort()
            digest = hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()
            summaries[table] = {"rows": len(rows), "sha256": digest}
        marker = db.execute("SELECT fixture_id FROM portable_trial_marker").fetchone()
        require(marker is not None and tuple(marker) == (FIXTURE_ID,),
                "expected portable recovery-trial marker is absent")
        result = db.execute("PRAGMA integrity_check").fetchone()[0]
        require(result == "ok", "SQLite integrity_check failed")
    # Include optional tables only when this app version actually defines them.
    optional = {"api_keys"}
    api_schema = sorted(optional & set(summaries))
    canonical = json.dumps(summaries, sort_keys=True, separators=(",", ":"))
    print(json.dumps({"fixture": FIXTURE_ID, "integrity": "ok",
                      "tables": summaries,
                      "global_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
                      "optional_api_schema": "present" if api_schema else "absent"},
                     sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("seed", "verify", "fingerprint"))
    parser.add_argument("--db", type=Path,
                        help="isolated SQLite path; defaults to KEEP_DB_PATH")
    parser.add_argument("--worker-started", action="store_true",
                        help="verify saved state after the worker may have advanced job observations")
    args = parser.parse_args(argv)
    if args.worker_started and args.mode != "verify":
        parser.error("--worker-started applies only to verify")
    try:
        path = args.db or database_path()
        if args.db:
            if path.exists() or path.is_symlink():
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise TrialError("--db must identify a regular, non-symlink database file")
            os.environ["KEEP_DB_PATH"] = str(path)
        if args.mode == "seed" and preflight_seed(path):
            print("Recovery trial fixture already seeded; no changes made.")
            return 0
        configure_synthetic_environment(path)
        app = app_module()
        if args.mode == "seed":
            seed(app)
        elif args.mode == "verify":
            verify(app, worker_started=args.worker_started)
        else:
            fingerprints(app)
    except (OSError, sqlite3.Error, TrialError, ValueError, AssertionError) as error:
        parser.exit(2, f"portable recovery trial failed: {error}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
