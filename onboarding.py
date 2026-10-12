"""Local operator bootstrap and short-lived, server-side Plex flow storage.

Run `python -m onboarding bootstrap` in the application's runtime environment.
No Flask import is needed and no Plex credentials are printed.
"""
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager,nullcontext
from pathlib import Path
import maintenance_app

TTL = 600


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Onboarding:
    def __init__(self,path,legacy_owner='',*,initialize=True,maintenance_store=None):
        self.path=path
        self.maintenance=maintenance_store or maintenance_app.Store(root=maintenance_app.FIXED_ROOT)
        if initialize:
            with self.maintenance.startup_schema(Path(__file__).with_name('VERSION').read_text().strip()):
                self._initialize_schema(legacy_owner)

    def _initialize_schema(self,legacy_owner):
        if legacy_owner and not re.fullmatch(r'[1-9][0-9]*', legacy_owner):
            raise ValueError('PLEX_OWNER_ID must be a positive numeric Plex account ID')
        with self.db(_schema=True) as db:
            db.execute('CREATE TABLE IF NOT EXISTS installation (id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, complete INTEGER NOT NULL DEFAULT 0)')
            db.execute('CREATE TABLE IF NOT EXISTS installation_metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL)')
            db.execute("INSERT OR IGNORE INTO installation_metadata VALUES ('plex_client_id', ?)", (secrets.token_urlsafe(24),))
            db.execute('CREATE TABLE IF NOT EXISTS bootstrap (id INTEGER PRIMARY KEY CHECK(id=1), digest TEXT NOT NULL, expires REAL NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS plex_flows (digest TEXT PRIMARY KEY, binding TEXT NOT NULL, purpose TEXT NOT NULL, payload TEXT NOT NULL, expires REAL NOT NULL)')
            row = db.execute('SELECT owner FROM installation WHERE id=1').fetchone()
            if legacy_owner:
                if row and row[0] != legacy_owner:
                    raise ValueError('PLEX_OWNER_ID conflicts with persisted ownership; refusing reassignment')
                db.execute('INSERT OR IGNORE INTO installation VALUES (1, ?, 1)', (legacy_owner,))
                db.execute('DELETE FROM bootstrap')

    @contextmanager
    def db(self,write=True,*,authority=False,_schema=False):
        lease=self.maintenance.work(authority=authority) if write and not _schema else nullcontext()
        with lease:
            uri=Path(self.path).absolute().as_uri()+'?mode=ro'
            db=sqlite3.connect(self.path,timeout=10) if write else sqlite3.connect(uri,uri=True,timeout=10)
            try:
                with db:
                    if write:
                        db.execute('PRAGMA secure_delete=ON')
                        db.execute('BEGIN IMMEDIATE')
                    yield db
            finally:
                db.close()

    def owner(self):
        with self.db(write=False) as db:
            row = db.execute('SELECT owner FROM installation WHERE id=1').fetchone()
            return row[0] if row else ''

    def client_id(self):
        with self.db(write=False) as db:
            return db.execute("SELECT value FROM installation_metadata WHERE name='plex_client_id'").fetchone()[0]

    def pending(self):
        with self.db(write=False) as db:
            row = db.execute('SELECT complete FROM installation WHERE id=1').fetchone()
            return not row or not row[0]

    def issue(self):
        code = secrets.token_urlsafe(32)
        with self.db(authority=True) as db:
            if db.execute('SELECT 1 FROM installation').fetchone():
                raise ValueError('Ownership is already established; bootstrap is disabled')
            # Old data without an explicit owner must be recovered deliberately.
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='user_profiles'").fetchone():
                if db.execute('SELECT 1 FROM user_profiles LIMIT 1').fetchone():
                    raise ValueError('Existing profiles require PLEX_OWNER_ID; bootstrap is disabled')
            db.execute('INSERT OR REPLACE INTO bootstrap VALUES (1, ?, ?)', (digest(code), time.time() + TTL))
        return code

    def valid_code(self, code):
        with self.db() as db:
            return bool(db.execute('SELECT 1 FROM bootstrap WHERE digest=? AND expires>?', (digest(code), time.time())).fetchone())

    def claim(self, code_digest, verified_owner):
        if not re.fullmatch(r'[1-9][0-9]*', verified_owner):
            raise ValueError('Invalid verified Plex identity')
        with self.db(authority=True) as db:
            if db.execute('SELECT 1 FROM installation').fetchone():
                raise ValueError('Ownership is already established')
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='user_profiles'").fetchone():
                if db.execute('SELECT 1 FROM user_profiles LIMIT 1').fetchone():
                    raise ValueError('Existing profiles require owner recovery')
            changed = db.execute('DELETE FROM bootstrap WHERE digest=? AND expires>?', (code_digest, time.time())).rowcount
            if changed != 1:
                raise ValueError('Bootstrap code expired or already used')
            db.execute('INSERT INTO installation VALUES (1, ?, 0)', (verified_owner,))

    def put_flow(self, binding, purpose, payload):
        key = secrets.token_urlsafe(32)
        with self.db() as db:
            db.execute('DELETE FROM plex_flows WHERE expires<=?', (time.time(),))
            db.execute('DELETE FROM plex_flows WHERE binding=?', (digest(binding),))
            db.execute('INSERT INTO plex_flows VALUES (?, ?, ?, ?, ?)',
                       (digest(key), digest(binding), purpose, json.dumps(payload), time.time() + TTL))
        return key

    def take_flow(self, key, binding, *, consume=True):
        with self.db() as db:
            db.execute('DELETE FROM plex_flows WHERE expires<=?', (time.time(),))
            row = db.execute('SELECT purpose, payload FROM plex_flows WHERE digest=? AND binding=?', (digest(key), digest(binding))).fetchone()
            if row and consume:
                db.execute('DELETE FROM plex_flows WHERE digest=?', (digest(key),))
            return (row[0], json.loads(row[1])) if row else None

    def cleanup(self):
        with self.db() as db:
            db.execute('DELETE FROM plex_flows WHERE expires<=?', (time.time(),))
            db.execute('DELETE FROM bootstrap WHERE expires<=?', (time.time(),))

    def finish(self):
        with self.db(authority=True) as db:
            db.execute('UPDATE installation SET complete=1 WHERE id=1')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['bootstrap'])
    parser.parse_args()
    os.umask(0o077)
    path = os.environ.get('KEEP_DB_PATH', '/app/data/keep.sqlite3')
    try:
        store=maintenance_app.Store(root=maintenance_app.FIXED_ROOT)
        with store.work(authority=True):
            os.makedirs(os.path.dirname(os.path.abspath(path)),exist_ok=True)
            print(Onboarding(path,os.environ.get('PLEX_OWNER_ID',''),maintenance_store=store).issue())
    except maintenance_app.MaintenanceError:
        parser.exit(1,'Keep maintenance is in progress. Try again after it finishes.\n')
    except ValueError as error:
        parser.exit(1, str(error) + '\n')
