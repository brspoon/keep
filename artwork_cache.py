"""Disposable, bounded disk cache. Authorization always belongs to the caller."""
from contextlib import closing
import hashlib
import json
import sqlite3
import threading
import time

_locks = [threading.Lock() for _ in range(64)]


def namespace(service, settings):
    prefix = service.upper()
    return hashlib.sha256(json.dumps([service, settings(prefix + '_URL'),
                                    settings(prefix + '_API_KEY')]).encode()).hexdigest()


class ArtworkCache:
    def __init__(self, path, limit=128 * 1024 * 1024):
        self.path, self.limit = str(path), limit
        with closing(self.connect()) as db:
            db.execute('PRAGMA auto_vacuum=FULL')
            db.execute('CREATE TABLE IF NOT EXISTS entries (key TEXT PRIMARY KEY, body BLOB NOT NULL, kind TEXT NOT NULL, expires REAL NOT NULL, used REAL NOT NULL)')

    def connect(self):
        return sqlite3.connect(self.path, timeout=5)

    def get(self, key):
        with closing(self.connect()) as db, db:
            row = db.execute('SELECT body,kind FROM entries WHERE key=? AND expires>?',
                             (key, time.time())).fetchone()
            if row:
                db.execute('UPDATE entries SET used=? WHERE key=?', (time.time(), key))
                return bytes(row[0]), row[1]

    def put(self, key, body, kind, ttl):
        if len(body) > self.limit:
            return
        now = time.time()
        with closing(self.connect()) as db, db:
            db.execute('DELETE FROM entries WHERE expires<=? OR key=?', (now, key))
            size = db.execute('SELECT COALESCE(SUM(length(body)),0) FROM entries').fetchone()[0]
            for old, length in db.execute('SELECT key,length(body) FROM entries ORDER BY used').fetchall():
                if size + len(body) <= self.limit:
                    break
                db.execute('DELETE FROM entries WHERE key=?', (old,))
                size -= length
            db.execute('INSERT INTO entries VALUES (?,?,?,?,?)', (key, body, kind, now + ttl, now))

    def load(self, key, loader, ttl):
        # Coalesce simultaneous misses without holding a database transaction over HTTP.
        with _locks[int(hashlib.sha256(key.encode()).hexdigest(), 16) % len(_locks)]:
            result = self.get(key)
            if result is None:
                result = loader()
                self.put(key, *result, ttl)
            return result

    def forget(self, prefix):
        with closing(self.connect()) as db, db:
            db.execute('DELETE FROM entries WHERE substr(key,1,?)=?', (len(prefix), prefix))

    def remember_item(self, key, item):
        # Only fields needed for artwork routing and library authorization.
        data = {name: item.get(name) for name in ('id', 'path', 'rootFolderPath', 'images', 'tmdbId', 'tvdbId', 'seasons')}
        self.put(key + ':metadata', json.dumps(data).encode(), 'application/json', 60)

    def remember_inventory(self, namespace, items):
        # Batch inventory hints in one transaction, not one disk sync per title.
        now = time.time()
        rows = []
        total = 0
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get('id'), int):
                continue
            data = {name: item.get(name) for name in ('id', 'path', 'rootFolderPath', 'images', 'tmdbId', 'tvdbId', 'seasons')}
            body = json.dumps(data).encode()
            if total + len(body) > self.limit // 4:
                break
            total += len(body)
            rows.append((namespace + ':' + str(item['id']) + ':metadata', body, 'application/json', now + 60, now))
        with closing(self.connect()) as db, db:
            db.execute('DELETE FROM entries WHERE expires<=?', (now,))
            db.executemany('INSERT OR REPLACE INTO entries VALUES (?,?,?,?,?)', rows)
            size = db.execute('SELECT COALESCE(SUM(length(body)),0) FROM entries').fetchone()[0]
            for key, length in db.execute('SELECT key,length(body) FROM entries ORDER BY used').fetchall():
                if size <= self.limit:
                    break
                db.execute('DELETE FROM entries WHERE key=?', (key,))
                size -= length
