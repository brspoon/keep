"""Synthetic entry point for the isolated native maintenance qualification.

This file is copied only into source-derived trial images. Every network or SMTP
transport is disabled before app import. It is never a production runtime asset.
"""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

DATA = Path('/app/data')


def publish_marker(name, value):
    path = DATA / name
    with path.open('w') as stream:
        os.chmod(path, 0o600)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def observe_gate():
    with closing(sqlite3.connect((DATA/'.maintenance/control.sqlite3').as_uri()+'?mode=ro', uri=True)) as db:
        row = db.execute('SELECT closed,drained,request_id FROM gate WHERE id=1').fetchone()
    with closing(sqlite3.connect((DATA/'keep.sqlite3').as_uri()+'?mode=ro', uri=True)) as db:
        writes = db.execute("SELECT version FROM user_feature_acknowledgements WHERE feature_key='maintenance-drain-write'").fetchall()
    return {'closed': bool(row[0]), 'drained': bool(row[1]), 'request_id': row[2],
        'writer_ready': (DATA/'maintenance-trial-lease').is_file(),
        'writer_done': (DATA/'maintenance-trial-done').read_text() if (DATA/'maintenance-trial-done').is_file() else None,
        'drain_writes': [value[0] for value in writes]}


def deny_transport(*args, **kwargs):
    raise RuntimeError('External transports are disabled in this fixture')


def application():
    import requests
    import smtplib
    requests.sessions.Session.request = deny_transport
    smtplib.SMTP = deny_transport
    smtplib.SMTP_SSL = deny_transport
    import app
    return app


def marker(app, value):
    with app.maintenance_store.startup_schema(app.APP_VERSION):
        with closing(sqlite3.connect(app.KEEP_DB_PATH)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS maintenance_trial_schema (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)')
            db.execute('INSERT OR REPLACE INTO maintenance_trial_schema VALUES (1,?)', (value,))


def main():
    mode = sys.argv[1]
    if mode == 'gate':
        print(json.dumps(observe_gate()))
        return
    if mode == 'release':
        publish_marker('maintenance-trial-release', sys.argv[2])
        return
    app = application()
    if mode == 'seed':
        import maintenance_portable_fixture as fixture
        fixture.seed(app)
        marker(app, 1)
    elif mode in ('web', 'worker'):
        value = int(Path('/app/TRIAL_SCHEMA').read_text())
        marker(app, value)
        if value == 3:
            # The schema write has committed before the unhealthy process exits.
            raise RuntimeError('Intentional failed-upgrade health fixture')
        if mode == 'worker':
            app.digest_worker()
        else:
            app.app.run(host='0.0.0.0', port=5000, use_reloader=False)
    elif mode == 'inspect':
        with app.maintenance_store.work(), closing(sqlite3.connect(app.KEEP_DB_PATH)) as db:
            assert db.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
            print(json.dumps({'schema': db.execute('SELECT value FROM maintenance_trial_schema WHERE id=1').fetchone()[0],
                'new_writes': db.execute("SELECT COUNT(*) FROM user_feature_acknowledgements WHERE feature_key='maintenance-post-commit'").fetchone()[0],
                'owner': db.execute('SELECT owner FROM installation WHERE id=1').fetchone()[0]}))
    elif mode == 'write':
        with app.maintenance_store.work(), closing(sqlite3.connect(app.KEEP_DB_PATH)) as db, db:
            db.execute("INSERT OR REPLACE INTO user_feature_acknowledgements(user_id,feature_key,version,acknowledged_at) VALUES ('7','maintenance-post-commit','1','2026-10-12 00:00:00')")
    elif mode == 'hold':
        identifier = sys.argv[2]
        for name in ('maintenance-trial-release', 'maintenance-trial-done'):
            (DATA/name).unlink(missing_ok=True)
        with app.maintenance_store.work():
            publish_marker('maintenance-trial-lease', identifier)
            deadline = time.monotonic()+45
            release = DATA/'maintenance-trial-release'
            while not release.is_file() or release.read_text() != identifier:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Controlled writer release did not arrive')
                time.sleep(.02)
            # This writer was admitted before gate closure. Its protected final
            # write must commit while the same work lease still prevents stop.
            with closing(sqlite3.connect(app.KEEP_DB_PATH)) as db, db:
                db.execute("INSERT OR REPLACE INTO user_feature_acknowledgements(user_id,feature_key,version,acknowledged_at) VALUES ('7','maintenance-drain-write',?,'2026-10-12 00:00:00')", (identifier,))
            publish_marker('maintenance-trial-done', identifier)
        (DATA/'maintenance-trial-lease').unlink()
    else:
        raise RuntimeError('Unknown trial-only operation')


if __name__ == '__main__':
    main()
