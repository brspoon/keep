"""Exercise durable Jobs controls through separate real web and worker processes.

Only disposable synthetic data and a loopback Radarr fixture are used. The worker
runs its production entrypoint and real connection callback without mocks.
"""
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from flask import Flask
from flask.sessions import SecureCookieSessionInterface
import requests


ROOT = Path(__file__).resolve().parents[1]
WEB_ENTRYPOINT = """
import os
from pathlib import Path
from werkzeug.serving import make_server
import app
server = make_server('127.0.0.1', 0, app.app, threaded=True)
Path(os.environ['KEEP_TEST_WEB_PORT']).write_text(str(server.server_port))
server.serve_forever()
"""


@unittest.skipUnless(os.name == 'posix', 'Keep worker requires POSIX fcntl locks')
class JobsProcessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='keep-jobs-process-')
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.db_path = self.path / 'keep.sqlite3'
        self.heartbeat = self.path / 'digest-worker.heartbeat'
        self.processes = []
        self.logs = []
        self.fixture_requests = []
        self.fixture_lock = threading.Lock()
        fixture_requests, fixture_lock = self.fixture_requests, self.fixture_lock

        class RadarrFixture(BaseHTTPRequestHandler):
            def do_GET(self):
                with fixture_lock:
                    fixture_requests.append((self.path, self.headers.get('X-Api-Key')))
                status = 200 if (self.path == '/api/v3/system/status' and
                                 self.headers.get('X-Api-Key') == 'synthetic-radarr-key') else 404
                payload = json.dumps({'version': 'synthetic-process-fixture'}).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        try:
            self.fixture = ThreadingHTTPServer(('127.0.0.1', 0), RadarrFixture)
        except PermissionError:
            self.skipTest('This environment does not permit loopback HTTP listeners')
        self.fixture_thread = threading.Thread(target=self.fixture.serve_forever,
                                               name='synthetic-radarr', daemon=True)
        self.fixture_thread.start()
        self.addCleanup(self.stop_fixture)
        self.addCleanup(self.stop_processes)

        # Strip inherited application configuration, secrets, and proxies. The
        # only configured service is this test's disposable loopback fixture.
        prefixes = ('KEEP_', 'PLEX_', 'SMTP_', 'RADARR_', 'SONARR_', 'SEERR_',
                    'TAUTULLI_', 'MAINTAINERR_', 'EMAIL_', 'FLASK_')
        self.environment = {name: value for name, value in os.environ.items()
                            if not name.startswith(prefixes) and
                            name.lower() not in ('http_proxy', 'https_proxy', 'all_proxy') and
                            name not in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP')}
        self.secret = 'synthetic-process-session-key-for-disposable-tests-only'
        self.environment.update(
            FLASK_SECRET_KEY=self.secret, KEEP_DB_PATH=str(self.db_path),
            KEEP_TRANSPORT_MODE='lan-http', KEEP_URL='http://127.0.0.1',
            KEEP_COLLECTIONS='{}', PLEX_OWNER_ID='7', EMAIL_ENABLED='false',
            DIGEST_WORKER_HEARTBEAT_PATH=str(self.heartbeat),
            RADARR_URL=f'http://127.0.0.1:{self.fixture.server_port}',
            RADARR_API_KEY='synthetic-radarr-key',
            NO_PROXY='127.0.0.1,localhost', PYTHONPATH=str(ROOT), PYTHONUNBUFFERED='1',
        )
        self.client = requests.Session()
        self.client.trust_env = False
        self.addCleanup(self.client.close)
        signing_app = Flask('synthetic-owner-session')
        signing_app.secret_key = self.secret
        cookie = SecureCookieSessionInterface().get_signing_serializer(signing_app).dumps({
            'plex_user': {'id': 7, 'username': 'Synthetic owner', 'auth_type': 'plex',
                          'session_version': 0},
            'csrf_token': 'synthetic-process-csrf',
        })
        self.client.cookies.set('session', cookie, domain='127.0.0.1', path='/')

    def stop_fixture(self):
        self.fixture.shutdown()
        self.fixture.server_close()
        self.fixture_thread.join(timeout=5)
        self.assertFalse(self.fixture_thread.is_alive(), 'Synthetic HTTP fixture leaked')

    def stop_process(self, process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        self.assertIsNotNone(process.poll(), 'Child process leaked')

    def stop_processes(self):
        for process in reversed(self.processes):
            self.stop_process(process)

    def spawn(self, label, arguments, **extra_environment):
        log_path = self.path / f'{label}.log'
        self.logs.append(log_path)
        with log_path.open('wb') as output:
            process = subprocess.Popen([sys.executable, *arguments], cwd=ROOT,
                                       env={**self.environment, **extra_environment},
                                       stdout=output, stderr=subprocess.STDOUT)
        self.processes.append(process)
        return process

    def diagnostics(self):
        return '\n'.join(f'{path.name}:\n{path.read_text(errors="replace")[-4000:]}'
                         for path in self.logs)

    def wait_until(self, condition, message, *, process=None):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process is not None and process.poll() is not None:
                self.fail(f'{message}: process exited {process.returncode}\n{self.diagnostics()}')
            try:
                value = condition()
                if value:
                    return value
            except (sqlite3.OperationalError, requests.ConnectionError, requests.Timeout):
                pass
            time.sleep(0.05)
        self.fail(f'{message}\n{self.diagnostics()}')

    def start_web(self, label):
        port_path = self.path / f'{label}.port'
        process = self.spawn(label, ['-c', WEB_ENTRYPOINT], KEEP_TEST_WEB_PORT=str(port_path))
        port = self.wait_until(lambda: port_path.read_text() if port_path.exists() else None,
                               'Web process did not start', process=process)
        self.origin = f'http://127.0.0.1:{int(port)}'
        self.wait_until(lambda: self.client.get(self.origin + '/health', timeout=2).status_code == 200,
                        'Web process health did not become ready', process=process)
        return process

    def row(self, query, parameters=()):
        with closing(sqlite3.connect(self.db_path, timeout=1)) as db:
            db.row_factory = sqlite3.Row
            result = db.execute(query, parameters).fetchone()
            return dict(result) if result else None

    def job(self):
        return self.row("SELECT * FROM background_jobs WHERE job_id='probe-radarr'")

    def queued_request(self):
        return self.row("SELECT * FROM background_job_requests WHERE job_id='probe-radarr'")

    def successful_probe(self, previous_token=None):
        row = self.job()
        if not row or row['status'] != 'success' or not self.heartbeat.exists():
            return None
        if previous_token is not None and (row['run_token'] == previous_token or
                                           self.queued_request() is not None):
            return None
        return row

    def fixture_count(self):
        with self.fixture_lock:
            return len(self.fixture_requests)

    def action(self, action, **data):
        response = self.client.post(self.origin + f'/settings/jobs/probe-radarr/{action}',
                                    data={'csrf_token': 'synthetic-process-csrf', **data},
                                    headers={'Accept': 'application/json'}, timeout=5)
        self.assertLess(response.status_code, 400, response.text)
        return response

    def test_owner_request_and_frequency_survive_web_and_worker_restarts(self):
        web = self.start_web('web-first')
        with closing(sqlite3.connect(self.db_path)) as db, db:
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, email, auth_type, status, plex_access, plex_checked_at)
                VALUES ('7', 'Synthetic owner', 'owner@example.test', 'plex',
                        'active', 'active', CURRENT_TIMESTAMP)""")
        worker = self.spawn('worker-first', [str(ROOT / 'app.py'), '--digest-worker'])
        first = self.wait_until(self.successful_probe,
                                'Actual worker did not complete initial Radarr probe', process=worker)
        self.stop_process(worker)
        initial_count = self.fixture_count()
        self.assertEqual(initial_count, 1)

        self.assertEqual(self.action('schedule', interval='600').status_code, 200)
        next_check = self.row("SELECT * FROM automatic_connection_checks WHERE service='radarr'")
        self.assertGreater(next_check['next_attempt'], time.time() + 500,
                           'Automatic due time must remain in the future for this manual-run proof')
        self.assertEqual(self.action('run').status_code, 202)
        queued = self.queued_request()
        self.assertIsNotNone(queued)
        self.assertIsNone(queued['claimed_token'])
        self.assertEqual(self.fixture_count(), initial_count, 'Web HTTP action performed the probe')
        self.assertEqual(self.job()['run_token'], first['run_token'])

        # The real worker supplied the still-fresh heartbeat. No synthetic worker
        # liveness or direct Store method is used to make Run now available.
        self.assertLess(time.time() - self.heartbeat.stat().st_mtime, 300)
        self.stop_process(web)
        web = self.start_web('web-restarted')
        snapshot = self.client.get(self.origin + '/settings/jobs?format=json', timeout=5)
        self.assertEqual(snapshot.status_code, 200, snapshot.text)
        radarr = next(row for row in snapshot.json()['jobs'] if row['id'] == 'probe-radarr')
        self.assertEqual(radarr['interval'], 600)
        self.assertEqual(radarr['schedule'], 'Every 10 minutes')
        self.assertTrue(radarr['queued'])
        self.assertEqual(self.queued_request()['request_token'], queued['request_token'])
        self.assertEqual(self.fixture_count(), initial_count)

        worker = self.spawn('worker-restarted', [str(ROOT / 'app.py'), '--digest-worker'])
        completed = self.wait_until(lambda: self.successful_probe(first['run_token']),
                                    'Restarted actual worker did not consume the manual request', process=worker)
        self.assertEqual(self.fixture_count(), initial_count + 1)
        automatic = self.row("SELECT * FROM automatic_connection_checks WHERE service='radarr'")
        self.assertAlmostEqual(automatic['next_attempt'] - automatic['checked'], 600, delta=0.001)
        self.assertAlmostEqual(completed['next_run'] - completed['finished'], 600, delta=0.001)
        self.assertEqual(self.row("SELECT interval_seconds FROM background_job_settings WHERE job_id='probe-radarr'")['interval_seconds'], 600)
        self.assertEqual(self.fixture_requests,
                         [('/api/v3/system/status', 'synthetic-radarr-key')] * 2)
        self.assertNotEqual(web.pid, worker.pid)
        self.stop_process(worker)
        self.stop_process(web)
        self.assertTrue(all(process.poll() is not None for process in self.processes))


if __name__ == '__main__':
    unittest.main()
