"""Offline app/control/host-protocol tests, no Docker or real HTTP service."""
from contextlib import closing
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from unittest.mock import Mock, patch

from flask import Flask
from maintenance_app import Authority, Controller, Hooks, MaintenanceError, Store, dispatch, fixed_hooks, register_flask, worker_step
from maintenance_protocol import Enrollment, ProtocolError, canonical, parse_json, public_status, signed, verify, verify_request
from private_store import Journal, PrivatePaths, Profile
from host_engine import EngineError, HostEngine
from test_drafts import FakeAdapter, image


class AppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.store = Store(root=self.root / '.maintenance', initialize=True)
        self.authority = Authority('owner', 3, True)
        self.version = '2.25.0'
        self.generation = 'e' * 64
        self.hooks = Hooks(lambda: self.authority, lambda: self.generation, lambda: self.version, lambda: True)
        self.controller = Controller(self.store, self.hooks)
        self.enrollment = Enrollment.create('owner')
        self.user = {'id': 'owner', 'session_version': 3}
        self.previous, self.target = image('2.25.0', 'd'), image('2.26.0', 'a')
        challenge = str(uuid.uuid4())
        response = self.controller.enroll(canonical({'protocol': 'keep.enrollment.v1',
            'install_id': self.enrollment.install_id, 'owner_id': 'owner', 'epoch': 1,
            'key': self.enrollment.key.hex(), 'challenge': challenge, 'expected': self.previous.as_dict()}), now=1000)
        self.assertEqual(verify(self.enrollment, response)['challenge'], challenge)
        self.advisory()

    def advisory(self, *, target=None, active=None, now=1000):
        self.controller.advisory(signed(self.enrollment, {'protocol': 'keep.host-advisory.v1',
            'install_id': self.enrollment.install_id, 'epoch': 1,
            'target': (target or self.target).as_dict(), 'host_active_request': active}), now=now)

    def start(self, operation='install', *, request_id=None, now=1000):
        snapshot = self.controller.snapshot(user=self.user, now=now)
        body = {'request_id': request_id or str(uuid.uuid4()), 'operation': operation,
                'confirmation': snapshot['confirmation']}
        self.controller.enqueue(body, user=self.user, now=now)
        request = verify_request(self.enrollment, self.controller.pending_request(), now=now)
        return body, request

    def command(self, request, verb, **extra):
        return signed(self.enrollment, {'protocol': 'keep.host-command.v1',
            'install_id': self.enrollment.install_id, 'epoch': 1,
            'request_id': request.request_id, 'verb': verb, 'payload_sha256': request.payload_sha256,
            'credential_version': request.credential_version, **extra})

    def call(self, request, verb, *, now=1000, **kwargs):
        return verify(self.enrollment, self.controller.mailbox(verb, self.command(request, verb, **kwargs), now=now))

    def progress(self, request, *, sequence, phase):
        envelope = parse_json(public_status(self.enrollment, request, sequence=sequence, phase=phase))
        return self.call(request, 'status', progress=envelope)

    def test_readonly_snapshot_does_not_create_unenrolled_state_or_modify_enrolled_bytes(self):
        missing = Store(root=self.root / 'absent')
        snapshot = Controller(missing, self.hooks).snapshot(user=self.user, now=1000)
        self.assertFalse(snapshot['enrolled'])
        self.assertFalse(missing.root.exists())
        before = {p.name: p.read_bytes() for p in self.store.root.iterdir() if p.is_file()}
        self.assertTrue(self.controller.snapshot(user=self.user, now=1000)['can_install'])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.store.root.iterdir() if p.is_file()})

    def test_browser_cannot_choose_image_commands_paths_or_stale_target(self):
        snapshot = self.controller.snapshot(user=self.user, now=1000)
        body = {'request_id': str(uuid.uuid4()), 'operation': 'install', 'confirmation': snapshot['confirmation']}
        for field in ('target', 'path', 'command', 'compose', 'owner_id', 'credential_version'):
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                self.controller.enqueue({**body, field: 'arbitrary'}, user=self.user, now=1000)
        self.advisory(target=image('2.27.0', 'f'))
        with self.assertRaises(MaintenanceError) as caught:
            self.controller.enqueue(body, user=self.user, now=1000)
        self.assertEqual(caught.exception.code, 'confirmation_changed')

    def test_run_once_request_retains_exact_nonce_and_payload_after_lost_response(self):
        body, request = self.start()
        original = self.controller.pending_request()
        self.controller.enqueue(body, user=self.user, now=1001)
        self.assertEqual(self.controller.pending_request(), original)
        self.assertEqual(verify_request(self.enrollment, original, now=1001).request_id, request.request_id)
        with self.assertRaises(MaintenanceError):
            self.controller.enqueue({**body, 'operation': 'restart'}, user=self.user, now=1001)
        with self.assertRaises(MaintenanceError):
            self.start('restart', now=1001)

    def test_stale_owner_session_inactive_owner_and_changed_credentials_abort_before_cutover(self):
        for user in ({'id': 'viewer', 'session_version': 3}, {'id': 'owner', 'session_version': 2}, {'id': 'owner'}):
            with self.assertRaises(MaintenanceError):
                self.controller.snapshot(user=user, now=1000)
        _, request = self.start()
        self.authority = replace(self.authority, credential_version=4)
        with self.assertRaises(MaintenanceError):
            self.call(request, 'claim')
        self.user['session_version'] = 4
        status = self.controller.snapshot(user=self.user, request_id=request.request_id, now=1000)
        self.assertEqual(status['request_state'], 'aborted')
        with self.store.work():
            pass

    def test_claim_expiry_and_changed_configuration_cannot_execute_again(self):
        _, request = self.start()
        with self.assertRaises(ProtocolError):
            self.call(request, 'claim', now=1600)
        self.assertEqual(self.controller.snapshot(user=self.user, request_id=request.request_id, now=1000)['request_state'], 'aborted')
        _, request = self.start(now=1000)
        self.generation = 'f' * 64
        with self.assertRaises(MaintenanceError):
            self.call(request, 'claim')

    def test_drain_waits_for_active_worker_smtp_probe_and_api_work_then_blocks_new_work(self):
        _, request = self.start()
        self.call(request, 'claim')
        entered, finish = threading.Event(), threading.Event()
        def work():
            with self.store.work():
                entered.set()
                finish.wait(2)
        thread = threading.Thread(target=work)
        thread.start()
        self.assertTrue(entered.wait(1))
        with self.assertRaises(MaintenanceError):
            self.controller.mailbox('drain', self.command(request, 'drain'), now=1000, drain_timeout=.02)
        with self.assertRaises(MaintenanceError):
            with self.store.work():
                pass
        finish.set()
        thread.join(2)
        reply = self.call(request, 'drain')
        self.assertEqual((reply['gate'], reply['drained']), ('closed', True))

    def test_independent_store_and_process_lock_cannot_bypass_closed_gate(self):
        _, request = self.start()
        self.call(request, 'claim')
        self.call(request, 'drain')
        second = Store(root=self.store.root)
        with self.assertRaises(MaintenanceError):
            with second.work():
                pass
        # Schema initialization is separately permitted for expected/target
        # images; this does not open ordinary work or worker recovery.
        with second.startup_schema('2.26.0'):
            pass
        with self.assertRaises(MaintenanceError):
            with second.startup_schema('9.0.0'):
                pass

    def test_missing_gate_cannot_admit_startup_schema_or_change_application_database(self):
        _, request = self.start()
        self.call(request, 'claim')
        self.call(request, 'drain')
        application = self.root / 'protected.sqlite3'
        with sqlite3.connect(application) as db:
            db.execute('CREATE TABLE protected(value TEXT)')
            db.execute("INSERT INTO protected VALUES ('original')")
        before = application.read_bytes()
        with closing(self.store._connect()) as db, db:
            db.execute('DELETE FROM gate WHERE id=1')
        for version in ('2.25.0', '2.26.0', '9.0.0'):
            with self.subTest(version=version), self.assertRaises(MaintenanceError) as caught:
                with self.store.startup_schema(version):
                    with sqlite3.connect(application) as db:
                        db.execute('CREATE TABLE forbidden_migration(value TEXT)')
            self.assertEqual(caught.exception.code, 'state_unavailable')
            self.assertEqual(application.read_bytes(), before)

    def test_first_enrollment_cannot_create_a_barrier_after_work_was_admitted(self):
        absent = Store(root=self.root / 'not-started')
        controller = Controller(absent, self.hooks)
        enrollment = Enrollment.create('owner')
        payload = canonical({'protocol':'keep.enrollment.v1',
            'install_id':enrollment.install_id,'owner_id':'owner','epoch':1,
            'key':enrollment.key.hex(),'challenge':str(uuid.uuid4()),
            'expected':self.previous.as_dict()})
        with absent.work():
            with self.assertRaises(MaintenanceError) as caught:
                controller.enroll(payload, now=1000)
            self.assertEqual(caught.exception.code, 'state_unavailable')
            self.assertFalse(absent.root.exists())
        absent.initialize()
        with absent.work():
            with self.assertRaises(MaintenanceError):
                controller.enroll(payload, now=1000)
        self.assertIsNone(absent._rows()[0])
        controller.enroll(payload, now=1000)
        self.assertEqual(absent._rows()[0]['install_id'], enrollment.install_id)

    def test_startup_refuses_current_and_target_until_active_work_is_drained(self):
        _, request = self.start()
        self.call(request, 'claim')
        entered, finish = threading.Event(), threading.Event()
        def callback():
            with self.store.work():
                entered.set()
                finish.wait(2)
        thread = threading.Thread(target=callback)
        thread.start()
        self.assertTrue(entered.wait(1))
        try:
            with self.assertRaises(MaintenanceError):
                self.controller.mailbox('drain', self.command(request,'drain'), now=1000, drain_timeout=.02)
            self.assertEqual(self.store._rows()[1]['drained'], 0)
            for version in ('2.25.0','2.26.0'):
                with self.subTest(version=version), self.assertRaises(MaintenanceError):
                    with self.store.startup_schema(version):
                        self.fail('Schema startup escaped unfinished drain')
        finally:
            finish.set()
            thread.join(2)
        self.call(request, 'drain')
        for version in ('2.25.0','2.26.0'):
            with self.store.startup_schema(version):
                pass

    def test_initialization_cannot_reopen_missing_or_closed_existing_gate(self):
        _, request = self.start()
        self.call(request,'claim')
        self.call(request,'drain')
        before = self.store._rows()[1]
        self.store.initialize()
        self.assertEqual(self.store._rows()[1], before)
        with closing(self.store._connect()) as db, db:
            db.execute('DELETE FROM gate WHERE id=1')
        with self.assertRaises(MaintenanceError):
            self.store.initialize()
        self.assertIsNone(self.store._rows()[1])

    def test_real_independent_process_work_lease_is_drained_before_mutation(self):
        _, request = self.start('restart')
        self.call(request, 'claim')
        code = "from maintenance_app import Store; import sys;\nwith Store(root=sys.argv[1]).work():\n print('ready',flush=True); sys.stdin.readline()\n"
        process = subprocess.Popen([sys.executable, '-B', '-c', code, str(self.store.root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=Path(__import__('maintenance_app').__file__).resolve().parent, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), 'ready')
            with self.assertRaises(MaintenanceError):
                self.controller.mailbox('drain', self.command(request, 'drain'), now=1000, drain_timeout=.02)
            process.communicate('finished\n', timeout=3)
            self.assertEqual(process.returncode, 0)
            self.assertTrue(self.call(request, 'drain')['drained'])
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)
    def test_commit_is_required_before_gate_reopens_and_repeat_completion_cannot_rollback(self):
        _, request = self.start()
        self.call(request, 'claim')
        self.call(request, 'drain')
        with self.assertRaises(MaintenanceError):
            self.call(request, 'complete')
        self.version = '2.26.0'
        self.progress(request, sequence=7, phase='committed')
        self.assertEqual(self.call(request, 'complete')['gate'], 'open')
        self.authority = replace(self.authority, credential_version=4)
        self.assertEqual(self.call(request, 'complete', now=2000)['gate'], 'open')
        with self.assertRaises(MaintenanceError):
            self.call(request, 'abort', now=2000)
        # A commit is not a completed host operation. Another browser cannot
        # start work until the signed final outcome is mirrored.
        self.user['session_version'] = 4
        self.assertFalse(self.controller.snapshot(user=self.user, now=1000)['can_restart'])
        self.progress(request, sequence=8, phase='success')
        self.assertTrue(self.controller.snapshot(user=self.user, now=1000)['can_restart'])

    def test_retained_terminal_request_reconciles_after_explicit_signing_epoch_rotation(self):
        _, request = self.start('restart')
        self.call(request, 'claim')
        self.call(request, 'drain')
        self.progress(request, sequence=7, phase='committed')
        self.call(request, 'complete')
        self.progress(request, sequence=8, phase='success')
        replacement = Enrollment(self.enrollment.install_id, 'owner', 2, b'x' * 32)
        self.controller.enroll(canonical({'protocol': 'keep.enrollment.v1',
            'install_id': replacement.install_id, 'owner_id': replacement.owner_id,
            'epoch': replacement.epoch, 'key': replacement.key.hex(),
            'challenge': str(uuid.uuid4()), 'expected': self.previous.as_dict()}), now=1000)
        snapshot = self.controller.snapshot(user=self.user, request_id=request.request_id, now=1000)
        self.assertEqual(snapshot['request_state'], 'completed')
        self.assertEqual(snapshot['operation']['phase'], 'success')
        self.assertTrue((self.store.root / 'key-1.json').exists())
        self.assertTrue((self.store.root / 'key-2.json').exists())

    def test_matching_recovery_commit_preserves_control_request_when_main_database_is_replaced(self):
        database = self.root / 'keep.sqlite3'
        with sqlite3.connect(database) as db:
            db.execute('CREATE TABLE protected(value TEXT)')
            db.execute("INSERT INTO protected VALUES ('before')")
        _, request = self.start()
        self.call(request, 'claim')
        self.call(request, 'drain')
        database.unlink()
        with sqlite3.connect(database) as db:
            db.execute('CREATE TABLE restored(value TEXT)')
        reconnect = Controller(Store(root=self.store.root), self.hooks)
        self.assertEqual(reconnect.snapshot(user=self.user, request_id=request.request_id, now=1000)['request_state'], 'claimed')
        self.progress(request, sequence=12, phase='recovery-committed')
        self.assertEqual(self.call(request, 'complete', now=3000)['gate'], 'open')

    def test_progress_is_authenticated_sanitized_and_cannot_regress(self):
        _, request = self.start()
        self.call(request, 'claim')
        self.progress(request, sequence=2, phase='pulling')
        with self.assertRaises(ProtocolError):
            self.progress(request, sequence=1, phase='resolving')
        with self.assertRaises(ProtocolError):
            self.progress(request, sequence=2, phase='draining')
        with self.assertRaises(ProtocolError):
            self.progress(request, sequence=3, phase='accepted')
        snapshot = self.controller.snapshot(user=self.user, request_id=request.request_id, now=1000)
        self.assertEqual(snapshot['operation']['phase'], 'pulling')
        self.assertEqual(snapshot['operation']['target_version'], '2.26.0')
        self.assertNotIn(self.enrollment.key.hex(), str(snapshot))
        self.assertNotIn(str(self.root), str(snapshot))
        self.assertNotIn('sha256:', str(snapshot))

    def test_unknown_request_is_not_received_only_with_current_intact_host_and_app_records(self):
        request_id = str(uuid.uuid4())
        status = self.controller.snapshot(user=self.user, request_id=request_id, now=1000)
        self.assertEqual(status['request_state'], 'not_received')
        self.assertEqual(status['requested_request_id'], request_id)
        self.assertEqual(self.controller.snapshot(user=self.user, request_id=request_id, now=1091)['request_state'], 'unknown')
        self.advisory(active=request_id)
        self.assertEqual(self.controller.snapshot(user=self.user, request_id=request_id, now=1000)['request_state'], 'unknown')

    def test_flask_first_hook_blocks_all_incidental_get_writes_and_validates_csrf(self):
        app = Flask(__name__)
        app.secret_key = 'synthetic-only'
        cleanup = Mock()
        app.before_request(cleanup)
        app.add_url_rule('/health', 'health', lambda: {'status': 'ok'})
        app.add_url_rule('/api/v1/media', 'api', lambda: {'items': []})
        app.add_url_rule('/api/webhooks/maintainerr', 'webhook', lambda: {'queued': True}, methods=['POST'])
        register_flask(app, self.controller, read_only_about=lambda snapshot: {'paused_about': True, 'snapshot': snapshot})
        client = app.test_client()
        with patch('maintenance_app.time.time', return_value=1000):
            with client.session_transaction() as session:
                session['plex_user'], session['csrf_token'] = self.user, 'csrf'
            response = client.get('/settings/about/maintenance/status')
            self.assertEqual(response.status_code, 200)
            cleanup.assert_not_called()
            body = {'request_id': str(uuid.uuid4()), 'operation': 'restart',
                    'confirmation': response.json['snapshot']['confirmation']}
            self.assertEqual(client.post('/settings/about/maintenance/start', json=body).status_code, 403)
            self.assertEqual(client.post('/settings/about/maintenance/start', json={**body, 'command': 'forbidden'},
                headers={'X-CSRF-Token': 'csrf'}).status_code, 400)
            self.assertEqual(client.get('/settings/about/maintenance/status?request_id=invalid').status_code, 400)
            self.assertEqual(client.post('/settings/about/maintenance/start', json=body,
                headers={'X-CSRF-Token': 'csrf'}).status_code, 202)
            request = verify_request(self.enrollment, self.controller.pending_request(), now=1000)
            self.call(request, 'claim')
            self.call(request, 'drain')
            self.assertEqual(client.get('/api/v1/media').status_code, 503)
            self.assertEqual(client.post('/api/webhooks/maintainerr', json={}).status_code, 503)
            self.assertEqual(client.get('/health').status_code, 200)
            self.assertTrue(client.get('/settings/about').json['paused_about'])
            cleanup.assert_not_called()

    def test_restart_request_has_no_target_and_does_not_follow_new_release_advisory(self):
        _, request = self.start('restart')
        self.assertIsNone(request.target)
        self.assertEqual(request.expected, self.previous)
        self.advisory(target=image('2.27.0', 'f'))
        status = self.controller.snapshot(user=self.user, request_id=request.request_id, now=1000)
        self.assertEqual(status['operation']['target_version'], '2.25.0')

    def test_fixed_hello_advisory_and_pending_request_dispatch_never_exposes_key(self):
        _, request = self.start()
        reply = verify(self.enrollment, dispatch(self.controller, 'hello', b'', now=1000))
        self.assertEqual(reply['protocol'], 'keep.app-hello.v1')
        queued = verify_request(self.enrollment, canonical(reply['pending']), now=1000)
        self.assertEqual(queued, request)
        self.assertNotIn(self.enrollment.key.hex(), str(reply))
        with self.assertRaises(ProtocolError):
            dispatch(self.controller, 'arbitrary-command', b'')

    def test_gated_worker_step_does_not_claim_send_probe_or_recover(self):
        _, request = self.start('restart')
        self.call(request, 'claim')
        self.call(request, 'drain')
        callback = Mock()
        self.assertEqual(worker_step(self.store, callback), (False, None))
        callback.assert_not_called()

    def test_fixed_neutral_hooks_read_current_owner_and_effective_config_without_flask_or_db_writes(self):
        database, packaged_version = self.root / 'fixed.sqlite3', self.root / 'VERSION'
        packaged_version.write_text('2.25.0\n')
        with sqlite3.connect(database) as db:
            db.executescript('''
                CREATE TABLE installation(id INTEGER,owner TEXT,complete INTEGER);
                INSERT INTO installation VALUES (1,'7',1);
                CREATE TABLE user_profiles(plex_id TEXT,session_version INTEGER,status TEXT,auth_type TEXT,plex_access TEXT);
                INSERT INTO user_profiles VALUES ('7',3,'active','plex','active');
                CREATE TABLE connection_settings(name TEXT,value TEXT);
                INSERT INTO connection_settings VALUES ('PLEX_ADMIN_TOKEN','synthetic-saved-token');
                CREATE TABLE plex_connection_overrides(name TEXT);
                INSERT INTO plex_connection_overrides VALUES ('PLEX_ADMIN_TOKEN');
            ''')
        before = database.read_bytes()
        real_path = Path
        def paths(value):
            return {'/app/data/keep.sqlite3': database, '/app/VERSION': packaged_version}.get(str(value), real_path(value))
        with patch('maintenance_app.Path', side_effect=paths), patch.dict('os.environ', {}, clear=True):
            hooks = fixed_hooks(qualified=True)
            self.assertEqual(hooks.authority(), Authority('7', 3, True))
            self.assertEqual(hooks.version(), '2.25.0')
            generation = hooks.config_generation()
            with patch.dict('os.environ', {'PLEX_ADMIN_TOKEN': 'synthetic-environment-token'}):
                self.assertEqual(hooks.config_generation(), generation)
            with patch.dict('os.environ', {'KEEP_URL': 'https://keep.example.test'}):
                self.assertNotEqual(hooks.config_generation(), generation)
            with patch.dict('os.environ', {'PUSHOVER_ENABLED': 'false', 'PUSHOVER_APP_TOKEN': 'invalid-private-token'}):
                ignored = hooks.config_generation()
                self.assertEqual(len(ignored), 64)
                with patch.dict('os.environ', {'PUSHOVER_APP_TOKEN': 'different-invalid-private-token'}):
                    self.assertNotEqual(hooks.config_generation(), ignored)
            self.assertEqual(database.read_bytes(), before)
            with sqlite3.connect(database) as db:
                db.execute("UPDATE user_profiles SET session_version=4,status='disabled'")
            self.assertEqual(hooks.authority(), Authority('7', 4, False))


class ProtocolEndToEndTests(unittest.TestCase):
    setUp = AppTests.setUp
    advisory = AppTests.advisory
    start = AppTests.start
    command = AppTests.command
    call = AppTests.call

    def adapter(self, *, fail_activation=False):
        paths = PrivatePaths()
        installation = paths.mkdir(self.root / 'installation')
        state = paths.mkdir(self.root / 'host-state')
        config = paths.mkdir(self.root / 'docker-config')
        paths.publish(installation / '.env', b'SYNTHETIC=true\n')
        paths.publish(installation / 'compose.yml', b'services: {}\n')
        paths.publish(self.root / 'docker', b'synthetic-fixed-executable')
        profile = Profile(installation, state, self.root / 'docker', config, 'synthetic',
            'unix:///synthetic.sock', 'synthetic-daemon', 'keep-trial', 'keep-trial-data',
            (installation / 'compose.yml',), installation / '.env')
        fixture = self

        class AppProtocolAdapter(FakeAdapter):
            def revalidate_authority(self, request, profile):
                fixture.call(request, 'claim')
                fixture.call(request, 'revalidate')

            def close_gate_and_drain(self, request):
                fixture.call(request, 'drain')
                self.gate = 'closed'

            def activate_both_paused(self, target, profile):
                self.image, self.database = target, 'synthetic migrated database'
                fixture.version = target.version
                if fail_activation and not self.preserved:
                    raise EngineError('Synthetic activation interruption')

            def restore_matched_database_config_and_image(self, request, profile):
                self.image, self.database = request.expected, 'synthetic original database'
                fixture.version = request.expected.version

            def open_gate_and_verify(self, request):
                journal = Journal(paths, state, request.request_id, request.payload_sha256)
                record = journal.records()[-1]
                envelope = parse_json(public_status(fixture.enrollment, request,
                    sequence=record['sequence'], phase=record['phase']))
                fixture.call(request, 'status', progress=envelope)
                fixture.call(request, 'complete')
                self.gate = 'open'

            def abort_gate_without_cutover(self, request):
                fixture.call(request, 'abort')

        adapter = AppProtocolAdapter()
        return HostEngine(paths, profile, adapter), adapter, paths, state

    def test_browser_host_durable_commit_app_reopen_and_exact_request_replay(self):
        _, request = self.start()
        engine, adapter, paths, state = self.adapter()
        result = engine.execute(request)
        self.assertEqual(result['phase'], 'success')
        self.assertEqual(adapter.gate, 'open')
        snapshot = self.controller.snapshot(user=self.user, request_id=request.request_id, now=1000)
        self.assertEqual(snapshot['request_state'], 'completed')
        records = Journal(paths, state, request.request_id, request.payload_sha256).records()
        self.assertIn('committed', [row['phase'] for row in records])
        self.assertEqual(engine.execute(request), result)
        self.assertEqual(self.version, request.target.version)
        envelope = parse_json(public_status(self.enrollment, request, sequence=result['sequence'], phase=result['phase']))
        self.call(request, 'status', progress=envelope)
        self.assertEqual(self.controller.snapshot(user=self.user, request_id=request.request_id, now=1000)['operation']['phase'], 'success')

    def test_failed_activation_host_matched_recovery_and_original_browser_request_survive(self):
        _, request = self.start()
        engine, adapter, paths, state = self.adapter(fail_activation=True)
        with self.assertRaises(EngineError):
            engine.execute(request)
        records = Journal(paths, state, request.request_id, request.payload_sha256).records()
        self.assertEqual(records[-1]['phase'], 'recovered')
        self.assertEqual(adapter.preserved, ['synthetic migrated database'])
        self.assertEqual(adapter.database, 'synthetic original database')
        self.assertEqual(self.version, request.expected.version)
        snapshot = self.controller.snapshot(user=self.user, request_id=request.request_id, now=1000)
        self.assertEqual(snapshot['request_state'], 'completed')
        self.assertEqual(snapshot['operation']['phase'], 'recovery-committed')


if __name__ == '__main__':
    unittest.main()
