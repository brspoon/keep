"""Real copied Flask integration in isolated interpreters; no host/service I/O."""
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest

DRAFT = Path(__file__).resolve().parents[1]
STARTUP = '''
import json
from pathlib import Path
import sys
import maintenance_app as ma
ma.FIXED_ROOT = Path(sys.argv[1])
try:
    import app
except ma.MaintenanceError as error:
    print(json.dumps({'error':error.code}))
    raise SystemExit(2)
assert app.app.test_client().get('/health').status_code == 200
assert app.worker_startup_recovery() == (False,None)
print(json.dumps({'version':app.APP_VERSION}))
'''
SETUP = r'''
from contextlib import closing
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import uuid
from unittest.mock import Mock, patch
temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
root = Path(temp.name).resolve()
os.environ.update(KEEP_DB_PATH=str(root/'keep.sqlite3'),
    FLASK_SECRET_KEY='synthetic-phase6-integration-secret-0000',
    KEEP_WEBHOOK_SECRET='synthetic-phase6-webhook-secret',
    PLEX_OWNER_ID='7', PLEX_CLIENT_IDENTIFIER='synthetic-phase6',
    KEEP_TRANSPORT_MODE='https', KEEP_URL='https://keep.example.invalid',
    EMAIL_ENABLED='false', PUSHOVER_ENABLED='false', PUSHOVER_APP_TOKEN='',
    KEEP_COLLECTIONS='{"901":"Synthetic Movies"}')
for name in ('PLEX_SERVER_URL','PLEX_MACHINE_IDENTIFIER','PLEX_ADMIN_TOKEN',
             'MAINTAINERR_URL','RADARR_URL','RADARR_API_KEY','SONARR_URL',
             'SONARR_API_KEY','SEERR_URL','SEERR_API_KEY','TAUTULLI_URL',
             'TAUTULLI_API_KEY','SMTP_HOST','SMTP_USER','SMTP_PASSWORD','SMTP_FROM'):
    os.environ.pop(name,None)
os.environ['PLEX_MACHINE_IDENTIFIER'] = 'synthetic-machine'
os.environ['PLEX_SERVER_URL'] = 'https://plex.example.invalid'
import requests
patch('requests.sessions.Session.request',
    side_effect=AssertionError('Synthetic fixture attempted external service I/O')).start()
import maintenance_app as ma
ma.FIXED_ROOT = root/'.maintenance'
import app as keep
assert Path(keep.__file__).parent == Path.cwd()
from maintenance_protocol import Enrollment,ImageIdentity,canonical,parse_json,signed,verify,verify_request
with closing(sqlite3.connect(keep.KEEP_DB_PATH)) as db, db:
    db.execute("""INSERT INTO user_profiles
        (plex_id,plex_username,email,auth_type,status,session_version,plex_access,theme_mode)
        VALUES ('7','Synthetic Owner','owner@example.invalid','plex','active',3,'active','dark')""")
    db.execute("INSERT INTO bootstrap VALUES (1,'expired-code',0)")
    db.execute("INSERT INTO plex_flows VALUES ('expired-flow','binding','login','{}',0)")
    db.execute("INSERT INTO api_keys VALUES ('fixture-key','7','Synthetic fixture','keep_AAAAAAAA',?,?,3,?,0,NULL,NULL)",
        (hashlib.sha256(('keep_'+'A'*43).encode()).hexdigest(),json.dumps(['collections:read']),time.time()))
keep.app.config.update(TESTING=True)
controller = keep.maintenance_controller
user = {'id':'7','username':'Synthetic Owner','auth_type':'plex','session_version':3,'thumb':''}
def owner_client(user=user):
    client = keep.app.test_client()
    with client.session_transaction() as state:
        state['plex_user'] = dict(user)
        state['csrf_token'] = 'synthetic-csrf'
    return client
client = owner_client()
def digest():
    with closing(sqlite3.connect(keep.KEEP_DB_PATH)) as db:
        return hashlib.sha256('\n'.join(db.iterdump()).encode()).hexdigest()
def image(version,char):
    return ImageIdentity('sha256:'+char*64,'sha256:'+'b'*64,
        'sha256:'+'c'*64,version,char*40,'amd64')
def enroll():
    keep.maintenance_store.initialize()
    # Synthetic protocol qualification only; production support remains false.
    controller.hooks = replace(controller.hooks,supported=lambda:True)
    enrollment = Enrollment.create('7')
    current = image(keep.APP_VERSION,'d')
    pieces = keep.APP_VERSION.split('.')
    target_version = '.'.join(pieces[:-1]+[str(int(pieces[-1])+1)])
    target = image(target_version,'a')
    controller.enroll(canonical({'protocol':'keep.enrollment.v1',
        'install_id':enrollment.install_id,'owner_id':'7','epoch':1,
        'key':enrollment.key.hex(),'challenge':str(uuid.uuid4()),'expected':current.as_dict()}))
    controller.advisory(signed(enrollment,{'protocol':'keep.host-advisory.v1',
        'install_id':enrollment.install_id,'epoch':1,'target':target.as_dict(),
        'host_active_request':None}))
    return enrollment,target
def queue():
    enrollment,target = enroll()
    body = {'request_id':str(uuid.uuid4()),'operation':'install',
        'confirmation':controller.snapshot(user=user)['confirmation']}
    response = client.post('/settings/about/maintenance/start',json=body,
        headers={'X-CSRF-Token':'synthetic-csrf'})
    assert response.status_code == 202,response.get_data(as_text=True)
    request = verify_request(enrollment,controller.pending_request())
    def command(verb,**extra):
        envelope = signed(enrollment,{'protocol':'keep.host-command.v1',
            'install_id':enrollment.install_id,'epoch':1,'request_id':request.request_id,
            'verb':verb,'payload_sha256':request.payload_sha256,
            'credential_version':request.credential_version,**extra})
        return envelope
    controller.mailbox('claim',command('claim'))
    return enrollment,target,request,command
def close_gate():
    result = queue()
    controller.mailbox('drain',result[3]('drain'))
    return result
'''
class IntegrationTests(unittest.TestCase):
    def run_case(self, body, timeout=30, qualified=False):
        setup = SETUP
        if qualified:
            setup = setup.replace('import app as keep',
                'import maintenance_mailbox\nmaintenance_mailbox.runtime_qualified = lambda: True\nimport app as keep')
        result = subprocess.run([sys.executable,'-B','-c',setup+'\nstartup_script = '+repr(STARTUP)+'\n'+textwrap.dedent(body)],
            cwd=DRAFT,capture_output=True,text=True,timeout=timeout)
        self.assertEqual(result.returncode,0,result.stderr+'\n'+result.stdout)

    def test_qualified_application_establishes_work_barrier_before_first_enrollment(self):
        self.run_case('''
            assert keep.maintenance_store._exists()
            assert keep.maintenance_store._rows()[0] is None
            assert keep.maintenance_store._rows()[1]['closed'] == 0
            with keep.maintenance_store.work():
                assert ma._depth.get()[str(keep.maintenance_store.root)] is False
            enrollment,target,request,command = close_gate()
            assert keep.maintenance_store._rows()[1]['drained'] == 1
            response = client.get('/preferences')
            assert response.status_code == 503,response.status_code
        ''',qualified=True)

    def test_untrusted_host_cannot_bypass_validation_through_maintenance_shortcuts(self):
        self.run_case('''
            keep.app.config['TRUSTED_HOSTS'] = ['localhost']
            before = digest()
            for path in ('/health','/static/keep-maintenance.js',
                         '/settings/about/maintenance/status','/settings/about'):
                response = client.get(path,base_url='http://attacker.example.invalid')
                assert response.status_code == 400,(path,response.status_code)
            response = client.post('/settings/about/maintenance/start',
                base_url='http://attacker.example.invalid',json={},
                headers={'X-CSRF-Token':'synthetic-csrf'})
            assert response.status_code == 400,response.status_code
            assert digest() == before
        ''')

    def test_ordinary_get_uses_shared_work_and_keeps_existing_api_bookkeeping(self):
        self.run_case('''
            before = digest()
            response = client.get('/api/v1/collections',headers={'Authorization':'Bearer keep_'+'A'*43})
            assert response.status_code == 200,response.get_data(as_text=True)
            assert digest() != before
            with closing(sqlite3.connect(keep.KEEP_DB_PATH)) as db:
                assert db.execute("SELECT last_used_at FROM api_keys").fetchone()[0] is not None
                assert db.execute('SELECT count(*) FROM api_rate_limits').fetchone()[0] > 0
                assert db.execute('SELECT count(*) FROM plex_flows').fetchone()[0] == 0
            with keep.maintenance_store.work():
                # Expired cleanup changes no active authority and needs no upgrade.
                keep.onboarding.cleanup()
        ''')

    def test_closed_gate_blocks_real_get_post_api_webhook_and_cleanup_writes(self):
        self.run_case('''
            close_gate()
            before = digest()
            for path,method in (('/', 'GET'),('/preferences','GET'),('/preferences','POST'),
                ('/api/v1/collections','GET'),('/api/v1/keeps','POST'),
                ('/api/webhooks/maintainerr','POST'),('/auth/plex/callback','GET')):
                response = client.open(path,method=method,
                    headers={'Authorization':'Bearer keep_'+'A'*43,'X-CSRF-Token':'synthetic-csrf'})
                assert response.status_code == 503,(path,response.status_code)
                assert response.json['error']['code'] == 'maintenance_in_progress'
                assert response.headers['Retry-After'] == '5'
            assert digest() == before
            with closing(sqlite3.connect(keep.KEEP_DB_PATH)) as db:
                assert db.execute('SELECT count(*) FROM bootstrap').fetchone()[0] == 1
                assert db.execute('SELECT last_used_at FROM api_keys').fetchone()[0] is None
        ''')

    def test_closed_gate_allows_pure_health_static_status_and_readonly_about(self):
        self.run_case('''
            enrollment,target,request,command = close_gate()
            before = digest()
            before_file = Path(keep.KEEP_DB_PATH).read_bytes()
            with patch.object(keep.onboarding,'cleanup',side_effect=AssertionError('cleanup bypassed gate')), \
                 patch.dict(keep.app.template_context_processors,
                    {None:[Mock(side_effect=AssertionError('context processor ran'))]}):
                assert client.get('/health').json == {'status':'ok'}
                response = client.get('/static/keep-icon.svg')
                assert response.status_code == 200
                response.close()
                status = client.get('/settings/about/maintenance/status?request_id='+request.request_id)
                assert status.status_code == 200
                assert status.json['snapshot']['request_state'] == 'claimed'
                about = client.get('/settings/about')
                assert about.status_code == 200,about.get_data(as_text=True)
                assert b'maintenance-snapshot' in about.data and b'Maintenance is in progress.' in about.data
                assert b'synthetic-phase6-integration-secret' not in about.data
            assert digest() == before
            assert Path(keep.KEEP_DB_PATH).read_bytes() == before_file
            assert client.get('/settings/about/status').status_code == 503
        ''')

    def test_closed_gate_skips_whole_worker_cycles_and_recovery(self):
        self.run_case('''
            close_gate()
            before = digest()
            with patch.object(keep,'_background_maintenance_once',side_effect=AssertionError('worker ran')), \
                 patch.object(keep,'_worker_startup_recovery',side_effect=AssertionError('recovery ran')), \
                 patch.object(keep,'seerr_store',side_effect=AssertionError('Seerr claimed')), \
                 patch.object(keep,'job_store',side_effect=AssertionError('job claimed')):
                assert keep.background_maintenance_once({'plex_sync':0,'reminder_scan':None}) is None
                assert keep.worker_startup_recovery() == (False,None)
                assert ma.worker_step(keep.maintenance_store,keep.seerr_worker_once) == (False,None)
                assert ma.worker_step(keep.maintenance_store,keep.connection_monitor_once) == (False,None)
                for callback in (keep.sync_plex_user_access,keep.expire_due_keeps,
                    keep.queue_due_reminders,keep.reconcile_reminder_queue,
                    keep.prune_notification_queue,keep.process_digest,keep.onboarding.cleanup,
                    keep.log_activity,keep.queue_notifications,keep.cancel_queued_notifications,
                    keep.queue_seerr_availability,keep.send_email,keep.send_notification_push_test,
                    keep.test_smtp_connection,keep.change_maintainerr_exclusion,keep.issue_local_setup,
                    keep.notification_runtime().recover_after_lock,
                    keep.notification_runtime().process_operational,keep.notification_runtime().send):
                    try: callback()
                    except ma.MaintenanceError as error: assert error.code == 'maintenance_in_progress'
                    else: raise AssertionError('Direct mutation helper escaped gate')
            assert digest() == before
        ''')

    def test_startup_permit_allows_current_and_target_but_blocks_wrong_version(self):
        self.run_case('''
            with closing(sqlite3.connect(keep.KEEP_DB_PATH)) as db,db:
                db.execute("INSERT INTO notification_batches VALUES ('inflight','sending',1,NULL)")
                db.execute("INSERT INTO notification_runs VALUES ('inflight',0,NULL)")
                db.execute("""INSERT INTO notification_dispatches
                    (batch_id,provider,destination_id,generation,state,created_at)
                    VALUES ('inflight','email','synthetic@example.invalid','legacy','sending',1)""")
                db.execute("""INSERT INTO background_jobs(job_id,run_token,started,status,result)
                    VALUES ('keep-expiry','synthetic-running',1,'running','Running')""")
            enrollment,target,request,command = close_gate()
            before = digest()
            original = keep.APP_VERSION
            keep.APP_VERSION = '99.99.99'
            try: keep.initialize_application_schema()
            except ma.MaintenanceError as error: assert error.code == 'state_unavailable'
            else: raise AssertionError('Wrong-version schema initializer ran')
            assert digest() == before
            keep.APP_VERSION = original
            import shutil
            import subprocess
            import sys
            startup = startup_script
            for version in ('99.99.99', original, target.version):
                variant = root/version
                variant.mkdir()
                for path in Path.cwd().iterdir():
                    if path.name in ('app.py','onboarding.py','maintenance_mailbox.py'):
                        shutil.copyfile(path,variant/path.name)
                    elif path.name != 'VERSION' and not path.name.startswith('tmp'):
                        (variant/path.name).symlink_to(path)
                (variant/'VERSION').write_text(version)
                before_import = digest()
                result = subprocess.run([sys.executable,'-B','-c',startup,str(keep.maintenance_store.root)],
                    cwd=variant,capture_output=True,text=True,timeout=10)
                if version == '99.99.99':
                    assert result.returncode == 2,result.stderr
                    assert json.loads(result.stdout) == {'error':'state_unavailable'}
                    assert digest() == before_import
                else:
                    assert result.returncode == 0,result.stderr
                    assert json.loads(result.stdout) == {'version':version}
            with closing(sqlite3.connect(keep.KEEP_DB_PATH)) as db:
                assert db.execute("SELECT state FROM notification_dispatches WHERE batch_id='inflight'").fetchone()[0] == 'sending'
                assert db.execute("SELECT status FROM background_jobs WHERE job_id='keep-expiry'").fetchone()[0] == 'running'
            assert keep.worker_startup_recovery() == (False,None)
        ''')

    def test_get_callback_and_post_authority_lease_are_outer_exclusive(self):
        self.run_case('''
            enroll()
            checks = []
            def capture():
                with keep.maintenance_store.work(authority=True):
                    checks.append(True)
                return {'checked':True}
            for path,method in (('/auth/plex/callback','GET'),('/preferences','POST')):
                rule = next(rule for rule in keep.app.url_map.iter_rules() if rule.rule == path)
                with patch.dict(keep.app.view_functions,{rule.endpoint:capture}):
                    response = client.open(path,method=method)
                    assert response.status_code == 200,(path,response.status_code)
            assert checks == [True,True]
            with keep.maintenance_store.work():
                try: keep.onboarding.finish()
                except ma.MaintenanceError as error: assert error.code == 'authority_lock_required'
                else: raise AssertionError('Authority upgrade unexpectedly succeeded')
        ''')

    def test_drain_waits_until_the_entire_admitted_response_finishes(self):
        self.run_case('''
            import threading
            enrollment,target,request,command = queue()
            entered,release = threading.Event(),threading.Event()
            def media(cid):
                entered.set()
                assert release.wait(5)
                return {'items':[]}
            results = []
            with patch.object(keep,'get_collection_media',side_effect=media), \
                 patch.object(keep,'get_collection_exclusions',return_value={'items':[]}):
                thread = threading.Thread(target=lambda:results.append(owner_client().get('/api/counts').status_code))
                thread.start()
                assert entered.wait(5)
                try: controller.mailbox('drain',command('drain'),drain_timeout=.02)
                except ma.MaintenanceError as error: assert error.code == 'busy'
                else: raise AssertionError('Drain finished while a handler still owned its work')
                assert keep.maintenance_store._rows()[1]['closed'] == 1
                assert keep.maintenance_store._rows()[1]['drained'] == 0
                release.set()
                thread.join(5)
                assert not thread.is_alive() and results == [200]
            controller.mailbox('drain',command('drain'),drain_timeout=.2)
            assert keep.maintenance_store._rows()[1]['drained'] == 1
        ''')

    def test_drain_waits_for_whole_worker_callback_including_its_final_write(self):
        self.run_case('''
            import threading
            enrollment,target,request,command = queue()
            entered,release = threading.Event(),threading.Event()
            def cycle(state):
                entered.set()
                assert release.wait(5)
                with closing(sqlite3.connect(keep.KEEP_DB_PATH)) as db,db:
                    db.execute("INSERT INTO activity_log(action,description) VALUES ('synthetic-worker','Final callback write')")
            with patch.object(keep,'_background_maintenance_once',side_effect=cycle):
                thread = threading.Thread(target=lambda:keep.background_maintenance_once({}))
                thread.start()
                assert entered.wait(5)
                try: controller.mailbox('drain',command('drain'),drain_timeout=.02)
                except ma.MaintenanceError as error: assert error.code == 'busy'
                else: raise AssertionError('Drain released during worker provider callback')
                release.set()
                thread.join(5)
                assert not thread.is_alive()
            with closing(sqlite3.connect(keep.KEEP_DB_PATH)) as db:
                assert db.execute("SELECT count(*) FROM activity_log WHERE action='synthetic-worker'").fetchone()[0] == 1
            controller.mailbox('drain',command('drain'),drain_timeout=.2)
            assert keep.maintenance_store._rows()[1]['drained'] == 1
        ''')

    def test_digest_recovery_waits_for_open_admission_then_runs_only_once(self):
        self.run_case('''
            enrollment,target,request,command = close_gate()
            steps = []
            def sleep(seconds):
                steps.append(seconds)
                if len(steps) == 1:
                    controller.mailbox('abort',command('abort'))
                elif len(steps) == 3:
                    raise StopIteration('Synthetic worker loop finished')
            with patch.object(keep.time,'sleep',side_effect=sleep), \
                 patch('threading.Thread'), \
                 patch.object(keep,'_worker_startup_recovery',wraps=keep._worker_startup_recovery) as recovery, \
                 patch.object(keep,'background_maintenance_once') as cycle:
                try: keep.digest_worker()
                except StopIteration: pass
                else: raise AssertionError('Worker did not terminate fixture loop')
                assert recovery.call_count == 1
                assert cycle.call_count == 2
            assert keep.maintenance_store._rows()[1]['closed'] == 0
        ''')

    def test_stale_authority_and_csrf_return_fixed_errors_without_db_changes(self):
        self.run_case('''
            enrollment,target = enroll()
            before = digest()
            invalid = client.post('/settings/about/maintenance/start',json={},
                headers={'X-CSRF-Token':'wrong-csrf'})
            assert invalid.status_code == 403 and invalid.json['error']['code'] == 'csrf_failed'
            stale = owner_client({**user,'session_version':2})
            response = stale.get('/settings/about/maintenance/status')
            assert response.status_code == 403 and response.json['error']['code'] == 'owner_unavailable'
            anonymous = keep.app.test_client().get('/settings/about/maintenance/status')
            assert anonymous.status_code == 403 and anonymous.json['error']['code'] == 'owner_unavailable'
            assert digest() == before
        ''')

    def test_optional_invalid_push_settings_keep_status_readable_and_change_authority_digest(self):
        self.run_case(r'''
enroll()
before = digest()
with patch.dict(os.environ, {'PUSHOVER_ENABLED':'false','PUSHOVER_APP_TOKEN':'invalid-private-token'}):
    response = client.get('/settings/about/maintenance/status')
    assert response.status_code == 200,response.get_data(as_text=True)
    assert 'invalid-private-token' not in response.get_data(as_text=True)
    assert response.json['snapshot']['can_restart']
    generation = keep.maintenance_configuration()
    with patch.dict(os.environ, {'PUSHOVER_APP_TOKEN':'different-invalid-token'}):
        assert keep.maintenance_configuration() != generation
assert digest() == before
with patch.dict(os.environ, {'SMTP_PORT':'invalid-private-value'}):
    response = client.get('/settings/about/maintenance/status')
    assert response.status_code == 503,response.get_data(as_text=True)
    assert response.json['error']['code'] == 'state_unavailable'
    assert 'invalid-private-value' not in response.get_data(as_text=True)
assert digest() == before
''')

    def test_native_runtime_never_claims_support_and_mailbox_never_imports_app(self):
        self.run_case('''
            assert not keep.maintenance_mailbox.runtime_qualified()
            status = client.get('/settings/about/maintenance/status')
            assert status.status_code == 200 and status.json['snapshot']['reason'] == 'unsupported'
            assert not keep.maintenance_store.root.exists()
            about = client.get('/settings/about')
            assert about.status_code == 200
            import builtins
            import maintenance_mailbox
            original_import = builtins.__import__
            def guarded(name,*args,**kwargs):
                assert name != 'app','standalone mailbox imported Flask app'
                return original_import(name,*args,**kwargs)
            with patch('builtins.__import__',side_effect=guarded):
                output = io.BytesIO()
                assert maintenance_mailbox.main(['hello','--path','/tmp'],stdin=io.BytesIO(),stdout=output) == 2
                assert json.loads(output.getvalue()) == {'error':'maintenance_unavailable'}
                output = io.BytesIO()
                assert maintenance_mailbox.main(['hello'],stdin=io.BytesIO(b'x'*65537),stdout=output) == 2
                assert json.loads(output.getvalue()) == {'error':'maintenance_unavailable'}
        ''')

    def test_standalone_bootstrap_cli_is_gated_before_schema_or_authority_writes(self):
        self.run_case('''
            import subprocess
            import sys
            close_gate()
            before = digest()
            code = "import runpy,sys; from pathlib import Path; import maintenance_app as ma; ma.FIXED_ROOT=Path(sys.argv[1]); sys.argv=['onboarding','bootstrap']; runpy.run_module('onboarding',run_name='__main__')"
            result = subprocess.run([sys.executable,'-B','-c',code,str(keep.maintenance_store.root)],
                cwd=Path.cwd(),capture_output=True,text=True,timeout=5)
            assert result.returncode == 1
            assert result.stdout == ''
            assert 'Keep maintenance is in progress.' in result.stderr
            assert 'Traceback' not in result.stderr
            assert digest() == before
        ''')

    def test_unavailable_control_state_holds_requests_and_retries_worker_recovery(self):
        self.run_case('''
            close_gate()
            before = digest()
            with patch.object(keep.maintenance_store,'_rows',side_effect=sqlite3.OperationalError('synthetic control unavailable')):
                response = client.get('/preferences')
                assert response.status_code == 503
                assert response.json['error']['code'] == 'state_unavailable'
                assert b'synthetic control unavailable' not in response.data
                with patch.object(keep.time,'sleep',side_effect=StopIteration), \
                     patch.object(keep,'_worker_startup_recovery',side_effect=AssertionError('recovery claimed work')):
                    try: keep.digest_worker()
                    except StopIteration: pass
                    else: raise AssertionError('Unavailable admission was not retried')
            assert digest() == before
        ''')

if __name__ == '__main__':
    unittest.main()
