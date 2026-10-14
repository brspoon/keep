"""Application startup and owner bootstrap against retained legacy helper state."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid

SOURCE=Path(__file__).resolve().parents[1]
STARTUP='''
from pathlib import Path
import sys
import helper_retirement
helper_retirement.FIXED_ROOT=Path(sys.argv[1])
try:
    import app
except helper_retirement.HelperRetirementError:
    print('retirement-held')
    raise SystemExit(2)
assert app.app.test_client().get('/health').status_code==200
assert app.owner_id()=='7'
print('startup-ready')
'''
BOOTSTRAP='''
from pathlib import Path
import runpy,sys
import helper_retirement
helper_retirement.FIXED_ROOT=Path(sys.argv[1])
sys.argv=['onboarding','bootstrap']
runpy.run_module('onboarding',run_name='__main__')
'''


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def signed(value):
    return canonical({'payload':value,'mac':hmac.new(bytes.fromhex('d'*64),canonical(value),hashlib.sha256).hexdigest()})


class RetiredHelperStartupTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name).resolve()
        self.legacy=self.root/'.maintenance'
        self.database=self.root/'application-data'/'keep.sqlite3'
        self.environment={**os.environ,'FLASK_SECRET_KEY':'synthetic-helper-retirement-app-secret-0000',
            'KEEP_DB_PATH':str(self.database),'PLEX_OWNER_ID':'7','PLEX_CLIENT_IDENTIFIER':'retirement-test',
            'KEEP_TRANSPORT_MODE':'https','KEEP_URL':'https://keep.example.invalid',
            'PLEX_SERVER_URL':'https://plex.example.invalid','PLEX_MACHINE_IDENTIFIER':'synthetic-machine','PLEX_ADMIN_TOKEN':'',
            'EMAIL_ENABLED':'false','PUSHOVER_ENABLED':'false','KEEP_COLLECTIONS':'{}'}

    def legacy_control(self,*,enrolled=False,closed=False,pending=False):
        self.legacy.mkdir(mode=0o700)
        database=self.legacy/'control.sqlite3'
        self.install_id=str(uuid.uuid4())
        self.image={'index_digest':'sha256:'+'a'*64,'native_digest':'sha256:'+'b'*64,
                    'image_id':'sha256:'+'c'*64,'version':'2.26.2','revision':'d'*40,'architecture':'amd64'}
        with sqlite3.connect(database) as db:
            db.executescript('''
                CREATE TABLE enrollment(id INTEGER PRIMARY KEY,install_id TEXT,owner_id TEXT,epoch INTEGER,
                    image_json TEXT,target_json TEXT,helper_seen REAL,host_active_request TEXT);
                CREATE TABLE operations(request_id TEXT PRIMARY KEY,payload BLOB,payload_sha256 TEXT,nonce TEXT,
                    state TEXT,config_generation TEXT,created_at REAL);
                CREATE TABLE gate(id INTEGER PRIMARY KEY,closed INTEGER,request_id TEXT,drained INTEGER);
                CREATE TABLE progress(request_id TEXT PRIMARY KEY,sequence INTEGER,envelope BLOB);
            ''')
            db.execute('INSERT INTO gate VALUES (1,?,?,?)',(int(closed),str(uuid.uuid4()) if closed else None,int(closed)))
            if enrolled or pending:
                db.execute('INSERT INTO enrollment VALUES (1,?,?,1,?,NULL,NULL,NULL)',
                    (self.install_id,'7',json.dumps(self.image)))
            if pending:
                identifier=str(uuid.uuid4())
                payload=self.request(identifier)
                db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,?)',
                    (identifier,signed(payload),hashlib.sha256(canonical(payload)).hexdigest(),'1'*64,'queued','c'*64,1000))
        database.chmod(0o600)
        if enrolled or pending:
            key=self.legacy/'key-1.json'
            key.write_text(json.dumps({'install_id':self.install_id,'owner_id':'7','epoch':1,'key':'d'*64}))
            key.chmod(0o600)

    def fingerprints(self):
        return {str(path.relative_to(self.legacy)):hashlib.sha256(path.read_bytes()).hexdigest()
                for path in self.legacy.rglob('*') if path.is_file()}

    def completed_recovery(self):
        identifier=str(uuid.uuid4())
        payload=self.request(identifier)
        progress={'protocol':'keep.maintenance.status.v1','install_id':self.install_id,'request_id':identifier,
                  'sequence':12,'phase':'recovered','result_code':'recovered'}
        with sqlite3.connect(self.legacy/'control.sqlite3') as db:
            db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,?)',
                (identifier,signed(payload),hashlib.sha256(canonical(payload)).hexdigest(),'1'*64,'completed','e'*64,1000))
            db.execute('INSERT INTO progress VALUES (?,?,?)',(identifier,12,signed(progress)))
        recovery=self.legacy/'recovery'/identifier
        recovery.mkdir(parents=True,mode=0o700);recovery.parent.chmod(0o700)
        snapshot=recovery/'database.sqlite3'
        with sqlite3.connect(snapshot) as db:
            db.execute('CREATE TABLE protected_fixture(value TEXT)')
            db.execute("INSERT INTO protected_fixture VALUES ('retained')")
        snapshot.chmod(0o600)

    def request(self,identifier):
        return {'protocol':'keep.maintenance.v1','install_id':self.install_id,'owner_id':'7','epoch':1,
            'request_id':identifier,'operation':'restart','credential_version':3,'issued_at':1000,
            'expires_at':1600,'nonce':'1'*64,'expected':self.image,'target':None}

    def child(self,code):
        return subprocess.run([sys.executable,'-B','-c',code,str(self.legacy)],cwd=SOURCE,
            env=self.environment,capture_output=True,text=True,timeout=30)

    def test_fresh_installation_starts_without_creating_legacy_helper_state(self):
        result=self.child(STARTUP)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('startup-ready',result.stdout)
        self.assertTrue(self.database.exists())
        self.assertFalse(self.legacy.exists())

    def test_idle_existing_enrollment_starts_and_preserves_legacy_files(self):
        self.legacy_control(enrolled=True)
        before=self.fingerprints()
        result=self.child(STARTUP)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.fingerprints(),before)
        self.assertTrue(self.database.exists())

    def test_completed_recovery_history_starts_without_changing_retained_backups(self):
        self.legacy_control(enrolled=True);self.completed_recovery()
        before=self.fingerprints();result=self.child(STARTUP)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.fingerprints(),before)
        self.assertTrue(self.database.exists())

    def test_pending_or_quiesced_state_holds_before_application_database_writes(self):
        for state in ('pending','quiesced'):
            with self.subTest(state=state):
                # Each child has its own exact fixture and absent database tree.
                with tempfile.TemporaryDirectory(dir=self.root) as case:
                    original_legacy,original_database=self.legacy,self.database
                    self.legacy=Path(case)/'.maintenance';self.database=Path(case)/'application-data'/'keep.sqlite3'
                    self.environment['KEEP_DB_PATH']=str(self.database)
                    self.legacy_control(enrolled=True,pending=state=='pending',closed=state=='quiesced')
                    before=self.fingerprints();result=self.child(STARTUP)
                    self.assertEqual(result.returncode,2,result.stderr)
                    self.assertIn('retirement-held',result.stdout)
                    self.assertFalse(self.database.parent.exists())
                    self.assertEqual(self.fingerprints(),before)
                    self.legacy,self.database=original_legacy,original_database

    def test_standalone_bootstrap_holds_before_owner_schema_or_directory_creation(self):
        self.legacy_control(enrolled=True,closed=True)
        before=self.fingerprints();result=self.child(BOOTSTRAP)
        self.assertEqual(result.returncode,1,result.stderr)
        self.assertIn('retired maintenance helper has unresolved state',result.stderr)
        self.assertFalse(self.database.parent.exists())
        self.assertEqual(self.fingerprints(),before)
