"""Real worker-entry diagnostics using private synthetic data, never Docker."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid

import volume_worker


class WorkerDiagnosticTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='keep-volume-diagnostic-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.source=Path(volume_worker.__file__).read_text()

    def run_worker(self,body):
        # Execute the unchanged injected source under its actual python -c
        # filename, translating only the synthetic named-volume directory.
        code='import sys;n={"__name__":"fixture"};exec(compile(sys.argv[1],"<string>","exec"),n);n["main"](n["Path"](sys.argv[2]))'
        return subprocess.run((sys.executable,'-B','-c',code,self.source,str(self.root)),
                              input=body,capture_output=True,timeout=5)

    def diagnostic(self,result):
        self.assertEqual(result.returncode,1)
        self.assertEqual(result.stdout,b'')
        prefix=volume_worker.DIAGNOSTIC_PREFIX.encode()
        self.assertTrue(result.stderr.startswith(prefix))
        self.assertLessEqual(len(result.stderr),1024)
        self.assertEqual(result.stderr.count(b'\n'),1)
        value=json.loads(result.stderr[len(prefix):])
        self.assertEqual(set(value),{'type','lines'})
        self.assertLessEqual(len(value['lines']),8)
        self.assertTrue(all(type(line) is int and 1<=line<=len(self.source.splitlines()) for line in value['lines']))
        return value

    def test_malformed_command_reveals_no_input_or_decoder_details(self):
        result=self.run_worker(b'{"secret":"private-user-password","sql":"SELECT private"')
        self.assertEqual(self.diagnostic(result)['type'],'JSONDecodeError')
        self.assertNotIn(b'private',result.stderr)
        self.assertNotIn(str(self.root).encode(),result.stderr)

    def test_private_path_guard_still_exits_one_without_path_or_values(self):
        self.root.chmod(0o755)
        command={'operation':'snapshot','request_id':str(uuid.uuid4()),'attempt_id':None,
                 'expected_sha256':None,'expected_bytes':None,'columns':None}
        result=self.run_worker(json.dumps(command).encode())
        self.assertEqual(self.diagnostic(result)['type'],'VolumeError')
        self.assertNotIn(str(self.root).encode(),result.stderr)
        self.assertNotIn(command['request_id'].encode(),result.stderr)

    def test_success_result_and_snapshot_are_unchanged(self):
        database=self.root/'keep.sqlite3'
        with closing(sqlite3.connect(database)) as db,db:
            db.execute('CREATE TABLE keep_schedules(collection_id TEXT,media_id TEXT)')
            db.execute("INSERT INTO keep_schedules VALUES('1','42')")
        database.chmod(0o600)
        command={'operation':'snapshot','request_id':str(uuid.uuid4()),'attempt_id':None,
                 'expected_sha256':None,'expected_bytes':None,'columns':None}
        result=self.run_worker(json.dumps(command).encode())
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stderr,b'')
        value=json.loads(result.stdout)
        self.assertEqual(value['schema'],'keep.volume-result.v1')
        self.assertEqual(value['fingerprint']['keep_schedules']['rows'],1)
        self.assertTrue((self.root/'.maintenance/recovery'/command['request_id']/'database.sqlite3').is_file())

    def test_foreign_frames_and_custom_exception_name_are_excluded(self):
        private_error=type('PrivateCredentialError',(Exception,),{})
        try:raise private_error('private endpoint and database values')
        except Exception as error:value=volume_worker.error_diagnostic(error)
        self.assertEqual(value,{'type':'Exception','lines':[]})
        self.assertNotIn('private',json.dumps(value).lower())

    def test_deep_owned_trace_is_bounded_without_function_or_filename(self):
        namespace={}
        exec(compile('def private_secret_function(depth):\n if depth:private_secret_function(depth-1)\n else:raise ValueError("private-secret")\n',
                     volume_worker.error_diagnostic.__code__.co_filename,'exec'),namespace)
        try:namespace['private_secret_function'](20)
        except ValueError as error:value=volume_worker.error_diagnostic(error)
        self.assertEqual(value['type'],'ValueError')
        self.assertEqual(len(value['lines']),8)
        self.assertNotIn('private',json.dumps(value))
        self.assertNotIn('volume_worker.py',json.dumps(value))


if __name__=='__main__':unittest.main()
