"""Concrete adapter tests: fake Docker, real private SQLite/config/tar fixtures.

No Docker or HTTP requests occur. Subprocess cases run only the local Python
volume worker against temporary directories and exercise real bounded pipes.
"""
from dataclasses import replace
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

from docker_adapter import PosixDockerAdapter, env_image
from host_engine import BoundedRunner, EngineError, HostEngine, Plan
from maintenance_protocol import canonical, parse_json, signed, verify, verify_request
from private_store import Journal
from release_resolver import HTTPSClient, OfficialReleaseResolver
from test_drafts import DraftFixture, image, request
import test_drafts
import volume_worker


class FakeResolver:
    def resolve(self,target):return target


class FakeDocker:
    def __init__(self,fixture):
        self.f=fixture;self.plans=[];self.gate='open';self.foreign=False;self.bad_context=False
        self.bad_owner=False;self.fail_candidate=False;self.lost_complete=False;self.helpers={};self.counter=3
        self.crash_candidate=False
        self.current_credential=3
        self.images={}
        for identity in (fixture.previous,fixture.target):
            self.images[identity.image_id]={'Id':identity.image_id,'Architecture':identity.architecture,'Os':'linux','Size':100000,
                'RepoDigests':[identity.reference],'Labels':{'org.opencontainers.image.version':identity.version,
                    'org.opencontainers.image.revision':identity.revision,'org.opencontainers.image.source':'https://github.com/brspoon/keep'},
                'Descriptor':None,'RootFS':['sha256:'+'9'*64],'User':'10001:10001'}
        self.containers={name:self.container(name,identifier) for name,identifier in zip(('keep-app','keep-digest'),('1'*64,'2'*64))}

    def container(self,name,identifier):
        return {'Id':identifier,'Image':self.f.previous.image_id,'Source':'brspoon/keep:'+self.f.previous.version,'Manifest':None,
            'Labels':{'com.docker.compose.project':self.f.profile.project,
            'com.docker.compose.service':name,'com.docker.compose.project.working_dir':str(self.f.install),
            'com.docker.compose.project.config_files':str(self.f.install/'compose.yml')},
            'Mounts':[{'Type':'volume','Name':self.f.profile.volume,'Destination':'/app/data','RW':True}],
            'State':{'Running':True,'Restarting':False,'Status':'running','Health':'healthy'},
            'Guard':{'ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true']}}

    def run(self,plan):
        self.plans.append(plan);args=list(plan.argv[3:]);first=args[0]
        if first=='context':return canonical('unix:///wrong.sock' if self.bad_context else self.f.profile.docker_endpoint)
        if first=='info':
            if args[-1]=='{{.OSType}}':return b'linux\n'
            if args[-1]=='{{.Architecture}}':return b'x86_64\n'
            return canonical(self.f.profile.daemon_id)
        if first=='volume':return canonical({'Name':self.f.profile.volume,'Driver':'local','Scope':'local','Options':None,
            'Labels':{'com.docker.compose.project':self.f.profile.project,'com.docker.compose.volume':'keep-data'}})
        if first=='ps':
            rows=list(self.containers.values())
            if any(value.startswith('label=io.keep.maintenance.install=') for value in args):ids=list(self.helpers)
            elif any(value.startswith('volume=') for value in args):
                ids=[row['Id'] for row in rows+list(self.helpers.values()) if row['State']['Running']]+(['f'*64] if self.foreign else [])
            else:ids=[row['Id'] for row in rows]
            return ('\n'.join(ids)+'\n').encode()
        if first=='inspect':
            identifier=args[-1]
            row=next((row for row in self.containers.values() if row['Id']==identifier),self.helpers.get(identifier))
            if row is None:raise EngineError('Synthetic missing container')
            return canonical(row)
        if first=='image':
            if args[1]=='inspect':
                reference=args[-1]
                if reference.startswith('brspoon/keep@'):
                    identifier=self.f.target.image_id if reference==self.f.target.reference else self.f.previous.image_id
                else:identifier=reference
                if identifier not in self.images:raise EngineError('Synthetic missing image')
                return canonical(self.images[identifier])
            if args[1]=='save':
                self.f.paths.publish(Path(args[args.index('--output')+1]),self.f.tar_bytes);return b''
            if args[1]=='load':return b'Loaded verified prior image\n'
        if first=='pull':return b'Pulled immutable image\n'
        if first=='compose':
            if 'stop' in args:
                for row in self.containers.values():row['State'].update(Running=False,Status='exited')
                return b''
            if 'up' in args:
                files=[args[i+1] for i,value in enumerate(args) if value=='--file']
                overlay=parse_json(Path(files[-1]).read_bytes());source=overlay['services']['keep-app']['image']
                identifier=self.f.target.image_id if source in (self.f.target.image_id,self.f.target.reference) else self.f.previous.image_id
                for row in self.containers.values():
                    row['Image']=identifier;row['Source']=source;row['Labels']['com.docker.compose.project.config_files']=','.join(files)
                    row['State'].update(Running=True,Status='running',Health='healthy')
                if identifier==self.f.target.image_id:
                    with sqlite3.connect(self.f.volume/'keep.sqlite3') as db:
                        db.execute('CREATE TABLE IF NOT EXISTS migration_marker (value TEXT)')
                    if self.fail_candidate:
                        self.fail_candidate=False;raise EngineError('Synthetic failure after migration')
                    if self.crash_candidate:
                        self.crash_candidate=False;raise SystemExit('Synthetic helper process crash after migration')
                return b''
        if first=='create':
            identifier=format(self.counter,'x')*64;self.counter+=1
            purpose=next(value.split('=',1)[1] for value in args if value.startswith('io.keep.maintenance.purpose='))
            row=self.container(purpose,identifier);row['State'].update(Running=False,Status='created',Health=None)
            row['Source']=args[-4]
            row['Labels']={'io.keep.maintenance.install':self.f.enrollment.install_id,
                'io.keep.maintenance.operation':self.f.command.request_id,'io.keep.maintenance.purpose':purpose}
            row.update(Command=['-B','-c',args[-1]],Entrypoint=['python'],User='10001:10001',Network='none')
            self.helpers[identifier]=row;return (identifier+'\n').encode()
        if first=='start':
            identifier=args[-1];command=parse_json(plan.stdin.strip())
            stream=plan.stdin_file.open('rb') if plan.stdin_file else None
            try:result=volume_worker.dispatch(command,self.f.volume,upload_stream=stream)
            finally:
                if stream:stream.close()
            self.helpers[identifier]['State'].update(Running=False,Status='exited')
            return canonical(result)
        if first=='cp':
            source=args[-2].split(':',1)[1]
            relative=source.removeprefix('/app/data/')
            self.f.paths.publish(Path(args[-1]),(self.f.volume/relative).read_bytes());return b''
        if first=='stop':
            self.helpers[args[-1]]['State'].update(Running=False,Restarting=False,Status='exited');return b''
        if first=='exec':
            if args[-2]=='-c':return canonical(volume_worker.dispatch(parse_json(plan.stdin),self.f.volume))
            verb=args[-1];command=verify(self.f.enrollment,plan.stdin)
            if verb=='drain':self.gate='closed'
            if verb in ('complete','abort'):self.gate='open'
            if verb=='complete' and self.lost_complete:
                self.lost_complete=False;raise EngineError('Synthetic lost result after gate opened')
            active=self.images[self.containers['keep-app']['Image']]
            body={'protocol':'keep.host-result.v1','install_id':self.f.enrollment.install_id,'epoch':self.f.enrollment.epoch,
                'request_id':command['request_id'],'verb':verb,'ok':True,'owner_id':'other-owner' if self.bad_owner else self.f.enrollment.owner_id,
                'credential_version':self.current_credential,'config_generation':'e'*64,'gate':self.gate,
                'drained':self.gate=='closed','version':active['Labels']['org.opencontainers.image.version']}
            return signed(self.f.enrollment,body)
        raise AssertionError('Unexpected fixed Docker plan: '+str(args[:4]))


class AdapterTests(DraftFixture):
    def setUp(self):
        super().setUp()
        self.volume=self.paths.mkdir(self.root/'data')
        database=self.volume/'keep.sqlite3'
        with sqlite3.connect(database) as db:
            db.execute('CREATE TABLE user_profiles (plex_id TEXT PRIMARY KEY,status TEXT,session_version INTEGER)')
            db.execute("INSERT INTO user_profiles VALUES ('local-owner','active',3)")
            db.execute('CREATE TABLE keep_schedules (collection_id TEXT,media_id TEXT,expires_at TEXT)')
            db.execute("INSERT INTO keep_schedules VALUES ('1','42',NULL)")
            db.execute('CREATE TABLE notification_dispatches (event TEXT,state TEXT,created_at REAL)')
            db.execute("INSERT INTO notification_dispatches VALUES ('trial-event','sent',1200)")
        os.chmod(database,0o600)
        self.paths.publish(self.install/'VERSION',b'2.25.0\n')
        archive=self.paths.mkdir(self.root/'image-source')
        self.previous=test_drafts.RecoveryTests.archive(self,archive);self.tar_bytes=(archive/'image.tar').read_bytes()
        self.target=image('2.26.0','a')
        body={**request(self.enrollment),'expected':self.previous.as_dict(),'target':self.target.as_dict()}
        self.command=verify_request(self.enrollment,signed(self.enrollment,body),now=1200)
        PosixDockerAdapter.capture_configuration(self.paths,self.profile)
        self.fake=FakeDocker(self)
        self.adapter=PosixDockerAdapter(self.paths,self.profile,self.enrollment,runner=self.fake,
            resolver=FakeResolver(),wall_time=lambda:1200,sleep=lambda _:None)

    def test_complete_update_persists_immutable_config_and_preserves_protected_data(self):
        result=HostEngine(self.paths,self.profile,self.adapter).execute(self.command)
        self.assertEqual(result['phase'],'success');self.assertEqual(self.fake.gate,'open')
        self.assertEqual({row['Image'] for row in self.fake.containers.values()},{self.target.image_id})
        self.assertIn(('KEEP_IMAGE='+self.target.reference).encode(),(self.install/'.env').read_bytes())
        self.assertEqual((self.install/'VERSION').read_text(),'2.26.0\n')
        with sqlite3.connect(self.volume/'keep.sqlite3') as db:
            self.assertEqual(db.execute('SELECT * FROM keep_schedules').fetchall(),[('1','42',None)])
        self.assertTrue((self.adapter.operation/'recovery'/'image.tar').exists())
        self.assertNotIn('do-not-log',repr([(plan.argv,plan.stdin) for plan in self.fake.plans]))

    def test_real_matching_restore_recovers_old_database_config_image_after_migration_failure(self):
        before=(self.install/'.env').read_bytes();self.fake.fail_candidate=True
        with self.assertRaises(EngineError):HostEngine(self.paths,self.profile,self.adapter).execute(self.command)
        self.assertEqual(self.fake.gate,'open');self.assertEqual((self.install/'.env').read_bytes(),before)
        self.assertEqual((self.install/'VERSION').read_bytes(),b'2.25.0\n')
        self.assertEqual({row['Image'] for row in self.fake.containers.values()},{self.previous.image_id})
        with sqlite3.connect(self.volume/'keep.sqlite3') as db:
            self.assertNotIn('migration_marker',{row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")})
        failed=list((self.volume/'.maintenance'/'recovery'/self.command.request_id/'failed').glob('*/keep.sqlite3'))
        self.assertEqual(len(failed),1)
        with sqlite3.connect(failed[0]) as db:
            self.assertIn('migration_marker',{row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")})
        journal=Journal(self.paths,self.state,self.command.request_id,self.command.payload_sha256)
        self.assertEqual(journal.records()[-1]['phase'],'recovered')

    def test_post_commit_reconnect_keeps_new_user_data_and_handles_changed_session_version(self):
        self.fake.lost_complete=True
        engine=HostEngine(self.paths,self.profile,self.adapter)
        with self.assertRaises(EngineError):engine.execute(self.command)
        with sqlite3.connect(self.volume/'keep.sqlite3') as db:
            db.execute("INSERT INTO keep_schedules VALUES ('1','99',NULL)")
        self.fake.current_credential=4
        fresh=PosixDockerAdapter(self.paths,self.profile,self.enrollment,runner=self.fake,resolver=FakeResolver(),wall_time=lambda:2000)
        self.assertEqual(HostEngine(self.paths,self.profile,fresh).execute(self.command)['phase'],'success')
        with sqlite3.connect(self.volume/'keep.sqlite3') as db:self.assertEqual(db.execute('SELECT count(*) FROM keep_schedules').fetchone()[0],2)

    def test_context_drift_is_rejected_before_any_daemon_request(self):
        self.fake.bad_context=True
        with self.assertRaises(EngineError):self.adapter.assert_daemon()
        self.assertEqual(len(self.fake.plans),1);self.assertEqual(self.fake.plans[0].argv[3],'context')

    def test_expired_accepted_crash_resumes_matching_rollback_without_replaying_candidate(self):
        self.fake.crash_candidate=True
        with self.assertRaises(SystemExit):HostEngine(self.paths,self.profile,self.adapter).execute(self.command)
        journal=Journal(self.paths,self.state,self.command.request_id,self.command.payload_sha256)
        self.assertEqual(journal.records()[-1]['phase'],'activating');self.assertEqual(self.fake.gate,'closed')
        fresh=PosixDockerAdapter(self.paths,self.profile,self.enrollment,runner=self.fake,resolver=FakeResolver(),wall_time=lambda:99999)
        self.assertEqual(HostEngine(self.paths,self.profile,fresh).resume(self.command)['phase'],'recovered')
        images=[parse_json(Path(plan.argv[plan.argv.index('--file',plan.argv.index('--file')+1)+1]).read_bytes())['services']['keep-app']['image']
            for plan in self.fake.plans if plan.argv[3]=='compose' and 'up' in plan.argv]
        self.assertEqual(images,[self.target.reference,self.previous.reference])

    def test_unsealed_crashed_backup_remains_held_without_restore_or_new_activation(self):
        self.adapter.bind(self.command);self.adapter.close_gate_and_drain(self.command);self.adapter.stop_and_verify_both(self.profile)
        journal=Journal(self.paths,self.state,self.command.request_id,self.command.payload_sha256)
        for phase in ('accepted','resolving','pulling','draining','stopping','backing-up'):journal.append(phase)
        before=(self.volume/'keep.sqlite3').read_bytes();self.fake.plans.clear()
        with self.assertRaises(Exception):HostEngine(self.paths,self.profile,self.adapter).resume(self.command)
        self.assertEqual((self.volume/'keep.sqlite3').read_bytes(),before);self.assertEqual(self.fake.gate,'closed')
        self.assertFalse(any(plan.argv[3]=='compose' and 'up' in plan.argv for plan in self.fake.plans))

    def test_interrupted_helper_is_stopped_by_exact_identity_and_uncertain_create_is_adopted(self):
        self.adapter.bind(self.command);self.adapter.close_gate_and_drain(self.command);self.adapter.stop_and_verify_both(self.profile)
        cid=self.adapter.helper('snapshot');self.fake.helpers[cid]['State'].update(Running=True,Status='running')
        (self.adapter.operation/'helper-snapshot.json').unlink()  # Lost publish after successful fixed create.
        self.adapter.reconcile_helpers()
        self.assertFalse(self.fake.helpers[cid]['State']['Running'])
        self.assertEqual(parse_json((self.adapter.operation/'helper-snapshot.json').read_bytes())['container_id'],cid)
        stops=[plan for plan in self.fake.plans if plan.argv[3]=='stop'];self.assertEqual(stops[-1].argv[-1],cid)

    def test_changed_running_helper_is_not_stopped_or_adopted(self):
        self.adapter.bind(self.command);self.adapter.close_gate_and_drain(self.command);self.adapter.stop_and_verify_both(self.profile)
        cid=self.adapter.helper('snapshot');self.fake.helpers[cid]['State'].update(Running=True,Status='running')
        self.fake.helpers[cid]['Entrypoint']=['other-program'];self.fake.plans.clear()
        with self.assertRaises(EngineError):self.adapter.reconcile_helpers()
        self.assertTrue(self.fake.helpers[cid]['State']['Running'])
        self.assertFalse(any(plan.argv[3]=='stop' for plan in self.fake.plans))

    def test_foreign_writer_unenrolled_mount_and_wrong_image_are_rejected(self):
        self.adapter.bind(self.command);self.fake.foreign=True
        with self.assertRaises(EngineError):self.adapter.assert_runtime(self.previous,self.profile)
        self.fake.foreign=False
        self.fake.containers['keep-app']['Mounts'].append({'Type':'bind','Source':'/host','Destination':'/host','RW':True})
        with self.assertRaises(EngineError):self.adapter.discover(images={self.previous.image_id})
        self.fake.containers['keep-app']['Mounts'].pop()
        self.fake.containers['keep-app']['Image']=self.target.image_id
        with self.assertRaises(EngineError):self.adapter.assert_runtime(self.previous,self.profile)

    def test_owner_and_configuration_changes_stop_before_cutover(self):
        self.fake.bad_owner=True
        with self.assertRaises(EngineError):self.adapter.revalidate_authority(self.command,self.profile)
        self.fake.bad_owner=False
        self.paths.publish(self.install/'.env',b'SYNTHETIC_SECRET=changed\n',overwrite=True)
        with self.assertRaises(EngineError):self.adapter.assert_configuration_unchanged(self.profile)
        self.assertTrue(all(row['State']['Running'] for row in self.fake.containers.values()))

    def test_missing_volume_snapshot_can_be_reuploaded_from_sealed_host_backup_without_root(self):
        self.adapter.bind(self.command);self.adapter.close_gate_and_drain(self.command);self.adapter.stop_and_verify_both(self.profile)
        recovery=self.adapter.snapshot_matched_state(self.command,self.profile)
        self.adapter.verify_matched_recovery(recovery,self.previous,self.profile)
        self.adapter.preserve_failed_state(self.command,self.profile)
        snapshot=self.volume/'.maintenance'/'recovery'/self.command.request_id/'database.sqlite3'
        snapshot.unlink()  # Synthetic loss injection, never part of production restoration.
        self.adapter.restore_matched_database_config_and_image(self.command,self.profile)
        self.assertTrue(snapshot.exists());self.assertTrue((self.volume/'keep.sqlite3').exists())
        upload=[plan for plan in self.fake.plans if plan.stdin_file is not None]
        self.assertEqual(len(upload),1);self.assertEqual(upload[0].stdin_file,self.adapter.operation/'recovery'/'database.sqlite3')
        creates=[plan.argv for plan in self.fake.plans if plan.argv[3]=='create']
        self.assertTrue(all('--network' in argv and argv[argv.index('--network')+1]=='none' for argv in creates))
        self.assertTrue(all(argv[argv.index('--user')+1]=='10001:10001' for argv in creates))

    def test_corrupt_recovery_bytes_block_restore_before_loading_or_changing_data(self):
        self.adapter.bind(self.command);self.adapter.close_gate_and_drain(self.command);self.adapter.stop_and_verify_both(self.profile)
        self.adapter.snapshot_matched_state(self.command,self.profile)
        before=(self.volume/'keep.sqlite3').read_bytes();self.fake.plans.clear()
        self.paths.publish(self.adapter.operation/'recovery'/'config-0',b'damaged',overwrite=True)
        with self.assertRaises(Exception):self.adapter.restore_matched_database_config_and_image(self.command,self.profile)
        self.assertEqual((self.volume/'keep.sqlite3').read_bytes(),before)
        self.assertFalse(any(plan.argv[3:5]==('image','load') for plan in self.fake.plans))

    def test_helper_source_network_user_and_command_are_revalidated(self):
        self.adapter.bind(self.command);self.adapter.close_gate_and_drain(self.command);self.adapter.stop_and_verify_both(self.profile)
        cid=self.adapter.helper('snapshot');self.fake.helpers[cid]['Network']='bridge'
        with self.assertRaises(EngineError):self.adapter.helper('snapshot')

    def test_gate_cannot_open_without_durable_commit(self):
        self.adapter.bind(self.command)
        journal=Journal(self.paths,self.state,self.command.request_id,self.command.payload_sha256);journal.append('accepted')
        with self.assertRaises(EngineError):self.adapter.open_gate_and_verify(self.command)

    def test_delivery_history_and_quiet_period_timestamps_are_protected_during_activation(self):
        self.adapter.bind(self.command);self.adapter.close_gate_and_drain(self.command);self.adapter.stop_and_verify_both(self.profile)
        self.adapter.snapshot_matched_state(self.command,self.profile)
        self.adapter.activate_both_paused(self.target,self.profile)
        with sqlite3.connect(self.volume/'keep.sqlite3') as db:
            db.execute('UPDATE notification_dispatches SET created_at=1300')
        with self.assertRaises(EngineError):self.adapter.verify_both_and_protected_data(self.target,self.profile)
        self.assertEqual(self.fake.gate,'closed')

    def test_environment_image_update_preserves_literals_and_rejects_ambiguous_export(self):
        body=b'# comment\r\nSECRET=literal $abc\r\nKEEP_IMAGE=brspoon/keep:2.25.0\r\nTAIL=yes'
        result=env_image(body,self.target)
        self.assertIn(b'SECRET=literal $abc\r\n',result);self.assertTrue(result.endswith(b'TAIL=yes'))
        self.assertIn(('KEEP_IMAGE='+self.target.reference+'\r\n').encode(),result)
        for source in (b'export KEEP_IMAGE=old\n',b'KEEP_IMAGE=one\nKEEP_IMAGE=two\n'):
            with self.assertRaises(EngineError):env_image(source,self.target)

    def test_fresh_helper_reuses_exact_recorded_native_config_bytes_without_registry_calls(self):
        records=ResolverTests().records();self.target=records[0]
        self.fake=FakeDocker(self)
        row=self.fake.images[self.target.image_id]
        row['Id']=self.target.native_digest
        row['Descriptor']={'digest':self.target.native_digest,'mediaType':'application/vnd.oci.image.manifest.v1+json'}
        self.command=verify_request(self.enrollment,signed(self.enrollment,{**request(self.enrollment),
            'expected':self.previous.as_dict(),'target':self.target.as_dict()}),now=1200)
        resolver=OfficialReleaseResolver(ResolverTests().client(records));resolver.resolve(self.target)
        adapter=PosixDockerAdapter(self.paths,self.profile,self.enrollment,runner=self.fake,resolver=resolver)
        adapter.bind(self.command);adapter.image(self.target)
        original=adapter.operation/('release-config-'+self.target.image_id[7:]+'.json')
        self.assertEqual(original.read_bytes(),records[-1])
        class Offline:
            configurations={};configuration_bytes={}
            def resolve(self,target):raise AssertionError('Recovery must use the retained original proof')
        fresh=PosixDockerAdapter(self.paths,self.profile,self.enrollment,runner=self.fake,resolver=Offline())
        fresh.bind(self.command);self.assertEqual(fresh.image(self.target)['Id'],self.target.native_digest)
        self.paths.publish(original,b'corrupt configuration',overwrite=True)
        with self.assertRaises(EngineError):fresh.image(self.target)


class StreamingWorkerTests(DraftFixture):
    def test_process_group_stop_failure_holds_and_reaps_original_child(self):
        original=subprocess.Popen;children=[]
        def spawn(*args,**kwargs):
            child=original(*args,**kwargs);children.append(child);return child
        plan=Plan('synthetic denied group stop',(sys.executable,'-c',
            "import sys,time;sys.stdout.write('x'*1000);sys.stdout.flush();time.sleep(10)"),1,32)
        with patch('host_engine.subprocess.Popen',side_effect=spawn),patch('host_engine.os.killpg',side_effect=PermissionError),self.assertRaisesRegex(EngineError,'process-tree stop is unavailable'):
            BoundedRunner(self.profile).run(plan)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(all(stream.closed for stream in (children[0].stdin,children[0].stdout,children[0].stderr)))

    def test_real_pipe_streaming_upload_publishes_only_complete_verified_snapshot(self):
        volume=self.paths.mkdir(self.root/'upload-volume')
        source=self.state/'snapshot.sqlite3'
        with sqlite3.connect(source) as db:
            db.execute('CREATE TABLE user_profiles (id TEXT,name TEXT)')
            db.execute('INSERT INTO user_profiles VALUES (?,?)',('owner','x'*150000))
        os.chmod(source,0o600)
        from uuid import uuid4
        operation=str(uuid4());content=source.read_bytes()
        command={'operation':'upload','request_id':operation,'attempt_id':None,'expected_sha256':hashlib.sha256(content).hexdigest(),
            'expected_bytes':len(content),'columns':None}
        code='from pathlib import Path;import sys;sys.path.insert(0,sys.argv[2]);import volume_worker;volume_worker.main(Path(sys.argv[1]))'
        plan=Plan('synthetic volume upload',(sys.executable,'-c',code,str(volume),str(Path(volume_worker.__file__).resolve().parent)),5,65536,canonical(command)+b'\n',None,0,source,len(content))
        result=parse_json(BoundedRunner(self.profile).run(plan))
        destination=volume/'.maintenance'/'recovery'/operation/'database.sqlite3'
        self.assertEqual(destination.read_bytes(),content);self.assertEqual(result['bytes'],len(content))
        self.assertEqual(result['fingerprint']['user_profiles']['rows'],1)

    def test_output_artifact_bound_is_checked_even_if_process_exits_before_poll(self):
        destination=self.state/'oversized-artifact'
        plan=Plan('synthetic oversized export',(sys.executable,'-c',"import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b'x'*1024)",str(destination)),5,65536,b'',destination,32)
        with self.assertRaises(EngineError):BoundedRunner(self.profile).run(plan)

    def test_short_snapshot_stream_is_rejected_without_publishing_or_overwriting_data(self):
        volume=self.paths.mkdir(self.root/'short-upload-volume')
        from uuid import uuid4
        operation=str(uuid4())
        command={'operation':'upload','request_id':operation,'attempt_id':None,'expected_sha256':'a'*64,
                 'expected_bytes':1000,'columns':None}
        with self.assertRaises(volume_worker.VolumeError):volume_worker.dispatch(command,volume,upload_stream=io.BytesIO(b'short'))
        self.assertFalse((volume/'.maintenance'/'recovery'/operation/'database.sqlite3').exists())

    def test_volume_space_failure_occurs_before_snapshot_or_restore_publication(self):
        volume=self.paths.mkdir(self.root/'space-limited-volume');database=volume/'keep.sqlite3'
        with sqlite3.connect(database) as db:db.execute('CREATE TABLE user_profiles (id TEXT)')
        os.chmod(database,0o600)
        from uuid import uuid4
        operation=str(uuid4())
        command={'operation':'snapshot','request_id':operation,'attempt_id':None,'expected_sha256':None,'expected_bytes':None,'columns':None}
        with patch.object(volume_worker.shutil,'disk_usage',return_value=type('Space',(),{'free':0})()),self.assertRaises(volume_worker.VolumeError):
            volume_worker.dispatch(command,volume)
        self.assertTrue(database.exists());self.assertFalse((volume/'.maintenance'/'recovery'/operation/'database.sqlite3').exists())


class ResolverTests(unittest.TestCase):
    def records(self):
        target=image('2.26.0','a')
        configuration=canonical({'architecture':'amd64','os':'linux','config':{'User':'10001:10001','Labels':{
            'org.opencontainers.image.version':target.version,'org.opencontainers.image.revision':target.revision,
            'org.opencontainers.image.source':'https://github.com/brspoon/keep'}},
            'rootfs':{'type':'layers','diff_ids':['sha256:'+'9'*64]}})
        target=replace(target,image_id='sha256:'+hashlib.sha256(configuration).hexdigest())
        manifest={'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':{'digest':target.image_id},
            'layers':[{'digest':'sha256:'+'f'*64,'size':100}]}
        manifest_bytes=canonical(manifest);target=replace(target,native_digest='sha256:'+hashlib.sha256(manifest_bytes).hexdigest())
        index={'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','manifests':[
            {'platform':{'os':'linux','architecture':'amd64'},'digest':target.native_digest},
            {'platform':{'os':'linux','architecture':'arm64'},'digest':'sha256:'+'d'*64}]}
        index_bytes=canonical(index);target=replace(target,index_digest='sha256:'+hashlib.sha256(index_bytes).hexdigest())
        release={'id':1,'draft':False,'prerelease':False,'immutable':True,'published_at':'2026-10-12T00:00:00Z',
            'tag_name':target.version,'html_url':'https://github.com/brspoon/keep/releases/tag/'+target.version,
            'assets':[{'name':'keep-'+target.version+'-release-materials.json'}]}
        materials={'version':target.version,'revision':target.revision,'images':{
            'amd64':{'architecture':'amd64','version':target.version,'revision':target.revision,'native_digest':target.native_digest,'config_digest':target.image_id},
            'arm64':{'architecture':'arm64','version':target.version,'revision':target.revision,'native_digest':'sha256:'+'d'*64,'config_digest':'sha256:'+'8'*64}}}
        return target,release,materials,index_bytes,manifest_bytes,configuration

    def client(self,records):
        target,release,materials,index,manifest,configuration=records
        class Client:
            def __init__(self):self.urls=[]
            def get(self,url,headers=None):
                self.urls.append(url)
                if '/releases/tags/' in url or url.endswith('/releases/latest'):return canonical(release),{}
                if '/releases/download/' in url:return canonical(materials),{}
                if 'auth.docker.io' in url:return canonical({'token':'anonymous-synthetic-token'}),{}
                if '/blobs/' in url:return configuration,{}
                if url.endswith(target.native_digest):return manifest,{}
                return index,{'Docker-Content-Digest':target.index_digest}
        return Client()

    def test_official_release_index_native_and_config_are_bound_without_credentials(self):
        records=self.records();client=self.client(records)
        self.assertEqual(OfficialReleaseResolver(client).resolve(records[0]),records[0])
        self.assertEqual(len(client.urls),6)
        self.assertTrue(all(url.startswith('https://') for url in client.urls))
        self.assertIn('repository:brspoon/keep:pull',client.urls[2])

    def test_unfinalized_or_substituted_release_identity_is_rejected(self):
        for field,value in (('draft',True),('immutable',False),('tag_name','2.25.0')):
            records=self.records();records[1][field]=value
            with self.subTest(field=field),self.assertRaises(EngineError):OfficialReleaseResolver(self.client(records)).resolve(records[0])
        records=self.records();records[2]['images']['amd64']['config_digest']='sha256:'+'0'*64
        with self.assertRaises(EngineError):OfficialReleaseResolver(self.client(records)).resolve(records[0])

    def test_transport_rejects_other_schemes_hosts_userinfo_and_ports(self):
        for url in ('http://github.com/brspoon/keep','https://other.example/release','https://user:secret@github.com/x','https://github.com:444/x'):
            with self.subTest(url=url),self.assertRaises(EngineError):HTTPSClient.allowed(url)

    def test_latest_selects_only_newer_numeric_stable_and_verifies_native_configuration_bytes(self):
        records=self.records();resolver=OfficialReleaseResolver(self.client(records))
        self.assertEqual(resolver.latest('amd64','2.25.0'),records[0])
        self.assertEqual(resolver.configurations[records[0].reference]['User'],'10001:10001')
        self.assertIsNone(OfficialReleaseResolver(self.client(records)).latest('amd64','2.26.0'))
        records[1]['tag_name']='2.27.0-beta.1'
        with self.assertRaises(EngineError):OfficialReleaseResolver(self.client(records)).latest('amd64','2.25.0')

    def test_native_config_blob_substitution_is_rejected_even_with_matching_labels(self):
        records=list(self.records());configuration=parse_json(records[-1])
        configuration['rootfs']['diff_ids']=['sha256:'+'0'*64]
        records[-1]=canonical(configuration)
        with self.assertRaises(EngineError):OfficialReleaseResolver(self.client(records)).resolve(records[0])


if __name__=='__main__':unittest.main()
