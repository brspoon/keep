"""Offline end-to-end real controller, host engine, adapter and recovery proof.

Only Docker command transport and registry byte authority are synthetic. Signed
messages, SQLite/control state, journal, configuration and volume worker are real.
"""
from dataclasses import replace
import copy
import sqlite3
import time
import unittest
import uuid

import test_docker_adapter as fixtures
from docker_adapter import PosixDockerAdapter, create_docker_adapter
from host_engine import EngineError, HostEngine
from host_mailbox import HostMailbox
from maintenance_app import Authority, Controller, Hooks, MaintenanceError, Store, dispatch
from maintenance_protocol import canonical, parse_json, signed, verify
from private_store import Journal


class FixtureResolver:
    def __init__(self,fixture,runner):
        self.f,self.runner=fixture,runner;self.calls=[];self.configurations={}

    def resolve(self,identity):
        self.calls.append(identity)
        if identity not in (self.f.previous,self.f.target):raise EngineError('Synthetic release substitution')
        record=self.runner.images[identity.image_id]
        self.configurations[identity.reference]={field:record[field] for field in ('RootFS','User','Labels')}
        return identity

    def resolve_version(self,version,architecture):
        identity=next((value for value in (self.f.previous,self.f.target) if value.version==version and value.architecture==architecture),None)
        if identity is None:raise EngineError('Synthetic missing release')
        return self.resolve(identity)


class AppDocker(fixtures.FakeDocker):
    def __init__(self,fixture):
        super().__init__(fixture)
        self.controller=None;self.events=[];self.native=False;self.lose_enroll=False;self.lose_final=False;self.lose_final_before=False
        self.lose_previous_reference_on_load=False;self.previous_reference_missing=False

    def run(self,plan):
        args=list(plan.argv[3:])
        if args[0]=='image' and args[1]=='load' and self.lose_previous_reference_on_load:
            self.previous_reference_missing=True
        if args[0]=='image' and args[1]=='inspect' and self.previous_reference_missing and args[-1]==self.f.previous.reference:
            raise EngineError('Synthetic prior index loaded with a dangling name only')
        if args[0]=='exec' and '/app/maintenance_mailbox.py' in args:
            verb=args[-1]
            if self.lose_final_before and verb=='status':
                body=verify(self.f.enrollment,plan.stdin)
                if 'progress' in body and verify(self.f.enrollment,canonical(body['progress']))['phase'] in ('success','recovered'):
                    self.lose_final_before=False;raise EngineError('Synthetic final mirror unavailable before receipt')
            try:result=dispatch(self.controller,verb,plan.stdin)
            except (MaintenanceError,ValueError) as error:raise EngineError('Synthetic app rejected command') from error
            if verb=='status' and plan.stdin:
                command=verify(self.f.enrollment,plan.stdin)
                if 'progress' in command:
                    phase=verify(self.f.enrollment,canonical(command['progress']))['phase']
                    self.events.append(('mirror',phase))
                    if self.lose_final and phase in ('success','recovered'):
                        self.lose_final=False;raise EngineError('Synthetic lost final reply')
            self.events.append(('verb',verb))
            if verb=='enroll' and self.lose_enroll:
                self.lose_enroll=False;raise EngineError('Synthetic lost enrollment reply')
            if verb=='complete' and self.lost_complete:
                self.lost_complete=False;raise EngineError('Synthetic lost completion reply')
            return result
        if args[0]=='image' and args[1]=='inspect' and self.native:
            reference=args[-1]
            identity=next((value for value in (self.f.previous,self.f.target)
                if reference in (value.image_id,value.index_digest,value.native_digest,value.reference)),None)
            if identity is None:raise EngineError('Synthetic image not found')
            record=copy.deepcopy(self.images[identity.image_id])
            record['Id']=identity.native_digest
            record['Descriptor']={'digest':identity.native_digest,'mediaType':'application/vnd.oci.image.manifest.v1+json'}
            return canonical(record)
        try:return super().run(plan)
        finally:
            if self.native and args[0] in ('compose','create'):
                # A lost/error CLI result does not undo daemon-side effects.
                for row in (*self.containers.values(),*self.helpers.values()):
                    identity=next((value for value in (self.f.previous,self.f.target)
                        if row['Image'] in (value.image_id,value.index_digest)),None)
                    if identity:
                        row['Image']=identity.index_digest
                        row['Manifest']={'digest':identity.native_digest,'mediaType':'application/vnd.oci.image.manifest.v1+json'}


class MailboxTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.AdapterTests(methodName='test_gate_cannot_open_without_durable_commit')
        self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.runner=AppDocker(self.f);self.resolver=FixtureResolver(self.f,self.runner)
        self.generation='e'*64
        def authority():
            with sqlite3.connect(self.f.volume/'keep.sqlite3') as db:
                row=db.execute("SELECT status,session_version FROM user_profiles WHERE plex_id='local-owner'").fetchone()
            return Authority('local-owner',row[1],row[0]=='active')
        def version():
            return self.runner.containers['keep-app']['Source'].endswith(self.f.target.index_digest) and self.f.target.version or self.f.previous.version
        # The qualified application initializes control state at startup before
        # its local enrollment mailbox becomes available.
        store=Store(root=self.f.volume/'.maintenance',paths=self.f.paths)
        store.initialize()
        self.controller=Controller(store,
            Hooks(authority,lambda:self.generation,version,lambda:True))
        self.runner.controller=self.controller
        self.mailbox=HostMailbox(self.f.paths,self.f.profile,runner=self.runner,resolver=self.resolver)
        self.user={'id':'local-owner','session_version':3}

    def enroll(self):
        observed=self.mailbox.probe()
        confirmed=self.mailbox.enroll(self.f.enrollment,observed)
        self.assertTrue(confirmed.hello['enrolled'])
        return confirmed

    def queued(self):
        self.enroll();self.mailbox.advisory(self.f.target)
        snapshot=self.controller.snapshot(user=self.user)
        request_id=str(uuid.uuid4())
        self.controller.enqueue({'request_id':request_id,'operation':'install','confirmation':snapshot['confirmation']},user=self.user)
        request=self.mailbox.poll();self.f.command=request
        return request

    def engine(self):
        return HostEngine(self.f.paths,self.f.profile,create_docker_adapter(self.f.paths,self.f.profile,
            self.f.enrollment,mailbox=self.mailbox))

    def test_real_enrollment_challenge_and_original_request_bytes(self):
        request=self.queued()
        self.assertEqual(self.mailbox.request_envelope(request),self.controller.pending_request())
        self.assertEqual(self.mailbox.accepted_request(self.mailbox.request_envelope(request)),request)
        self.assertEqual(request.expected,self.f.previous)
        self.assertEqual(request.target,self.f.target)

    def test_lost_enrollment_reply_reconciles_same_key_without_replacing_state(self):
        observation=self.mailbox.probe();self.runner.lose_enroll=True
        with self.assertRaises(EngineError):self.mailbox.enroll(self.f.enrollment,observation)
        key=(self.f.volume/'.maintenance'/'key-1.json').read_bytes()
        self.assertTrue(self.mailbox.enroll(self.f.enrollment,observation).hello['enrolled'])
        self.assertEqual((self.f.volume/'.maintenance'/'key-1.json').read_bytes(),key)

    def test_private_key_published_before_enrollment_transaction_can_reconcile(self):
        observation=self.mailbox.probe();self.enroll()
        key=(self.f.volume/'.maintenance'/'key-1.json').read_bytes()
        # Simulate a key publication that survived before the SQLite row commit.
        with self.controller.store._connect() as db:db.execute('DELETE FROM enrollment')
        self.assertTrue(self.mailbox.enroll(self.f.enrollment,observation).hello['enrolled'])
        self.assertEqual((self.f.volume/'.maintenance'/'key-1.json').read_bytes(),key)

    def test_local_signed_queue_uses_saved_target_fresh_owner_and_original_uuid(self):
        self.enroll();self.mailbox.advisory(self.f.target)
        with sqlite3.connect(self.f.volume/'keep.sqlite3') as db:
            db.execute("UPDATE user_profiles SET session_version=4 WHERE plex_id='local-owner'")
        request_id=str(uuid.uuid4())
        reply=self.mailbox.queue(request_id=request_id);self.assertEqual(reply['state'],'queued')
        request=self.mailbox.poll();original=self.mailbox.request_envelope(request)
        self.assertEqual(request.request_id,request_id);self.assertEqual(request.credential_version,4)
        self.assertEqual(request.target,self.f.target)
        self.assertEqual(self.mailbox.queue(request_id=request_id)['request_id'],request_id)
        self.assertEqual(self.controller.pending_request(),original)
        with self.assertRaises(EngineError):self.mailbox.queue(request_id=str(uuid.uuid4()))
        self.assertEqual(self.controller.pending_request(),original)

    def test_local_queue_rejects_arbitrary_target_foreign_key_and_inactive_owner(self):
        self.enroll();self.mailbox.advisory(self.f.target)
        body={'protocol':'keep.host-queue.v1','install_id':self.f.enrollment.install_id,
            'epoch':self.f.enrollment.epoch,'request_id':str(uuid.uuid4()),'operation':'install','image':'other/image:latest'}
        with self.assertRaises(Exception):dispatch(self.controller,'queue',signed(self.f.enrollment,body))
        body.pop('image');foreign=replace(self.f.enrollment,key=b'x'*32)
        with self.assertRaises(Exception):dispatch(self.controller,'queue',signed(foreign,body))
        with sqlite3.connect(self.f.volume/'keep.sqlite3') as db:db.execute("UPDATE user_profiles SET status='blocked'")
        with self.assertRaises(EngineError):self.mailbox.queue(request_id=body['request_id'])
        self.assertIsNone(self.controller.pending_request())

    def test_release_proof_cached_but_changed_source_and_configuration_rejected(self):
        self.enroll();before=len(self.resolver.calls)
        for _ in range(3):self.mailbox.probe();self.mailbox.advisory(self.f.target)
        self.assertEqual(len(self.resolver.calls),before+1)
        self.runner.containers['keep-app']['Source']='unrelated/image:2.25.0'
        with self.assertRaises(EngineError):self.mailbox.probe()
        self.runner.containers['keep-app']['Source']='brspoon/keep:'+self.f.previous.version
        self.f.paths.publish(self.f.install/'.env',b'changed=external\n',overwrite=True)
        with self.assertRaises(EngineError):self.mailbox.probe()

    def test_real_success_mirrors_commit_before_open_and_final_before_reuse(self):
        request=self.queued();result=self.engine().execute(request)
        self.assertEqual(result['phase'],'success')
        self.assertLess(self.runner.events.index(('mirror','committed')),self.runner.events.index(('verb','complete')))
        snapshot=self.controller.snapshot(user=self.user,request_id=request.request_id)
        self.assertEqual(snapshot['request_state'],'completed');self.assertEqual(snapshot['operation']['phase'],'success')
        self.assertTrue(snapshot['can_restart'])
        with sqlite3.connect(self.f.volume/'keep.sqlite3') as db:
            self.assertEqual(db.execute('SELECT media_id FROM keep_schedules').fetchall(),[('42',)])

    def test_real_matching_rollback_only_before_commit(self):
        request=self.queued();self.runner.fail_candidate=True
        with self.assertRaises(EngineError):self.engine().execute(request)
        snapshot=self.controller.snapshot(user=self.user,request_id=request.request_id)
        self.assertEqual(snapshot['operation']['phase'],'recovered')
        self.assertEqual(snapshot['installed_version'],self.f.previous.version)
        self.assertLess(self.runner.events.index(('mirror','recovery-committed')),self.runner.events.index(('verb','complete')))
        self.assertTrue(snapshot['can_restart'])

    def test_lost_complete_reconnect_preserves_new_rows_connection_generation_and_session(self):
        request=self.queued();self.runner.lost_complete=True
        with self.assertRaises(EngineError):self.engine().execute(request)
        before=len([plan for plan in self.runner.plans if plan.argv[3] in ('create','compose')])
        self.generation='f'*64
        with sqlite3.connect(self.f.volume/'keep.sqlite3') as db:
            db.execute("INSERT INTO keep_schedules VALUES ('1','99',NULL)")
            db.execute("UPDATE user_profiles SET session_version=4 WHERE plex_id='local-owner'")
        self.user['session_version']=4
        self.assertEqual(self.engine().resume(request)['phase'],'success')
        self.assertEqual(len([plan for plan in self.runner.plans if plan.argv[3] in ('create','compose')]),before)
        with sqlite3.connect(self.f.volume/'keep.sqlite3') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM keep_schedules').fetchone()[0],2)
        self.assertTrue(self.controller.snapshot(user=self.user)['can_restart'])

    def test_lost_final_mirror_reply_only_republishes_durable_terminal_record(self):
        request=self.queued();self.runner.lose_final=True
        with self.assertRaises(EngineError):self.engine().execute(request)
        self.assertEqual(Journal(self.f.paths,self.f.state,request.request_id,request.payload_sha256).records()[-1]['phase'],'success')
        before=len(self.runner.plans)
        self.assertEqual(self.engine().resume(request)['phase'],'success')
        self.assertFalse(any(plan.argv[3] in ('create','compose','pull') for plan in self.runner.plans[before:]))

    def test_missing_final_mirror_holds_reuse_until_exact_terminal_publication(self):
        request=self.queued();self.runner.lose_final_before=True
        with self.assertRaises(EngineError):self.engine().execute(request)
        snapshot=self.controller.snapshot(user=self.user,request_id=request.request_id)
        self.assertEqual(snapshot['operation']['phase'],'committed')
        self.assertFalse(snapshot['can_restart']);self.assertFalse(snapshot['can_install'])
        receipt=parse_json((self.f.state/'operations'/request.request_id/'app-progress-receipt.json').read_bytes())
        self.assertEqual(receipt['phase'],'committed')
        self.assertEqual(self.engine().resume(request)['phase'],'success')
        receipt=parse_json((self.f.state/'operations'/request.request_id/'app-progress-receipt.json').read_bytes())
        self.assertEqual(receipt['phase'],'success')
        self.assertTrue(self.controller.snapshot(user=self.user)['can_restart'])

    def test_recovery_commit_reconnect_preserves_later_user_rows_and_generation(self):
        request=self.queued();self.runner.fail_candidate=True;self.runner.lost_complete=True
        with self.assertRaises(EngineError):self.engine().execute(request)
        self.generation='f'*64
        with sqlite3.connect(self.f.volume/'keep.sqlite3') as db:db.execute("INSERT INTO keep_schedules VALUES ('1','100',NULL)")
        self.assertEqual(self.engine().resume(request)['phase'],'recovered')
        with sqlite3.connect(self.f.volume/'keep.sqlite3') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM keep_schedules').fetchone()[0],2)
        self.assertEqual(self.controller.snapshot(user=self.user)['installed_version'],self.f.previous.version)

    def test_local_restart_preserves_image_without_release_pull_or_install(self):
        self.enroll();self.mailbox.advisory()
        self.mailbox.queue('restart',request_id=str(uuid.uuid4()))
        request=self.mailbox.poll();self.f.command=request
        self.resolver.calls.clear();self.runner.plans.clear()
        self.assertEqual(self.engine().execute(request)['phase'],'success')
        self.assertFalse(self.resolver.calls)
        self.assertFalse(any(plan.argv[3]=='pull' for plan in self.runner.plans))
        self.assertEqual({row['Image'] for row in self.runner.containers.values()},{self.f.previous.image_id})

    def test_configuration_generation_drift_before_claim_never_cuts_over(self):
        request=self.queued();self.generation='f'*64
        with self.assertRaises(EngineError):self.engine().execute(request)
        self.assertFalse(any(plan.argv[3]=='compose' for plan in self.runner.plans))
        self.assertEqual(self.controller.snapshot(user=self.user,request_id=request.request_id)['request_state'],'aborted')

    def test_containerd_index_native_config_bindings_and_poisoned_native_rejected(self):
        self.runner.native=True
        for row in self.runner.containers.values():
            row['Image']=self.f.previous.index_digest
            row['Manifest']={'digest':self.f.previous.native_digest,'mediaType':'application/vnd.oci.image.manifest.v1+json'}
        request=self.queued();self.assertEqual(self.engine().execute(request)['phase'],'success')
        self.assertEqual({row['Image'] for row in self.runner.containers.values()},{self.f.target.index_digest})
        self.mailbox.probe()
        self.runner.containers['keep-app']['Manifest']['digest']='sha256:'+'0'*64
        with self.assertRaises(EngineError):self.mailbox.probe()

    def test_complete_real_class_recovery_with_containerd_oci_gzip_archive(self):
        from test_recovery_oci import OCIArchiveTests
        archive=OCIArchiveTests(methodName='test_original_index_native_config_compressed_blob_and_uncompressed_diff_are_verified')
        archive.setUp();self.addCleanup(archive.doCleanups)
        previous,members=archive.fixture();self.f.previous=previous
        self.f.tar_bytes=archive.archive(members).read_bytes()
        self.runner=AppDocker(self.f);self.runner.native=True;self.runner.controller=self.controller
        self.runner.lose_previous_reference_on_load=True
        configuration=parse_json(members['blobs/sha256/'+previous.image_id[7:]])
        self.runner.images[previous.image_id]['RootFS']=configuration['rootfs']['diff_ids']
        for row in self.runner.containers.values():
            row['Image']=previous.index_digest
            row['Manifest']={'digest':previous.native_digest,'mediaType':'application/vnd.oci.image.manifest.v1+json'}
        self.resolver=FixtureResolver(self.f,self.runner)
        self.mailbox=HostMailbox(self.f.paths,self.f.profile,runner=self.runner,resolver=self.resolver)
        request=self.queued();self.runner.fail_candidate=True
        with self.assertRaises(EngineError) as caught:self.engine().execute(request)
        self.assertEqual(self.controller.snapshot(user=self.user,request_id=request.request_id)['operation']['phase'],'recovered',
            repr(caught.exception)+' '+repr(caught.exception.__cause__))
        self.assertEqual({row['Image'] for row in self.runner.containers.values()},{previous.index_digest})
        self.assertEqual({row['Source'] for row in self.runner.containers.values()},{previous.index_digest})
        self.assertFalse(any(plan.argv[3]=='image' and 'tag' in plan.argv for plan in self.runner.plans))
        with sqlite3.connect(self.f.volume/'keep.sqlite3') as db:
            self.assertEqual(db.execute('SELECT media_id FROM keep_schedules').fetchall(),[('42',)])
            self.assertNotIn('migration_marker',{row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")})


if __name__=='__main__':unittest.main()
