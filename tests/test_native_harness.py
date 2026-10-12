"""Offline graph/source tests. Never execute Docker or contact a registry."""
import hashlib
import importlib.util
import os
import json
import io
from pathlib import Path
import tempfile
import tarfile
import sqlite3
import sys
from contextlib import contextmanager
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parent/'maintenance_container_trial.py'
if not SCRIPT.is_file():
    SCRIPT = Path(__file__).resolve().parents[1]/'scripts/maintenance_container_trial.py'
spec = importlib.util.spec_from_file_location('keep_native_trial_runner',SCRIPT)
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)
import maintenance_trial_fixture as fixture
from maintenance_protocol import canonical
from maintenance_protocol import signed
from private_store import create_private_paths
from helper_bundle import create_root


class Graph(trial.RegistryGraph):
    def __init__(self):
        super().__init__(12345, 'amd64')
        self.data={}
        config=canonical({'architecture':'amd64','os':'linux','config':{'User':'10001:10001','Labels':{
            'org.opencontainers.image.version':'0.0.1','org.opencontainers.image.revision':'a'*40,
            'org.opencontainers.image.source':'https://github.com/brspoon/keep'}},
            'rootfs':{'type':'layers','diff_ids':['sha256:'+'c'*64]}})
        config_digest='sha256:'+hashlib.sha256(config).hexdigest()
        manifest=canonical({'schemaVersion':2,'mediaType':trial.MANIFEST,
            'config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':config_digest,'size':len(config)},'layers':[]})
        native='sha256:'+hashlib.sha256(manifest).hexdigest()
        self.data['/v2/brspoon/keep/blobs/'+config_digest]=(config,config_digest)
        self.data['/v2/brspoon/keep/manifests/'+native]=(manifest,native)
        self.data['/v2/brspoon/keep/manifests/native-1']=(manifest,native)
    def request(self,method,path,data=None,content_type=None):
        if method=='PUT':
            digest='sha256:'+hashlib.sha256(data).hexdigest()
            self.data['/v2/brspoon/keep/manifests/'+digest]=(data,digest)
            return b'',digest
        return self.data[path]


class GraphTests(unittest.TestCase):
    def test_actual_index_native_and_config_bytes_define_fixture_identity(self):
        graph=Graph();image=graph.register('native-1','0.0.1','a'*40)
        self.assertEqual(graph.resolve(image),image)
        self.assertEqual(graph.resolve_version('0.0.1','amd64'),image)
        self.assertEqual(hashlib.sha256(graph.configuration_bytes[image.reference]).hexdigest(),image.image_id[7:])
        self.assertEqual(graph.configurations[image.reference]['User'],'10001:10001')
        with self.assertRaises(trial.TrialError):graph.resolve_version('0.0.1','arm64')
        with self.assertRaises(trial.TrialError):graph.latest('amd64','0.0.1')
    def test_changed_content_or_descriptor_cannot_qualify(self):
        graph=Graph();image=graph.register('native-1','0.0.1','a'*40)
        path='/v2/brspoon/keep/blobs/'+image.image_id
        graph.data[path]=(b'changed',image.image_id)
        with self.assertRaises(trial.TrialError):graph.resolve(image)
    def test_unscoped_http_and_invalid_port_fail_before_network(self):
        graph=trial.RegistryGraph(12345,'amd64')
        with patch('http.client.HTTPConnection') as connect:
            with self.assertRaises(trial.TrialError):graph.request('GET','/v2/other/app/manifests/tag')
            connect.assert_not_called()
        for value in (True,0,65536,'1234'):
            with self.assertRaises(trial.TrialError):trial.RegistryGraph(value,'amd64')


class PackagingTests(unittest.TestCase):
    def test_fixed_root_and_isolated_module_layouts_resolve_without_user_paths(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            root=Path(temporary).resolve();scripts=root/'scripts';scripts.mkdir()
            self.assertEqual(trial.helper_source(scripts/'maintenance_container_trial.py'),root)
            (scripts/'docker_adapter.py').write_text('# isolated draft')
            self.assertEqual(trial.helper_source(scripts/'maintenance_container_trial.py'),scripts)
            packaged=scripts/'maintenance_host';packaged.mkdir()
            self.assertEqual(trial.helper_source(scripts/'maintenance_container_trial.py'),packaged)
            self.assertEqual(trial.neutral_source(scripts/'maintenance_container_trial.py'),root)
    def test_actual_neutral_module_bytes_and_ui_paths_are_staged_without_symlinks(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temp:
            root=Path(temp).resolve();paths=create_private_paths();private=create_root(paths,root/'private')
            integration=paths.mkdir(private/'integration');source=paths.mkdir(private/'source');tests=paths.mkdir(source/'tests')
            for name in ('app.py','onboarding.py'):paths.publish(integration/name,b'# fixture app\n')
            templates=paths.mkdir(integration/'templates');assets=paths.mkdir(integration/'static')
            paths.publish(templates/'about_maintenance.html',b'<div>fixture</div>')
            paths.publish(assets/'keep-maintenance.js',b'// fixture\n')
            paths.publish(tests/'portable_trial.py',b'# seed fixture\n')
            paths.publish(tests/'maintenance_trial_fixture.py',Path(fixture.__file__).read_bytes())
            value=trial.NativeTrial.__new__(trial.NativeTrial)
            value.paths,value.root,value.integration,value.source=paths,private,integration,source
            value.report={'source_files':{}}
            original_shim=(trial.NEUTRAL_SOURCE/'maintenance_mailbox.py').read_bytes()
            base={'Id':'sha256:'+'b'*64,'fixture_reference':'keep-native:source','Config':{'Labels':{'org.opencontainers.image.revision':'a'*40}}}
            with patch('subprocess.run') as process:
                staged=value.stage_source(base)
                process.assert_not_called()
            self.assertIn('COPY --chown=10001:10001 templates/about_maintenance.html /app/templates/about_maintenance.html', (staged/'Dockerfile').read_text())
            self.assertTrue((staged/'Dockerfile').read_text().startswith('FROM keep-native:source\n'))
            self.assertFalse((staged/'maintenance_app.py').is_symlink())
            self.assertEqual((staged/'maintenance_app.py').read_bytes(), (trial.NEUTRAL_SOURCE/'maintenance_app.py').read_bytes())
            self.assertIn(b'RUNTIME_QUALIFIED = True',(staged/'maintenance_mailbox.py').read_bytes())
            self.assertEqual(value.report['source_files']['maintenance_mailbox.py']['source_sha256']==value.report['source_files']['maintenance_mailbox.py']['fixture_sha256'],
                b'RUNTIME_QUALIFIED = True' in original_shim)
            self.assertEqual((trial.NEUTRAL_SOURCE/'maintenance_mailbox.py').read_bytes(),original_shim)

    def test_host_only_package_does_not_supply_neutral_app_source(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temp:
            root=Path(temp).resolve();paths=create_private_paths();private=create_root(paths,root/'private')
            repository=paths.mkdir(private/'repository');scripts=paths.mkdir(repository/'scripts')
            host=paths.mkdir(scripts/'maintenance_host');tests=paths.mkdir(repository/'tests')
            for name in ('app.py','onboarding.py'):paths.publish(repository/name,b'# app source\n')
            for name in ('maintenance_app.py','maintenance_mailbox.py','maintenance_protocol.py','private_store.py'):
                body=(trial.NEUTRAL_SOURCE/name).read_bytes()
                if name=='maintenance_mailbox.py':body=body.replace(b'RUNTIME_QUALIFIED = False',b'RUNTIME_QUALIFIED = True')
                paths.publish(repository/name,body)
            paths.publish(host/'docker_adapter.py',b'# host-only source\n')
            paths.publish(host/'private_store.py',b'# host-only duplicate must not replace app bytes\n')
            paths.publish(tests/'portable_trial.py',b'# portable fixture\n')
            paths.publish(tests/'maintenance_trial_fixture.py',Path(fixture.__file__).read_bytes())
            value=trial.NativeTrial.__new__(trial.NativeTrial)
            value.paths,value.root,value.integration,value.source=paths,private,repository,repository
            value.report={'source_files':{}}
            helper=trial.helper_source(scripts/'maintenance_container_trial.py')
            neutral=trial.neutral_source(scripts/'maintenance_container_trial.py')
            with patch.object(trial,'DRAFT',helper),patch.object(trial,'NEUTRAL_SOURCE',neutral):
                staged=value.stage_source({'fixture_reference':'keep-owned:source','Config':{'Labels':{'org.opencontainers.image.revision':'a'*40}}})
            self.assertEqual((staged/'private_store.py').read_bytes(),(repository/'private_store.py').read_bytes())
            self.assertNotEqual((staged/'private_store.py').read_bytes(),(host/'private_store.py').read_bytes())
            self.assertTrue((staged/'maintenance_mailbox.py').is_file())
            self.assertEqual(value.report['source_files']['maintenance_mailbox.py']['source_sha256'],
                value.report['source_files']['maintenance_mailbox.py']['fixture_sha256'])


class CandidateTests(unittest.TestCase):
    def test_classic_and_containerd_exports_identify_the_same_canonical_config(self):
        config={'architecture':'amd64','os':'linux','config':{'User':'10001:10001','Labels':{'org.opencontainers.image.version':'2.26.0'}}}
        raw=canonical(config);digest='sha256:'+hashlib.sha256(raw).hexdigest()
        manifest=canonical({'schemaVersion':2,'mediaType':trial.MANIFEST,
            'config':{'digest':digest,'size':len(raw)}})
        native='sha256:'+hashlib.sha256(manifest).hexdigest()
        index=canonical({'schemaVersion':2,'mediaType':trial.INDEX,'manifests':[{'mediaType':trial.MANIFEST,
            'digest':native,'size':len(manifest),'platform':{'os':'linux','architecture':'amd64'}}]})
        indexed='sha256:'+hashlib.sha256(index).hexdigest()
        classic={'manifest.json':canonical([{'Config':digest[7:]+'.json','Layers':[],'RepoTags':['keep-ci:latest']}]),digest[7:]+'.json':raw}
        oci={'oci-layout':canonical({'imageLayoutVersion':'1.0.0'}),
            'index.json':canonical({'schemaVersion':2,'manifests':[{'digest':indexed,'size':len(index)}]}),
            'blobs/sha256/'+indexed[7:]:index,'blobs/sha256/'+native[7:]:manifest,'blobs/sha256/'+digest[7:]:raw}
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temp:
            archive=Path(temp).resolve()/'candidate.tar'
            for identifier,members in ((digest,classic),(indexed,oci)):
                with tarfile.open(archive,'w') as package:
                    for name,data in members.items():
                        member=tarfile.TarInfo(name);member.size=len(data);package.addfile(member,io.BytesIO(data))
                inspected={'Id':identifier,'Architecture':'amd64','Config':config['config']}
                self.assertEqual(trial.candidate_configuration(archive,inspected),digest)
                with self.assertRaises(trial.TrialError):trial.candidate_configuration(archive,{**inspected,'Architecture':'arm64'})


class FreshProcessTests(unittest.TestCase):
    def test_fixed_child_dispatch_and_network_free_recovery_boundary(self):
        identifier='12345678-1234-4234-8234-123456789abc'
        with patch.object(trial,'child_helper',return_value=0) as child:
            self.assertEqual(trial.main(['--child-resume',identifier,'--state','/private/tmp/fixture']),0)
        child.assert_called_once_with(Path('/private/tmp/fixture'),identifier,crash=False)
        with self.assertRaises(trial.TrialError):trial.NoNetworkResolver().resolve(None)
        with self.assertRaises(trial.TrialError):trial.NoNetworkResolver().resolve_version('0.0.1','amd64')

    def test_child_reconstructs_original_key_profile_and_signed_request_before_resume(self):
        from test_host_cli import CliTests
        fixture=CliTests();fixture.setUp();self.addCleanup(fixture.doCleanups);fixture.enroll()
        state=trial.HostState(fixture.paths,fixture.state)
        profile,enrollment=state.credentials(state.active()[1])
        self.assertEqual(profile.docker_executable.parent,fixture.root)
        if os.name=='posix':
            self.assertEqual(profile.docker_executable.stat().st_mode&0o777,0o500)
        identifier='12345678-1234-4234-8234-123456789abc'
        body={'protocol':'keep.maintenance.v1','install_id':enrollment.install_id,'owner_id':enrollment.owner_id,
            'epoch':enrollment.epoch,'request_id':identifier,'operation':'restart','credential_version':0,
            'issued_at':1000,'expires_at':1300,'nonce':'1'*64,'expected':fixture.image.as_dict(),'target':None}
        accepted=fixture.paths.mkdir(fixture.state/'accepted-requests')
        fixture.paths.publish(accepted/(identifier+'.json'),signed(enrollment,body))
        with patch.object(trial,'PosixDockerAdapter') as adapter,patch.object(trial,'HostEngine') as engine:
            engine.return_value.resume.return_value={'phase':'success','sequence':9}
            self.assertEqual(trial.child_helper(fixture.state,identifier),0)
            request=engine.return_value.resume.call_args.args[0]
            self.assertEqual(request.request_id,identifier);self.assertEqual(request.expected,fixture.image)
            self.assertEqual(adapter.call_args.args[1],profile);self.assertEqual(adapter.call_args.args[2],enrollment)
            self.assertIsInstance(adapter.call_args.kwargs['resolver'],trial.NoNetworkResolver)
            engine.return_value.execute.assert_not_called()
        receipt=json.loads((fixture.state/('trial-resumed-'+identifier+'.json')).read_bytes())
        self.assertEqual(receipt['request_id'],identifier);self.assertFalse(receipt['network_resolution'])


class ControlledWriterTests(unittest.TestCase):
    def test_gate_observer_and_release_do_not_import_application_or_acquire_work(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temp:
            data=Path(temp).resolve();control=data/'.maintenance';control.mkdir()
            with sqlite3.connect(control/'control.sqlite3') as db:
                db.execute('CREATE TABLE gate (id INTEGER,closed INTEGER,drained INTEGER,request_id TEXT)')
                db.execute("INSERT INTO gate VALUES (1,1,0,'request')")
            with sqlite3.connect(data/'keep.sqlite3') as db:
                db.execute('CREATE TABLE user_feature_acknowledgements (feature_key TEXT,version TEXT)')
            (data/'maintenance-trial-lease').write_text('held')
            output=io.StringIO()
            with patch.object(fixture,'DATA',data),patch.object(fixture,'application',side_effect=AssertionError('Observer imported app')), \
                    patch.object(sys,'argv',['fixture','gate']),patch('sys.stdout',output):fixture.main()
            self.assertEqual(json.loads(output.getvalue()),{'closed':True,'drained':False,'request_id':'request',
                'writer_ready':True,'writer_done':None,'drain_writes':[]})
            with patch.object(fixture,'DATA',data),patch.object(fixture,'application',side_effect=AssertionError('Release imported app')), \
                    patch.object(sys,'argv',['fixture','release','request']):fixture.main()
            self.assertEqual((data/'maintenance-trial-release').read_text(),'request')
            if os.name=='posix':self.assertEqual((data/'maintenance-trial-release').stat().st_mode&0o777,0o600)

    def test_final_protected_sqlite_write_commits_before_held_work_lease_exits(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temp:
            data=Path(temp).resolve();database=data/'keep.sqlite3'
            with sqlite3.connect(database) as db:
                db.execute('CREATE TABLE user_feature_acknowledgements (user_id TEXT,feature_key TEXT,version TEXT,acknowledged_at TEXT)')
            held=[];identifier='12345678-1234-4234-8234-123456789abc'
            @contextmanager
            def lease():
                held.append(True)
                try:yield
                finally:
                    with sqlite3.connect(database) as db:
                        self.assertEqual(db.execute('SELECT version FROM user_feature_acknowledgements').fetchone(),(identifier,))
                    self.assertEqual((data/'maintenance-trial-done').read_text(),identifier)
                    held.pop()
            app=SimpleNamespace(KEEP_DB_PATH=str(database),maintenance_store=SimpleNamespace(work=lease))
            def release_after_ready(_):
                self.assertEqual(held,[True]);self.assertEqual((data/'maintenance-trial-lease').read_text(),identifier)
                fixture.publish_marker('maintenance-trial-release',identifier)
            with patch.object(fixture,'DATA',data),patch.object(fixture,'application',return_value=app), \
                    patch.object(fixture.time,'sleep',side_effect=release_after_ready),patch.object(sys,'argv',['fixture','hold',identifier]):fixture.main()
            self.assertEqual(held,[]);self.assertFalse((data/'maintenance-trial-lease').exists())


class ToolIdentityTests(unittest.TestCase):
    def test_classic_familiar_digest_and_explicit_native_descriptor_are_bound(self):
        for tool in trial.TOOLING:
            base={'Architecture':'amd64','Os':'linux','Id':'sha256:'+'a'*64}
            familiar=tool['repository'].removeprefix('library/')
            for name in (familiar,tool['repository'],'docker.io/'+tool['repository']):
                self.assertTrue(trial.pinned_tool_identity({**base,'RepoDigests':[name+'@'+tool['index_digest']]},tool,'amd64'))
            self.assertFalse(trial.pinned_tool_identity({**base,'RepoDigests':['other/'+familiar+'@'+tool['index_digest']]},tool,'amd64'))
            self.assertFalse(trial.pinned_tool_identity({**base,'RepoDigests':[familiar+'@sha256:'+'b'*64]},tool,'amd64'))
            native=tool['native']['amd64']
            selected={**base,'Id':native,'Descriptor':{'digest':native,'mediaType':trial.MANIFEST}}
            self.assertTrue(trial.pinned_tool_identity(selected,tool,'amd64'))
            selected['Descriptor']['digest']='sha256:'+'b'*64
            self.assertFalse(trial.pinned_tool_identity(selected,tool,'amd64'))


class CleanupTests(unittest.TestCase):
    def test_unlabeled_foreign_container_before_enrollment_holds_all_cleanup_untouched(self):
        value=trial.NativeTrial.__new__(trial.NativeTrial)
        value.profile=SimpleNamespace(volume='trial_keep-data')
        value.name='trial';value.report={'cleanup':{}};value.images_by_schema={}
        identifier='f'*64
        def inner(*args,**kwargs):
            if args[0]=='ps':return (identifier+'\n').encode()
            if args[0]=='inspect':return json.dumps([{'Id':identifier,'Config':{'Labels':None},'State':{'Running':True}}]).encode()
            raise AssertionError('Unexpected mutation or lookup')
        value.inner=Mock(side_effect=inner);value.outer=Mock()
        with self.assertRaisesRegex(trial.TrialError,'Unexpected isolated daemon container'):
            value.cleanup()
        self.assertEqual([call.args[0] for call in value.inner.call_args_list],['ps','inspect'])
        value.outer.assert_not_called()

    def test_foreign_container_after_owned_services_is_rejected_before_any_stop(self):
        value=trial.NativeTrial.__new__(trial.NativeTrial)
        value.profile=SimpleNamespace(volume='trial_keep-data');value.paths=Mock();value.resolver=Mock()
        value.name='trial';value.report={'cleanup':{}};value.images_by_schema={}
        owned='a'*64;foreign='f'*64
        rows={owned:{'Id':owned,'Config':{'Labels':{'com.docker.compose.project':'trial'}},'State':{'Running':True}},
            foreign:{'Id':foreign,'Config':{'Labels':{}},'State':{'Running':True}}}
        def inner(*args,**kwargs):
            if args[0]=='ps':return (owned+'\n'+foreign+'\n').encode()
            if args[0]=='inspect':return json.dumps([rows[args[1]]]).encode()
            raise AssertionError('Unexpected mutation or lookup')
        value.inner=Mock(side_effect=inner);value.outer=Mock()
        with patch.object(trial,'PosixDockerAdapter') as adapter:
            adapter.return_value.discover.return_value={'keep-app':{'Id':owned}}
            with self.assertRaisesRegex(trial.TrialError,'Unexpected isolated daemon container'):value.cleanup()
        self.assertEqual([call.args[0] for call in value.inner.call_args_list],['ps','inspect','inspect'])
        value.outer.assert_not_called()


if __name__=='__main__':unittest.main()
