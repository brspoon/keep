"""Offline graph/source tests. Never execute Docker or contact a registry."""
import hashlib
import importlib.util
import copy
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


def registry_records():
    project='keep-maintenance-native-012345abcdef';identifier='b'*64;network_id='a'*64;endpoint_id='c'*64
    proof={'project':project,'network_id':network_id,'container_id':identifier,
        'image_id':'sha256:'+'d'*64,'members':[identifier]}
    network={'Id':network_id,'Name':project,'Internal':True,'Driver':'bridge','Scope':'local',
        'Labels':{'io.keep.maintenance.trial':project},'IPAM':{'Config':[{'Subnet':'172.18.0.0/16','Gateway':'172.18.0.1'}]},
        'Containers':{identifier:{'Name':project+'-registry','EndpointID':endpoint_id,'IPv4Address':'172.18.0.2/16'}}}
    container={'Id':identifier,'Image':proof['image_id'],'State':{'Running':True},
        'Config':{'Image':trial.TOOLING[1]['repository']+'@'+trial.TOOLING[1]['index_digest'],
            'Labels':{'io.keep.maintenance.trial':project}},
        'NetworkSettings':{'Ports':{},'Networks':{project:{'NetworkID':network_id,'EndpointID':endpoint_id,
            'IPAddress':'172.18.0.2','IPPrefixLen':16}}}}
    return proof,network,container


class RegistryEndpointTests(unittest.TestCase):
    def test_owned_internal_registry_uses_verified_ipv4_without_published_port(self):
        proof,network,container=registry_records()
        graph=trial.RegistryGraph.owned('amd64',proof,network,container)
        response=SimpleNamespace(status=200,read=lambda limit:b'{}',getheader=lambda name:None)
        with patch.object(trial.http.client,'HTTPConnection') as connection:
            connection.return_value.getresponse.return_value=response
            self.assertEqual(graph.request('GET','/v2/'),(b'{}',None))
        connection.assert_called_once_with('172.18.0.2',5000,timeout=15)
        self.assertEqual(container['NetworkSettings']['Ports'],{})

    def test_foreign_network_container_image_endpoint_and_public_address_reject_before_http(self):
        mutations=(
            lambda p,n,c:n.update(Internal=False),
            lambda p,n,c:n.update(Id='e'*64),
            lambda p,n,c:n['Labels'].update({'io.keep.maintenance.trial':'other'}),
            lambda p,n,c:n['Containers'].update({'e'*64:{}}),
            lambda p,n,c:c.update(Id='e'*64),
            lambda p,n,c:c.update(Image='sha256:'+'e'*64),
            lambda p,n,c:c['Config'].update(Image='unrelated/image:latest'),
            lambda p,n,c:c['State'].update(Running=False),
            lambda p,n,c:c['NetworkSettings']['Networks'].update({'other':{}}),
            lambda p,n,c:c['NetworkSettings']['Networks'][p['project']].update(NetworkID='e'*64),
            lambda p,n,c:c['NetworkSettings']['Networks'][p['project']].update(EndpointID='e'*64),
            lambda p,n,c:c['NetworkSettings']['Networks'][p['project']].update(IPAddress='8.8.8.8'),
            lambda p,n,c:n['IPAM']['Config'][0].update(Subnet='8.8.8.0/24'),
            lambda p,n,c:c['NetworkSettings']['Networks'][p['project']].update(IPAddress='172.19.0.2'),
            lambda p,n,c:c['NetworkSettings']['Networks'][p['project']].update(IPAddress='172.18.0.1'),
            lambda p,n,c:c['NetworkSettings']['Networks'][p['project']].update(IPPrefixLen=24),
            lambda p,n,c:p.update(address='8.8.8.8'),
        )
        for mutate in mutations:
            proof,network,container=registry_records();mutate(proof,network,container)
            with self.subTest(mutate=mutate),patch.object(trial.http.client,'HTTPConnection') as connect:
                with self.assertRaises(trial.TrialError):trial.RegistryGraph.owned('amd64',proof,network,container)
                connect.assert_not_called()

    def test_fresh_child_revalidates_owned_resources_and_rejects_unbounded_id_before_commands(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temp:
            paths=create_private_paths();root=create_root(paths,Path(temp).resolve()/'private');state=paths.mkdir(root/'state')
            executable=root/'docker';paths.publish(executable,b'fixture');executable.chmod(0o500)
            proof,network,container=registry_records()
            graph={'schema':'keep.maintenance-trial-graph.v1','architecture':'amd64','registry':proof,'images':[]}
            paths.publish(state/'trial-registry-graph.json',canonical(graph))
            def transport(argv,**kwargs):
                if tuple(argv[3:])==('network','inspect',proof['network_id']):return canonical([network])
                if tuple(argv[3:])==('inspect',proof['container_id']):return canonical([container])
                raise AssertionError('Unexpected registry reconstruction command')
            with patch.object(trial.shutil,'which',return_value=str(executable)),patch.object(trial,'run',side_effect=transport) as run, \
                 patch.object(trial,'load_backend',side_effect=RuntimeError('stop after endpoint proof')) as load, \
                 patch.object(trial.http.client,'HTTPConnection') as connect:
                with self.assertRaisesRegex(RuntimeError,'stop after endpoint proof'):
                    trial.child_helper(state,'12345678-1234-4234-8234-123456789abc',crash=True)
                self.assertEqual(run.call_count,2);load.assert_called_once();connect.assert_not_called()
            proof['network_id']='--unbounded-command'
            paths.publish(state/'trial-registry-graph.json',canonical(graph),overwrite=True)
            with patch.object(trial,'run') as run:
                with self.assertRaises(trial.TrialError):
                    trial.child_helper(state,'12345678-1234-4234-8234-123456789abc',crash=True)
                run.assert_not_called()


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
    def hybrid(self, *, root_kind='index', architecture='amd64'):
        configuration={'architecture':architecture,'os':'linux',
            'config':{'User':'10001:10001','Labels':{'org.opencontainers.image.version':'2.26.0',
                'org.opencontainers.image.revision':'a'*40}},
            'rootfs':{'type':'layers','diff_ids':['sha256:'+'e'*64]}}
        raw=canonical(configuration);config_digest='sha256:'+hashlib.sha256(raw).hexdigest()
        manifest=canonical({'schemaVersion':2,'mediaType':trial.MANIFEST,
            'config':{'digest':config_digest,'size':len(raw),'mediaType':'application/vnd.oci.image.config.v1+json'},
            'layers':[{'digest':'sha256:'+'f'*64,'size':42,'mediaType':'application/vnd.oci.image.layer.v1.tar+gzip'}]})
        native='sha256:'+hashlib.sha256(manifest).hexdigest()
        index=canonical({'schemaVersion':2,'mediaType':trial.INDEX,'manifests':[{'mediaType':trial.MANIFEST,
            'digest':native,'size':len(manifest),'platform':{'os':'linux','architecture':architecture}}]})
        indexed='sha256:'+hashlib.sha256(index).hexdigest()
        root_digest,root_body,root_type=(indexed,index,trial.INDEX) if root_kind=='index' else (native,manifest,trial.MANIFEST)
        members={'oci-layout':canonical({'imageLayoutVersion':'1.0.0'}),
            'index.json':canonical({'schemaVersion':2,'manifests':[{'digest':root_digest,'size':len(root_body),'mediaType':root_type}]}),
            'blobs/sha256/'+indexed[7:]:index,'blobs/sha256/'+native[7:]:manifest,'blobs/sha256/'+config_digest[7:]:raw}
        inspected={'Id':config_digest,'Architecture':architecture,'Os':'linux','Config':configuration['config'],
            'RootFS':{'Type':'layers','Layers':configuration['rootfs']['diff_ids']},
            'Descriptor':{'digest':root_digest,'mediaType':root_type}}
        return members,inspected,config_digest

    def archive(self,members):
        temporary=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        archive=Path(temporary.name).resolve()/'candidate.tar'
        with tarfile.open(archive,'w') as package:
            for name,data in members.items():
                member=tarfile.TarInfo(name);member.size=len(data);package.addfile(member,io.BytesIO(data))
        return archive

    def test_oci_export_with_classic_config_id_selects_one_verified_native_or_index_graph(self):
        for architecture in ('amd64','arm64'):
            for root_kind in ('native','index'):
                members,inspected,digest=self.hybrid(root_kind=root_kind,architecture=architecture)
                with self.subTest(architecture=architecture,root_kind=root_kind):
                    self.assertEqual(trial.candidate_configuration(self.archive(members),inspected),digest)
                    without_descriptor={key:value for key,value in inspected.items() if key!='Descriptor'}
                    self.assertEqual(trial.candidate_configuration(self.archive(members),without_descriptor),digest)

    def test_hybrid_cannot_fall_back_to_similar_metadata_or_ignore_live_descriptor_and_rootfs(self):
        mutations=(
            lambda value:value.update(Id='sha256:'+'f'*64),
            lambda value:value.update(Architecture='arm64'),
            lambda value:value.update(Os='windows'),
            lambda value:value['Config'].update(User='0:0'),
            lambda value:value['Config']['Labels'].update({'org.opencontainers.image.revision':'b'*40}),
            lambda value:value['Descriptor'].update(digest='sha256:'+'f'*64),
            lambda value:value['Descriptor'].update(mediaType=trial.MANIFEST),
            lambda value:value['RootFS'].update(Layers=['sha256:'+'f'*64]),
            lambda value:value['RootFS'].update(Type='other'),
        )
        for mutate in mutations:
            members,inspected,_=self.hybrid();mutate(inspected)
            with self.subTest(mutate=mutate),self.assertRaises(trial.TrialError):
                trial.candidate_configuration(self.archive(members),inspected)

    def test_malformed_blob_descriptor_and_ambiguous_oci_graphs_are_held(self):
        for kind in ('tampered-config','missing-config','wrong-size','boolean-size','duplicate-root','duplicate-native','foreign-graph'):
            members,inspected,digest=self.hybrid()
            if kind=='tampered-config':members['blobs/sha256/'+digest[7:]]+=b' '
            elif kind=='missing-config':members.pop('blobs/sha256/'+digest[7:])
            else:
                wrapper=json.loads(members['index.json'])
                root=wrapper['manifests'][0]
                if kind=='wrong-size':root['size']+=1
                elif kind=='boolean-size':root['size']=True
                elif kind=='duplicate-root':wrapper['manifests'].append(copy.deepcopy(root))
                elif kind=='duplicate-native':
                    index=json.loads(members['blobs/sha256/'+root['digest'][7:]])
                    index['manifests'].append(copy.deepcopy(index['manifests'][0]))
                    raw=canonical(index);new_digest='sha256:'+hashlib.sha256(raw).hexdigest()
                    members['blobs/sha256/'+new_digest[7:]]=raw
                    root.update(digest=new_digest,size=len(raw));inspected['Descriptor'].update(digest=new_digest)
                else:
                    index=json.loads(members['blobs/sha256/'+root['digest'][7:]])
                    native=index['manifests'][0]
                    manifest=json.loads(members['blobs/sha256/'+native['digest'][7:]])
                    manifest['annotations']={'fixture':'different immutable native sharing the same config'}
                    raw=canonical(manifest);new_digest='sha256:'+hashlib.sha256(raw).hexdigest()
                    members['blobs/sha256/'+new_digest[7:]]=raw
                    wrapper['manifests'].append({'digest':new_digest,'size':len(raw),'mediaType':trial.MANIFEST})
                members['index.json']=canonical(wrapper)
            with self.subTest(kind=kind),self.assertRaises(trial.TrialError):
                trial.candidate_configuration(self.archive(members),inspected)

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
                inspected={'Id':identifier,'Architecture':'amd64','Os':'linux','Config':config['config']}
                self.assertEqual(trial.candidate_configuration(archive,inspected),digest)
                with self.assertRaises(trial.TrialError):trial.candidate_configuration(archive,{**inspected,'Architecture':'arm64'})


class ImageStagingTests(unittest.TestCase):
    def test_verified_hybrid_candidate_and_staging_failure_have_safe_specific_receipt(self):
        fixture=CandidateTests();members,inspected,digest=fixture.hybrid();archive=fixture.archive(members)
        self.addCleanup(fixture.doCleanups)
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            paths=create_private_paths();root=create_root(paths,Path(temporary).resolve()/'private')
            value=trial.NativeTrial.__new__(trial.NativeTrial)
            value.paths,value.tool_state=paths,paths.mkdir(root/'tool-state')
            value.candidate,value.architecture='keep-ci:latest','amd64'
            value.name='keep-maintenance-native-012345abcdef';value.outer_images=[]
            value.report={'source_files':{},'images':{}}
            inspected=copy.deepcopy(inspected);inspected['Config']['Env']=['PRIVATE_TOKEN=do-not-report']
            def outer(*args,**kwargs):
                if args[:2]==('image','inspect'):return canonical([inspected])
                if args[:2]==('image','save'):
                    paths.publish(Path(args[args.index('--output')+1]),archive.read_bytes())
                    return b''
                if args[:2]==('image','tag'):return b''
                raise AssertionError('Unexpected staging transport')
            value.outer=Mock(side_effect=outer)
            value.stage_source=Mock(side_effect=trial.TrialError('private staging detail',code='command_failed',returncode=1))
            with self.assertRaises(trial.TrialError):value.images()
            self.assertEqual(value.report['candidate']['image_id'],digest)
            self.assertEqual(value.report['base_image']['config_digest'],digest)
            self.assertEqual([row['step'] for row in value.report['image_staging']],[
                'candidate-inspect','candidate-export','candidate-export-verify','candidate-reinspect',
                'owned-base-alias-create','fixture-source-stage'])
            self.assertEqual(value.report['image_staging'][-1],{
                'step':'fixture-source-stage','status':'failed','error_code':'command_failed','exit_code':1})
            self.assertNotIn('PRIVATE_TOKEN',json.dumps(value.report))
            self.assertNotIn('private staging detail',json.dumps(value.report))

    def test_candidate_metadata_is_held_before_export_or_alias_creation(self):
        value=trial.NativeTrial.__new__(trial.NativeTrial)
        value.candidate,value.architecture='keep-ci:latest','amd64';value.report={}
        value.outer=Mock(return_value=canonical([{'Id':'sha256:'+'a'*64,'Architecture':'arm64','Os':'linux'}]))
        with self.assertRaises(trial.TrialError):value.images()
        self.assertEqual(value.report['image_staging'][-1]['step'],'candidate-inspect')
        self.assertEqual(value.outer.call_count,1)
        self.assertNotIn('candidate',value.report)


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

    def test_index_descriptors_and_config_id_hybrids_keep_exact_pins(self):
        for architecture in ('amd64','arm64'):
            for tool in trial.TOOLING:
                index=tool['index_digest'];native=tool['native'][architecture]
                base={'Architecture':architecture,'Os':'linux','Id':'sha256:'+'a'*64,
                    'RepoDigests':[tool['repository']+'@'+index]}
                for digest,mime in ((index,trial.INDEX),(native,trial.MANIFEST)):
                    descriptor={'digest':digest,'mediaType':mime}
                    self.assertTrue(trial.pinned_tool_identity({**base,'Descriptor':descriptor},tool,architecture))
                    self.assertTrue(trial.pinned_tool_identity({**base,'Id':digest,'Descriptor':descriptor},tool,architecture))
                    self.assertFalse(trial.pinned_tool_identity({**base,'RepoDigests':[],
                        'Descriptor':descriptor},tool,architecture))
                    self.assertFalse(trial.pinned_tool_identity({**base,'Descriptor':{**descriptor,
                        'digest':'sha256:'+'f'*64}},tool,architecture))
                    self.assertFalse(trial.pinned_tool_identity({**base,'Descriptor':{**descriptor,
                        'mediaType':trial.MANIFEST if mime==trial.INDEX else trial.INDEX}},tool,architecture))
                self.assertFalse(trial.pinned_tool_identity({**base,'Id':native,
                    'Descriptor':{'digest':index,'mediaType':trial.INDEX}},tool,architecture))
                self.assertFalse(trial.pinned_tool_identity({**base,'Architecture':
                    'arm64' if architecture=='amd64' else 'amd64'},tool,architecture))
                self.assertFalse(trial.pinned_tool_identity({**base,'Os':'windows'},tool,architecture))


class ToolPreflightTests(unittest.TestCase):
    def value(self, architecture='amd64'):
        value=trial.NativeTrial.__new__(trial.NativeTrial)
        value.architecture,value.report=architecture,{}
        return value

    def test_older_outer_client_inspects_preloaded_native_pins_without_platform_flag(self):
        for architecture,machine in (('amd64','x86_64'),('arm64','aarch64')):
            value=self.value(architecture)
            def outer(*args):
                self.assertNotIn('--platform',args)
                if args==('version','--format','{{json .Client.Version}}'):return b'"28.0.4"\n'
                if args==('info','--format','{{.Architecture}}'):return machine.encode()
                for tool in trial.TOOLING:
                    reference=tool['repository']+'@'+tool['index_digest']
                    if args==('image','inspect',reference):
                        return canonical([{'Id':'sha256:'+'a'*64,'Architecture':architecture,'Os':'linux',
                            'RepoDigests':[tool['repository'].removeprefix('library/')+'@'+tool['index_digest']]}])
                raise AssertionError('Unexpected preflight command')
            value.outer=Mock(side_effect=outer)
            with patch.object(trial.platform,'machine',return_value=machine):value.tooling_preflight()
            self.assertEqual(len(value.report['tooling']),2)
            self.assertTrue(all(row['status']=='passed' for row in value.report['tooling_preflight']))
            self.assertEqual(value.report['tooling_preflight'][1]['client_version'],'28.0.4')
            self.assertEqual([row['native_digest'] for row in value.report['tooling']],
                [tool['native'][architecture] for tool in trial.TOOLING])

    def test_failed_public_tool_inspect_records_bounded_code_without_stderr_or_environment(self):
        value=self.value()
        secret='private-token-that-must-not-be-reported'
        def process(argv,**kwargs):
            if 'version' in argv:return SimpleNamespace(returncode=0,stdout=b'"28.0.4"\n')
            if 'info' in argv:return SimpleNamespace(returncode=0,stdout=b'x86_64\n')
            return SimpleNamespace(returncode=1,stdout=secret.encode(),stderr=secret.encode())
        value.outer=lambda *args:trial.run(('docker','--host','unix:///var/run/docker.sock',*args),
            env={'PRIVATE_TOKEN':secret})
        with patch.object(trial.platform,'machine',return_value='x86_64'),patch.object(trial.subprocess,'run',side_effect=process):
            with self.assertRaises(trial.TrialError) as raised:value.tooling_preflight()
        self.assertEqual(raised.exception.code,'command_failed')
        failed=value.report['tooling_preflight'][-1]
        self.assertEqual(failed,{'step':'outer-tool-image-inspect','status':'failed',
            'reference':trial.TOOLING[0]['repository']+'@'+trial.TOOLING[0]['index_digest'],
            'error_code':'command_failed','exit_code':1})
        self.assertNotIn(secret,json.dumps(value.report))
        self.assertNotIn('PRIVATE_TOKEN',json.dumps(value.report))
        self.assertNotIn('tooling',value.report)

    def test_wrong_native_platform_and_unbound_reference_fail_before_resources(self):
        for change,code in (({'Architecture':'arm64'},'tool_not_native'),
                ({'RepoDigests':['unrelated/image@'+trial.TOOLING[0]['index_digest']]},'tool_identity_unavailable')):
            value=self.value()
            def outer(*args):
                if args[0]=='version':return b'"28.0.4"'
                if args[0]=='info':return b'x86_64'
                self.assertEqual(args[:2],('image','inspect'))
                return canonical([{'Id':'sha256:'+'a'*64,'Architecture':'amd64','Os':'linux',
                    'RepoDigests':['docker@'+trial.TOOLING[0]['index_digest']],**change}])
            value.outer=Mock(side_effect=outer)
            with patch.object(trial.platform,'machine',return_value='x86_64'):
                with self.assertRaises(trial.TrialError):value.tooling_preflight()
            self.assertEqual(value.report['tooling_preflight'][-1]['error_code'],code)
            self.assertNotIn('tooling',value.report)

    def test_command_timeout_unavailable_and_invalid_version_have_fixed_codes(self):
        for error,code in ((trial.subprocess.TimeoutExpired(['private'],1), 'command_timeout'),
                (OSError('private filesystem error'),'command_unavailable')):
            with patch.object(trial.subprocess,'run',side_effect=error):
                with self.assertRaises(trial.TrialError) as raised:trial.run(('docker','version'))
            self.assertEqual(raised.exception.code,code)
        value=self.value();value.outer=Mock(return_value=b'"private invalid version"')
        with patch.object(trial.platform,'machine',return_value='x86_64'):
            with self.assertRaises(trial.TrialError):value.tooling_preflight()
        self.assertEqual(value.report['tooling_preflight'][-1]['error_code'],'metadata_invalid')
        self.assertNotIn('private invalid version',json.dumps(value.report))


class ToolSetupTests(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(directory.cleanup)
        paths=create_private_paths();root=create_root(paths,Path(directory.name).resolve()/'private')
        value=trial.NativeTrial.__new__(trial.NativeTrial)
        value.paths,value.root=paths,root
        for name in ('tool_state','installation','state','config','socket'):
            setattr(value,name,paths.mkdir(root/name))
        proof,self.network,self.registry=registry_records()
        value.name,value.architecture=proof['project'],'amd64'
        value.env={'PATH':'/usr/bin:/bin'}
        value.tools,value.network=[],None
        value.report={'tooling':[{'local_id':'sha256:'+'e'*64},{'local_id':proof['image_id']}]}
        value.tooling_preflight=Mock()
        self.dind='f'*64;self.fail_dind=False
        def outer(*args,**kwargs):
            self.assertNotIn('--publish',args)
            if args[:2]==('network','create'):
                self.assertIn('--internal',args)
                return proof['network_id'].encode()
            if args[0]=='run':
                self.assertEqual(args[args.index('--network')+1],value.name)
                if args[args.index('--name')+1]==value.name+'-registry':return proof['container_id'].encode()
                self.assertEqual(args[args.index('--entrypoint')+1],'dockerd')
                self.assertIn('--host=unix:///trial-socket/docker.sock',args)
                if self.fail_dind:raise trial.TrialError('private command error',code='command_failed',returncode=125)
                paths.publish(value.socket/'docker.sock',b'fixture socket')
                return self.dind.encode()
            if args==('network','inspect',proof['network_id']):return canonical([self.network])
            if args==('inspect',proof['container_id']):return canonical([self.registry])
            if args[0]=='cp':
                paths.publish(Path(args[-1]),b'private fixture executable')
                return b''
            if args[0]=='exec':return b''
            raise AssertionError('Unexpected tooling setup command')
        value.outer=Mock(side_effect=outer)
        def inner(*args):
            if args==('info','--format','{{json .ID}}'):return b'"synthetic-daemon"'
            if args==('info','--format','{{.OSType}}'):return b'linux'
            if args==('info','--format','{{.Architecture}}'):return b'x86_64'
            raise AssertionError('Unexpected inner daemon probe')
        value.inner=Mock(side_effect=inner)
        self.value=value

    def test_actual_setup_stages_use_owned_internal_endpoint_and_unix_only_daemon(self):
        with patch.object(trial.RegistryGraph,'request',return_value=(b'{}',None)),patch.object(trial,'run',return_value=b''):
            self.value.tooling()
        self.assertEqual(self.value.resolver.host,'172.18.0.2')
        self.assertEqual(self.value.resolver.port,5000)
        self.assertEqual(self.value.registry_proof['members'],['b'*64,self.dind])
        self.assertEqual(self.value.profile.daemon_id,'synthetic-daemon')
        rows=self.value.report['tooling_preflight']
        self.assertEqual([row['step'] for row in rows],[
            'owned-internal-network-create','owned-registry-container-start','owned-registry-endpoint-inspect',
            'owned-registry-http-ready','owned-dind-container-start','pinned-docker-client-copy',
            'pinned-compose-client-copy','isolated-unix-socket-ready','isolated-context-create',
            'isolated-daemon-ready','isolated-native-platform-verify'])
        self.assertTrue(all(row['status']=='passed' for row in rows))
        self.assertNotIn('172.18.0.2',json.dumps(self.value.report))

    def test_dind_setup_failure_records_exact_safe_stage_and_preserves_registry_ownership(self):
        self.fail_dind=True
        with patch.object(trial.RegistryGraph,'request',return_value=(b'{}',None)):
            with self.assertRaises(trial.TrialError):self.value.tooling()
        self.assertEqual(self.value.report['tooling_preflight'][-1],{
            'step':'owned-dind-container-start','status':'failed','error_code':'command_failed','exit_code':125})
        self.assertEqual(self.value.tools,['b'*64])
        self.assertNotIn('private command error',json.dumps(self.value.report))
        self.assertFalse(any(call.args[0]=='cp' for call in self.value.outer.call_args_list))


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
