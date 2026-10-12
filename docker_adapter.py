"""Concrete POSIX Docker adapter. No operation runs at import time.

Only fixed commands against the locally enrolled context, project, and volume
are accepted. Browser requests cannot choose paths, names, flags, or repositories.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time
import uuid

from host_engine import BoundedRunner, DockerPlans, EngineError, Plan
from maintenance_protocol import (ImageIdentity, canonical, canonical_uuid, exact_fields,
                                  parse_json, public_status, signed, verify)
from private_store import PrivatePaths, StorageError
from recovery_set import MAX_CONFIG, MAX_DATABASE, MAX_IMAGE, RecoverySet, file_digest

SERVICES = ("keep-app", "keep-digest")
CONTAINER = re.compile(r"[a-f0-9]{64}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")
INSPECT_CONTAINER = ('{"Id":{{json .Id}},"Image":{{json .Image}},"Source":{{json .Config.Image}},'
    '"Manifest":{{json .ImageManifestDescriptor}},"Labels":{{json .Config.Labels}},'
    '"Mounts":{{json .Mounts}},"State":{"Running":{{json .State.Running}},'
    '"Restarting":{{json .State.Restarting}},"Status":{{json .State.Status}},'
    '"Health":{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}}},'
    '"Guard":{"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},'
    '"Privileged":{{json .HostConfig.Privileged}},"CapDrop":{{json .HostConfig.CapDrop}},'
    '"SecurityOpt":{{json .HostConfig.SecurityOpt}}}}')
INSPECT_IMAGE = ('{"Id":{{json .Id}},"Architecture":{{json .Architecture}},"Os":{{json .Os}},'
    '"Size":{{json .Size}},"RepoDigests":{{json .RepoDigests}},"Labels":{{json .Config.Labels}},'
    '"Descriptor":{{json .Descriptor}},"RootFS":{{json .RootFS.Layers}},"User":{{json .Config.User}}}')
INSPECT_VOLUME = ('{"Name":{{json .Name}},"Driver":{{json .Driver}},"Scope":{{json .Scope}},'
                  '"Labels":{{json .Labels}},"Options":{{json .Options}}}')
INSPECT_HELPER=INSPECT_CONTAINER[:-1]+',"Command":{{json .Config.Cmd}},"Entrypoint":{{json .Config.Entrypoint}},"User":{{json .Config.User}},"Network":{{json .HostConfig.NetworkMode}}}'


def env_image(data, identity):
    """Change only the unique literal KEEP_IMAGE setting, preserving other bytes."""
    if not isinstance(data, bytes) or len(data) > MAX_CONFIG:
        raise EngineError("Installation environment is invalid")
    lines = data.decode("utf-8").splitlines(keepends=True)
    matches = [i for i,line in enumerate(lines) if re.match(r"^\s*KEEP_IMAGE\s*=",line)]
    if len(matches) > 1 or any(re.match(r"^\s*export\s+KEEP_IMAGE\b",line) for line in lines):
        raise EngineError("Installation image setting is ambiguous")
    line = "KEEP_IMAGE="+identity.reference
    if matches:
        index=matches[0]; ending="\r\n" if lines[index].endswith("\r\n") else "\n" if lines[index].endswith("\n") else ""
        lines[index]=line+ending
    else:
        if lines and not lines[-1].endswith(("\n","\r")):lines[-1]+="\n"
        lines.append(line+"\n")
    return ''.join(lines).encode()


class PosixDockerAdapter:
    EXPECTED_VOLUME_KEY='keep-data'
    def __init__(self, paths, profile, enrollment, *, resolver=None, runner=None,
                 sleep=time.sleep, monotonic=time.monotonic, wall_time=time.time):
        if os.name=="nt":raise EngineError("This adapter requires POSIX; native Windows adapter is not qualified")
        self.paths,self.profile,self.enrollment=paths,profile.validate(paths),enrollment
        self.plans=DockerPlans(paths,profile);self.runner=runner or BoundedRunner(profile,paths=paths)
        if resolver is None:
            from release_resolver import OfficialReleaseResolver
            resolver=OfficialReleaseResolver()
        self.resolver,self.sleep,self.monotonic,self.wall_time=resolver,sleep,monotonic,wall_time
        self.request=None;self.containers={};self.attempt=None;self.known_identities={}
        self.source=(Path(__file__).parent/'volume_worker.py').read_text()
        self.source_sha=hashlib.sha256(self.source.encode()).hexdigest()
        self.config_paths=(profile.env_file,*profile.compose_files)
        version=profile.installation/'VERSION'
        if version.exists() or version.is_symlink():self.config_paths+= (paths.check(version),)
        self.configuration_record=profile.state/'configuration.json'

    @classmethod
    def capture_configuration(cls, paths, profile):
        """Local enrollment only; never auto-recapture altered config on restart."""
        files=(profile.env_file,*profile.compose_files)
        version=profile.installation/'VERSION'
        if version.exists() or version.is_symlink():files+=(paths.check(version),)
        value={str(path):file_digest(paths,path,limit=MAX_CONFIG) for path in files}
        paths.publish(profile.state/'configuration.json',canonical(value))
        return value

    def run(self, label, args, *, timeout=30, limit=1048576, stdin=b"", artifact=None, artifact_limit=0):
        return self.runner.run(Plan(label,tuple(args),timeout,limit,stdin,artifact,artifact_limit))

    def json(self,label,args,**kwargs):
        return parse_json(self.run(label,args,**kwargs),kwargs.get('limit',1048576))

    def assert_daemon(self):
        # Reject a changed/remote endpoint before invoking any daemon request.
        endpoint=parse_json(self.runner.run(self.plans.context_endpoint()))
        if endpoint!=self.profile.docker_endpoint:raise EngineError("Enrolled Docker context endpoint changed")
        if parse_json(self.runner.run(self.plans.identity()))!=self.profile.daemon_id:
            raise EngineError("Enrolled Docker daemon changed")
        if self.run('Linux engine',(*self.plans.base,'info','--format','{{.OSType}}'),limit=4096).strip()!=b'linux':
            raise EngineError("Keep maintenance requires Linux containers")
        if self.request:
            architecture=self.run('native engine architecture',(*self.plans.base,'info','--format','{{.Architecture}}'),limit=4096).strip()
            normalized={b'amd64':'amd64',b'x86_64':'amd64',b'arm64':'arm64',b'aarch64':'arm64'}.get(architecture)
            if normalized!=self.request.expected.architecture:raise EngineError('Image architecture is not native to the enrolled engine')

    def image(self,identity):
        identity=ImageIdentity.from_dict(identity.as_dict())
        # Digest exports may reload as dangling images. Lookup only the exact
        # already verified original index/config, never tag or overwrite aliases.
        record=None
        for selected in (identity.reference,identity.index_digest,identity.image_id):
            try:
                record=self.json('immutable native image metadata',(*self.plans.base,'image','inspect','--platform',
                    'linux/'+identity.architecture,'--format',INSPECT_IMAGE,selected),limit=65536)
                break
            except EngineError:
                continue
        if record is None:raise EngineError('Original immutable image is unavailable')
        if not isinstance(record,dict):raise EngineError('Immutable image metadata is invalid')
        labels=record.get('Labels') or {}
        descriptor=record.get('Descriptor')
        # Classic stores report the config digest. Docker's containerd store
        # reports an index/native descriptor digest; neither is a config ID.
        descriptor_ok=record.get('Id')==identity.image_id and descriptor is None
        if isinstance(descriptor,dict):
            descriptor_ok=(descriptor.get('digest')==record.get('Id') and
                (record['Id']==identity.native_digest and descriptor.get('mediaType') in
                    ('application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json')
                or record['Id']==identity.index_digest and descriptor.get('mediaType') in
                    ('application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json')))
        if (not descriptor_ok or record.get('Architecture')!=identity.architecture
                or not isinstance(labels,dict)
                or record.get('Os')!='linux' or labels.get('org.opencontainers.image.version')!=identity.version
                or labels.get('org.opencontainers.image.revision')!=identity.revision
                or labels.get('org.opencontainers.image.source')!='https://github.com/brspoon/keep'
                or record.get('User')!='10001:10001'):
            raise EngineError("Immutable image metadata does not match the release")
        configurations=getattr(self.resolver,'configurations',{})
        recorded=None
        if self.request:
            recorded=self.operation/('release-config-'+identity.image_id[7:]+'.json')
            if recorded.exists() or recorded.is_symlink():
                raw=self.paths.read(recorded,limit=524288)
                proof=self.configuration_proof(raw,identity)
                configurations[identity.reference]=proof
        if descriptor is not None and identity.reference not in configurations:
            self.resolver.resolve(identity)
            configurations=getattr(self.resolver,'configurations',{})
        if descriptor is not None and identity.reference not in configurations:
            raise EngineError('Native configuration proof is unavailable')
        proof=configurations.get(identity.reference)
        if proof and any(record.get(field)!=proof[field] for field in ('RootFS','User','Labels')):
            raise EngineError('Local native configuration differs from published configuration bytes')
        if type(record.get('Size')) is not int or not 1<=record['Size']<=MAX_IMAGE:
            raise EngineError("Image size exceeds its bound")
        self.known_identities[identity.image_id]=identity
        published=getattr(self.resolver,'configuration_bytes',{}).get(identity.reference)
        if recorded is not None and published is not None:
            self.configuration_proof(published,identity)
            if recorded.exists():
                if self.paths.read(recorded,limit=524288)!=published:raise EngineError('Original release configuration bytes changed')
            else:self.paths.publish(recorded,published)
        record['SelectedReference']=selected
        return record

    @staticmethod
    def configuration_proof(data,identity):
        if hashlib.sha256(data).hexdigest()!=identity.image_id[7:]:
            raise EngineError('Original release configuration digest changed')
        value=parse_json(data,524288)
        config=value.get('config') if isinstance(value,dict) else None
        root=value.get('rootfs') if isinstance(value,dict) else None
        labels=config.get('Labels') if isinstance(config,dict) else None
        if (not isinstance(config,dict) or not isinstance(root,dict) or not isinstance(labels,dict)
                or value.get('architecture')!=identity.architecture or value.get('os')!='linux'
                or config.get('User')!='10001:10001' or root.get('type')!='layers'
                or labels.get('org.opencontainers.image.version')!=identity.version
                or labels.get('org.opencontainers.image.revision')!=identity.revision
                or labels.get('org.opencontainers.image.source')!='https://github.com/brspoon/keep'
                or not isinstance(root.get('diff_ids'),list) or not 1<=len(root['diff_ids'])<=128
                or any(not isinstance(digest,str) or not re.fullmatch('sha256:[a-f0-9]{64}',digest) for digest in root['diff_ids'])):
            raise EngineError('Original release configuration bytes are invalid')
        return {'RootFS':root['diff_ids'],'User':config['User'],'Labels':labels}

    def canonical_image(self,row,identities):
        for identity in identities:
            if row.get('Image') not in (identity.image_id,identity.index_digest,identity.native_digest):continue
            source=row.get('Source')
            fixed_sources={identity.image_id,identity.index_digest,identity.native_digest,identity.reference,
                'brspoon/keep@'+identity.native_digest,'brspoon/keep:'+identity.version,'brspoon/keep:stable','brspoon/keep:latest'}
            if source not in fixed_sources and source not in {'docker.io/'+value for value in fixed_sources if value.startswith('brspoon/')}:
                continue
            manifest=row.get('Manifest')
            if row['Image']!=identity.image_id and (not isinstance(manifest,dict)
                    or manifest.get('digest')!=identity.native_digest or manifest.get('mediaType') not in
                    ('application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json')):
                continue
            if manifest is not None and (not isinstance(manifest,dict) or manifest.get('digest')!=identity.native_digest):continue
            self.image(identity)
            return identity.image_id
        raise EngineError('Service source, native manifest or configuration identity changed')

    def inspect(self,container,helper=False):
        if not isinstance(container,str) or not CONTAINER.fullmatch(container):raise EngineError("Invalid Docker container identity")
        record=self.json('selected container metadata',(*self.plans.base,'inspect','--format',INSPECT_HELPER if helper else INSPECT_CONTAINER,container),limit=65536)
        if record.get('Id')!=container:raise EngineError("Docker returned another container")
        return record

    def mounts(self,record):
        mounts=record.get('Mounts')
        if not isinstance(mounts,list):raise EngineError("Container mounts are incomplete")
        data=[]
        for mount in mounts:
            if mount.get('Type')=='tmpfs' and mount.get('Destination')=='/tmp':continue
            if (mount.get('Type')!='volume' or mount.get('Name')!=self.profile.volume
                    or mount.get('Destination')!='/app/data' or mount.get('RW') is not True):
                raise EngineError("Container has an unenrolled mount")
            data.append(mount)
        if len(data)!=1:raise EngineError("Container must use the exact one enrolled data volume")
        guard=record.get('Guard') or {}
        if (guard.get('ReadonlyRootfs') is not True or guard.get('Privileged') is not False
                or 'ALL' not in (guard.get('CapDrop') or [])
                or not any(value in ('no-new-privileges','no-new-privileges:true') for value in (guard.get('SecurityOpt') or []))):
            raise EngineError("Container isolation differs from the enrolled profile")

    def discover(self, *, images=None):
        self.assert_daemon()
        volume=self.json('enrolled named volume',(*self.plans.base,'volume','inspect','--format',INSPECT_VOLUME,self.profile.volume),limit=16384)
        if (volume.get('Name')!=self.profile.volume or volume.get('Driver')!='local'
                or volume.get('Scope')!='local' or volume.get('Options') not in (None,{})):
            raise EngineError("Data volume is not the enrolled local named volume")
        labels=volume.get('Labels') or {}
        if labels.get('com.docker.compose.project')!=self.profile.project or labels.get('com.docker.compose.volume')!=self.EXPECTED_VOLUME_KEY:
            raise EngineError("Data volume labels do not match enrollment")
        ids=self.run('all project containers',(*self.plans.base,'ps','--all','--no-trunc','--filter',
            'label=com.docker.compose.project='+self.profile.project,'--format','{{.ID}}'),limit=4096).decode().split()
        if len(ids)!=2 or len(set(ids))!=2:raise EngineError("The enrolled project must have exactly two service containers")
        records={}
        base_files=tuple(str(path) for path in self.profile.compose_files)
        for identifier in ids:
            row=self.inspect(identifier);labels=row.get('Labels') or {};service=labels.get('com.docker.compose.service')
            if (service not in SERVICES or service in records or labels.get('com.docker.compose.project')!=self.profile.project
                    or labels.get('com.docker.compose.project.working_dir')!=str(self.profile.installation)):
                raise EngineError("Service topology or image changed outside this operation")
            if images is not None:
                identities=dict(self.known_identities)
                if self.request:
                    identities[self.request.expected.image_id]=self.request.expected
                    if self.request.target:identities[self.request.target.image_id]=self.request.target
                row['CanonicalImage']=self.canonical_image(row,[value for key,value in identities.items() if key in images])
            files=tuple(labels.get('com.docker.compose.project.config_files','').split(','))
            if files!=base_files:
                if len(files)!=len(base_files)+1 or files[:-1]!=base_files:
                    raise EngineError("Service Compose files are not enrolled")
                overlay=Path(files[-1])
                if overlay.parent.parent!=self.profile.state/'operations' or overlay.name not in ('activate.json','restore.json'):
                    raise EngineError("Service Compose override is not helper-owned")
                canonical_uuid(overlay.parent.name)
                expected_override={'services':{name:{'image':row['Source']} for name in SERVICES}}
                if parse_json(self.paths.read(overlay))!=expected_override:
                    raise EngineError("Service Compose override changed")
            self.mounts(row);records[service]=row
        self.containers=records
        return records

    def no_foreign_writers(self,allowed=()):
        ids=self.run('data-volume writers',(*self.plans.base,'ps','--no-trunc','--filter','volume='+self.profile.volume,'--format','{{.ID}}'),limit=4096).decode().split()
        if len(ids)>16 or any(not CONTAINER.fullmatch(value) or value not in allowed for value in ids):
            raise EngineError("Another running container can write Keep data")

    @property
    def operation(self):
        if not self.request:raise EngineError("No verified operation is bound")
        return self.profile.state/'operations'/canonical_uuid(self.request.request_id)

    def bind(self,request):
        if self.request and self.request!=request:raise EngineError("Adapter cannot switch operations")
        self.request=request
        operation=self.operation
        for directory in (operation.parent,operation):
            if not directory.exists():self.paths.mkdir(directory)
        body={'protocol':'keep.maintenance.v1','install_id':self.enrollment.install_id,'owner_id':self.enrollment.owner_id,
            'epoch':self.enrollment.epoch,'request_id':request.request_id,'operation':request.operation,
            'credential_version':request.credential_version,'issued_at':request.issued_at,'expires_at':request.expires_at,
            'nonce':request.nonce,'expected':request.expected.as_dict(),'target':request.target.as_dict() if request.target else None}
        if hashlib.sha256(canonical(body)).hexdigest()!=request.payload_sha256:raise EngineError("Accepted request fingerprint does not match")
        path=operation/'request.json';data=signed(self.enrollment,body)
        if path.exists():
            if self.paths.read(path)!=data:raise EngineError("Original accepted request bytes changed")
        else:self.paths.publish(path,data)
        source_path=operation/'volume-worker.py'
        if source_path.exists():self.source=self.paths.read(source_path,limit=65536).decode()
        else:self.paths.publish(source_path,self.source.encode())
        self.source_sha=hashlib.sha256(self.source.encode()).hexdigest()

    def mailbox(self,verb,**extra):
        if verb not in DockerPlans.MAILBOX_VERBS:raise EngineError("Mailbox verb is not allowed")
        rows=self.discover(images={self.request.expected.image_id,self.request.target.image_id} if self.request.target else {self.request.expected.image_id})
        app=rows['keep-app']
        if app['State'].get('Running') is not True:raise EngineError("Keep mailbox is unavailable")
        command={'protocol':'keep.host-command.v1','install_id':self.enrollment.install_id,'epoch':self.enrollment.epoch,
            'request_id':self.request.request_id,'verb':verb,'payload_sha256':self.request.payload_sha256,
            'credential_version':self.request.credential_version,**extra}
        reply=verify(self.enrollment,self.runner.run(self.plans.mailbox(app['Id'],verb,signed(self.enrollment,command))))
        exact_fields(reply,('protocol','install_id','epoch','request_id','verb','ok','owner_id','credential_version',
                            'config_generation','gate','drained','version'))
        if (reply['protocol']!='keep.host-result.v1' or reply['install_id']!=self.enrollment.install_id
                or reply['epoch']!=self.enrollment.epoch or reply['request_id']!=self.request.request_id
                or reply['verb']!=verb or reply['ok'] is not True or reply['owner_id']!=self.enrollment.owner_id
                or type(reply['credential_version']) is not int
                or verb in ('claim','revalidate','drain') and reply['credential_version']!=self.request.credential_version
                or not isinstance(reply['config_generation'],str) or not HASH.fullmatch(reply['config_generation'])):
            raise EngineError("Current owner or mailbox authority changed")
        from private_store import Journal
        committed = any(row['phase'] in ('committed','recovery-committed') for row in
                        Journal(self.paths,self.profile.state,self.request.request_id,self.request.payload_sha256).records())
        generation=self.operation/'app-generation.json'
        value=canonical({'generation':reply['config_generation']})
        if generation.exists():
            if (not committed or verb in ('claim','revalidate','drain')) and self.paths.read(generation)!=value:
                raise EngineError("Application configuration changed during maintenance")
        else:self.paths.publish(generation,value)
        return reply

    def publish_status(self,request,record):
        self.bind(request)
        from private_store import Journal
        records=Journal(self.paths,self.profile.state,request.request_id,request.payload_sha256).records()
        if not records or record not in records:
            raise EngineError('Progress is not a durable original journal record')
        rows=self.discover(images={request.expected.image_id,request.target.image_id} if request.target else {request.expected.image_id})
        if rows['keep-app']['State'].get('Running') is not True:
            if record['phase'] in ('committed','recovery-committed','success','recovered','failed'):
                raise EngineError('Final progress delivery is unavailable')
            # During the verified service stop, only the host journal can be
            # updated. The next live mirror may safely skip intermediate phases.
            return None
        # Send the exact original sequence/phase, never host paths or details.
        reply=self.mailbox('status',progress=parse_json(public_status(self.enrollment,request,
            sequence=record['sequence'],phase=record['phase'],
            result_code='complete' if record['phase']=='success' else 'recovered' if record['phase']=='recovered' else None)))
        self.paths.publish(self.operation/'app-progress-receipt.json',canonical({
            'request_id':request.request_id,'payload_sha256':request.payload_sha256,
            'sequence':record['sequence'],'phase':record['phase']}),overwrite=True)
        return reply

    def revalidate_authority(self,request,profile):
        self.bind(request)
        if self.wall_time()>=request.expires_at:raise EngineError("Unstarted maintenance request expired")
        self.mailbox('claim');self.mailbox('revalidate')

    def assert_runtime(self,expected,profile):
        rows=self.discover(images={expected.image_id});self.image(expected)
        if any(row['State'].get('Running') is not True for row in rows.values()):raise EngineError("Both Keep services must be running before cutover")
        self.no_foreign_writers(tuple(row['Id'] for row in rows.values()))

    def assert_configuration_unchanged(self,profile):
        recorded=parse_json(self.paths.read(self.configuration_record))
        actual={str(path):file_digest(self.paths,path,limit=MAX_CONFIG) for path in self.config_paths}
        if actual!=recorded:raise EngineError("Host installation configuration changed")

    def resolve_published_release(self,target):
        if tuple(map(int,target.version.split('.')))<=tuple(map(int,self.request.expected.version.split('.'))):
            raise EngineError("Automatic installation cannot downgrade or reinstall the current version")
        return self.resolver.resolve(target)

    def pull_and_verify(self,target):
        self.assert_daemon();self.runner.run(self.plans.pull(target));self.image(target)

    def close_gate_and_drain(self,request):
        reply=self.mailbox('drain')
        if reply['gate']!='closed' or reply['drained'] is not True:raise EngineError("Keep did not finish draining active work")

    def stop_and_verify_both(self,profile):
        allowed={self.request.expected.image_id}
        if self.request.target:allowed.add(self.request.target.image_id)
        self.discover(images=allowed);self.runner.run(self.plans.stop())
        rows=self.discover(images=allowed)
        if any(row['State'].get('Running') is not False or row['State'].get('Restarting') is not False
               or row['State'].get('Status') not in ('exited','created') for row in rows.values()):
            raise EngineError("Both Keep services are not safely stopped")
        self.no_foreign_writers()

    def stopped_proof(self):
        rows=self.discover(images={self.request.expected.image_id,self.request.target.image_id} if self.request.target else {self.request.expected.image_id})
        if any(row['State'].get('Running') is not False or row['State'].get('Restarting') is not False for row in rows.values()):
            raise EngineError("Stopped services are required for data access")
        self.no_foreign_writers()
        return {'daemon_id':self.profile.daemon_id,'project':self.profile.project,'volume':self.profile.volume,
                'services':{name:'stopped' for name in SERVICES}}

    def helper(self,purpose):
        if purpose not in ('snapshot','preserve','prepare-restore','restore','upload'):raise EngineError("Data helper purpose is not allowed")
        self.stopped_proof();metadata=self.image(self.request.expected)
        path=self.operation/('helper-'+purpose+'.json')
        if path.exists():
            record=parse_json(self.paths.read(path));cid=record.get('container_id')
            if record.get('source_sha256')!=self.source_sha:raise EngineError("Original helper source identity changed")
        else:
            name='keep-maintenance-'+self.enrollment.install_id.replace('-','')[:12]+'-'+self.request.request_id.replace('-','')[:12]+'-'+purpose
            args=(*self.plans.base,'create','--interactive','--name',name,
                '--label','io.keep.maintenance.install='+self.enrollment.install_id,
                '--label','io.keep.maintenance.operation='+self.request.request_id,'--label','io.keep.maintenance.purpose='+purpose,
                '--network','none','--read-only','--pull','never','--cap-drop','ALL','--security-opt','no-new-privileges:true',
                '--user','10001:10001','--memory','512m','--pids-limit','64',
                '--mount','type=volume,source='+self.profile.volume+',target=/app/data,volume-nocopy',
                '--tmpfs','/tmp:rw,noexec,nosuid,size=64m,mode=1777','--entrypoint','python',metadata['SelectedReference'],'-B','-c',self.source)
            intent=self.operation/('helper-'+purpose+'-intent.json')
            value=canonical({'name':name,'source_sha256':self.source_sha,'image_id':self.request.expected.image_id,
                'image_source':metadata['SelectedReference']})
            if intent.exists():
                if self.paths.read(intent)!=value:raise EngineError('Data helper creation intent changed')
                raise EngineError('Uncertain data helper creation must be reconciled before reuse')
            self.paths.publish(intent,value)
            cid=self.run('create fixed isolated data helper',args,limit=4096).decode().strip()
            if not CONTAINER.fullmatch(cid):raise EngineError("Docker returned an invalid helper identity")
            self.paths.publish(path,canonical({'container_id':cid,'source_sha256':self.source_sha}))
        row=self.inspect(cid,helper=True)
        self.validate_helper(row,purpose,stopped=True)
        return cid

    def validate_helper(self,row,purpose,*,stopped):
        labels=row.get('Labels') or {}
        intent=parse_json(self.paths.read(self.operation/('helper-'+purpose+'-intent.json')))
        if (self.canonical_image(row,[self.request.expected])!=self.request.expected.image_id
                or intent.get('image_id')!=self.request.expected.image_id or intent.get('source_sha256')!=self.source_sha
                or row.get('Source')!=intent.get('image_source') or labels.get('io.keep.maintenance.install')!=self.enrollment.install_id
                or labels.get('io.keep.maintenance.operation')!=self.request.request_id or labels.get('io.keep.maintenance.purpose')!=purpose
                or stopped and (row['State'].get('Running') is not False or row['State'].get('Restarting') is not False)
                or row.get('Network')!='none' or row.get('User')!='10001:10001' or row.get('Entrypoint')!=['python']
                or row.get('Command')!=['-B','-c',self.source]):raise EngineError("Data helper identity or state changed")
        self.mounts(row)

    def reconcile_helpers(self):
        """Stop only exact owned helpers left alive by an interrupted Docker CLI.

Creation is reconciled by full labels/source/image/command/isolation, then an
immutable ID record is published. Unknown helpers, duplicate purposes and
changed identity hold. No container or artifact is removed.
"""
        self.assert_daemon()
        ids=self.run('original operation helpers',(*self.plans.base,'ps','--all','--no-trunc',
            '--filter','label=io.keep.maintenance.install='+self.enrollment.install_id,
            '--filter','label=io.keep.maintenance.operation='+self.request.request_id,'--format','{{.ID}}'),limit=4096).decode().split()
        if len(ids)>5 or len(set(ids))!=len(ids):raise EngineError('Unexpected operation helper inventory')
        seen=set()
        for cid in ids:
            row=self.inspect(cid,helper=True);purpose=(row.get('Labels') or {}).get('io.keep.maintenance.purpose')
            if purpose not in ('snapshot','preserve','prepare-restore','restore','upload') or purpose in seen:
                raise EngineError('Unexpected or duplicated operation helper purpose')
            seen.add(purpose);self.validate_helper(row,purpose,stopped=False)
            path=self.operation/('helper-'+purpose+'.json')
            value=canonical({'container_id':cid,'source_sha256':self.source_sha})
            if path.exists():
                if self.paths.read(path)!=value:raise EngineError('Original helper container identity changed')
            else:
                intent=parse_json(self.paths.read(self.operation/('helper-'+purpose+'-intent.json')))
                if intent.get('image_id')!=self.request.expected.image_id or intent.get('source_sha256')!=self.source_sha:
                    raise EngineError('Helper has no matching durable creation intent')
                self.paths.publish(path,value)
            if row['State'].get('Running') is True or row['State'].get('Restarting') is True:
                stop=self.operation/('helper-stop-'+cid+'.json')
                if not stop.exists():self.paths.publish(stop,canonical({'container_id':cid,'purpose':purpose}))
                self.run('stop exact interrupted data helper',(*self.plans.base,'stop','--time','10',cid),timeout=30,limit=4096)
                self.validate_helper(self.inspect(cid,helper=True),purpose,stopped=True)

    def volume(self,operation,*,attempt=None,expected=None,columns=None):
        cid=self.helper(operation if operation!='prepare-restore' else 'prepare-restore')
        command={'operation':operation,'request_id':self.request.request_id,'attempt_id':attempt,
                 'expected_sha256':expected,'expected_bytes':None,'columns':columns}
        result=self.json('fixed volume operation',(*self.plans.base,'start','--attach','--interactive',cid),timeout=300,limit=65536,stdin=canonical(command))
        if result.get('schema')!='keep.volume-result.v1' or result.get('operation')!=operation or result.get('request_id')!=self.request.request_id:
            raise EngineError("Data helper result does not match this operation")
        self.stopped_proof()
        return cid,result

    def copy_out(self,cid,slot,destination,limit):
        if slot!='database.sqlite3':raise EngineError("Volume export slot is not allowed")
        source=cid+':/app/data/.maintenance/recovery/'+self.request.request_id+'/'+slot
        self.run('export exact private database snapshot',(*self.plans.base,'cp',source,str(destination)),timeout=300,
                 limit=4096,artifact=destination,artifact_limit=limit)
        self.paths.check(destination)

    def recovery(self):return RecoverySet(self.paths,self.operation/'recovery',self.request.request_id)

    def snapshot_matched_state(self,request,profile):
        self.stopped_proof();self.assert_configuration_unchanged(profile)
        root=self.paths.mkdir(self.operation/'recovery')
        metadata=self.image(request.expected)
        if shutil.disk_usage(root).free < metadata['Size']*2+MAX_DATABASE+64*1024**2:
            raise EngineError("Insufficient free space for matching recovery artifacts")
        cid,result=self.volume('snapshot')
        self.copy_out(cid,'database.sqlite3',root/'database.sqlite3',MAX_DATABASE)
        if file_digest(self.paths,root/'database.sqlite3',limit=MAX_DATABASE)!={key:result[key] for key in ('sha256','bytes')}:
            raise EngineError("Exported snapshot differs from the volume result")
        for index,path in enumerate(self.config_paths):self.paths.publish(root/f'config-{index}',self.paths.read(path,limit=MAX_CONFIG))
        archive=root/'image.tar'
        plan=self.plans.save_image(request.expected,root)
        self.runner.run(replace(plan,artifact=archive,artifact_limit=MAX_IMAGE))
        manifest=self.recovery().seal(request.expected,tuple(path.name for path in self.config_paths),
            daemon_id=profile.daemon_id,project=profile.project,volume=profile.volume)
        fingerprint=canonical(result['fingerprint'])
        self.paths.publish(root/'protected-fingerprint.json',fingerprint)
        self.paths.publish(self.operation/'recovery-identity.json',canonical({'manifest_sha256':hashlib.sha256(canonical(manifest)).hexdigest(),
            'fingerprint_sha256':hashlib.sha256(fingerprint).hexdigest()}))
        return request.request_id

    def manifest(self):
        value=parse_json(self.paths.read(self.operation/'recovery'/'manifest.json'))
        record=parse_json(self.paths.read(self.operation/'recovery-identity.json'))
        fingerprint=self.paths.read(self.operation/'recovery'/'protected-fingerprint.json')
        if record!={'manifest_sha256':hashlib.sha256(canonical(value)).hexdigest(),'fingerprint_sha256':hashlib.sha256(fingerprint).hexdigest()}:
            raise EngineError("Matching recovery manifest identity changed")
        return value

    def verify_matched_recovery(self,recovery,expected,profile):
        if recovery!=self.request.request_id or self.recovery().verify(self.manifest())!=expected:
            raise EngineError("Matching recovery set belongs to another operation/image")

    def apply_configuration(self,identity,*,restore=False):
        paths=self.config_paths
        if restore:
            manifest=self.manifest();self.recovery().verify(manifest)
            data=[self.paths.read(self.operation/'recovery'/f'config-{i}',limit=MAX_CONFIG) for i in range(len(paths))]
        else:
            self.assert_configuration_unchanged(self.profile)
            data=[env_image(self.paths.read(path),identity) if path==self.profile.env_file
                  else (identity.version+'\n').encode() if path.name=='VERSION' else self.paths.read(path) for path in paths]
        intent=self.operation/('configuration-restore-intent.json' if restore else 'configuration-activation-intent.json')
        if not intent.exists():self.paths.publish(intent,canonical({str(path):hashlib.sha256(body).hexdigest() for path,body in zip(paths,data)}))
        for path,body in zip(paths,data):
            if self.paths.read(path)!=body:self.paths.publish(path,body,overwrite=True)
        self.paths.publish(self.configuration_record,canonical({str(path):file_digest(self.paths,path,limit=MAX_CONFIG) for path in paths}),overwrite=True)

    def activate_both_paused(self,target,profile):
        self.stopped_proof();self.image(target)
        self.apply_configuration(target)
        override=self.operation/'activate.json'
        self.paths.publish(override,canonical({'services':{name:{'image':target.reference} for name in SERVICES}}))
        self.runner.run(self.plans.activate(override))
        self.wait_healthy(target)
        reply=self.mailbox('status')
        if reply['gate']!='closed' or reply['drained'] is not True:raise EngineError("Activated services did not preserve the closed gate")

    def wait_healthy(self,image):
        deadline=self.monotonic()+300
        while True:
            rows=self.discover(images={image.image_id})
            if any(row['State'].get('Status') in ('dead','exited') for row in rows.values()):
                raise EngineError("A Keep service failed health verification")
            if all(row['State'].get('Running') is True and row['State'].get('Health')=='healthy' for row in rows.values()):return
            if self.monotonic()>=deadline:raise EngineError("Keep health verification timed out")
            self.sleep(1)

    def fingerprint_running(self,columns):
        app=self.containers['keep-app'];command={'operation':'fingerprint','request_id':self.request.request_id,
            'attempt_id':None,'expected_sha256':None,'expected_bytes':None,'columns':columns}
        result=self.json('read protected database fingerprints',(*self.plans.base,'exec','--interactive',app['Id'],
            'python','-B','-c',self.source),timeout=60,limit=65536,stdin=canonical(command))
        if result.get('schema')!='keep.volume-result.v1' or result.get('request_id')!=self.request.request_id:
            raise EngineError("Fingerprint observation is invalid")
        return result['fingerprint']

    def verify_both_and_protected_data(self,image,profile):
        self.image(image);self.wait_healthy(image);self.assert_configuration_unchanged(profile)
        reply=self.mailbox('status')
        if reply['gate']!='closed' or reply['drained'] is not True or reply['version']!=image.version:
            raise EngineError("Keep is not safely paused on the verified version")
        baseline=parse_json(self.paths.read(self.operation/'recovery'/'protected-fingerprint.json'))
        columns={table:value['columns'] for table,value in baseline.items()}
        if self.fingerprint_running(columns)!=baseline:raise EngineError("Protected data differs from the pre-cutover snapshot")

    def verify_committed_runtime(self,image,profile):
        self.image(image);self.wait_healthy(image);self.assert_configuration_unchanged(profile)
        if self.mailbox('status')['version']!=image.version:raise EngineError("Committed application version changed")
        self.fingerprint_running(None)  # Integrity check; legitimate new rows are not compared with old data.

    def open_gate_and_verify(self,request):
        from private_store import Journal
        journal=Journal(self.paths,self.profile.state,request.request_id,request.payload_sha256)
        if journal.records()[-1]['phase'] not in ('committed','recovery-committed'):
            raise EngineError("Admission cannot open before the durable host commit")
        reply=self.mailbox('complete')
        if reply['gate']!='open':raise EngineError("Admission did not reopen")

    def abort_gate_without_cutover(self,request):
        self.bind(request)
        self.assert_runtime(request.expected,self.profile);self.assert_configuration_unchanged(self.profile)
        if self.mailbox('abort')['gate']!='open':raise EngineError("Pre-cutover gate remains held")

    def reconcile(self,request,records,profile):
        self.bind(request)
        if any(row['phase'] in ('committed','recovery-committed','success','recovered') for row in records):
            raise EngineError("Committed database may not be rolled back")
        self.reconcile_helpers()
        self.discover(images={request.expected.image_id,request.target.image_id} if request.target else {request.expected.image_id})
        self.recovery().verify(self.manifest())
        recorded=parse_json(self.paths.read(self.configuration_record))
        permitted={}
        for name in ('configuration-activation-intent.json','configuration-restore-intent.json'):
            intent=self.operation/name
            if intent.exists():
                for path,digest in parse_json(self.paths.read(intent)).items():permitted.setdefault(path,set()).add(digest)
        for path in self.config_paths:
            digest=file_digest(self.paths,path,limit=MAX_CONFIG)
            if digest!=recorded.get(str(path)) and digest['sha256'] not in permitted.get(str(path),set()):
                raise EngineError("External host configuration change requires local review")

    def preserve_failed_state(self,request,profile):
        self.stopped_proof()
        self.attempt=str(uuid.uuid4())
        failed=self.paths.mkdir(self.operation/('failed-'+self.attempt))
        for index,path in enumerate(self.config_paths):self.paths.publish(failed/f'config-{index}',self.paths.read(path))
        self.paths.publish(failed/'images.json',canonical({name:row['Image'] for name,row in self.containers.items()}))
        _,result=self.volume('preserve',attempt=self.attempt)
        self.paths.publish(failed/'volume-preservation.json',canonical(result))
        self.paths.publish(self.operation/'preservation.json',canonical({'attempt_id':self.attempt}),overwrite=True)

    def restore_matched_database_config_and_image(self,request,profile):
        manifest=self.manifest();plan=self.recovery().restoration_plan(manifest,current_stop_proof=self.stopped_proof())
        if not (self.operation/'preservation.json').exists():raise EngineError("Failed-state preservation is incomplete")
        archive=self.operation/'recovery'/'image.tar'
        self.run('load exact verified prior image',(*self.plans.base,'image','load','--input',str(archive)),timeout=900,limit=65536)
        metadata=self.image(request.expected)
        cid,prepared=self.volume('prepare-restore')
        expected={key:manifest['database'][key] for key in ('sha256','bytes')}
        if prepared['snapshot'] is None:
            upload=self.helper('upload')
            command={'operation':'upload','request_id':request.request_id,'attempt_id':None,
                     'expected_sha256':expected['sha256'],'expected_bytes':expected['bytes'],'columns':None}
            source=self.operation/'recovery'/'database.sqlite3'
            result=parse_json(self.runner.run(Plan('upload exact private snapshot',(*self.plans.base,'start','--attach','--interactive',upload),
                300,65536,canonical(command)+b'\n',None,0,source,MAX_DATABASE)))
            if {key:result[key] for key in ('sha256','bytes')}!=expected:raise EngineError('Reuploaded snapshot did not match')
        elif prepared['snapshot']!=expected:raise EngineError('Existing volume snapshot differs from the sealed host backup')
        _,result=self.volume('restore',expected=manifest['database']['sha256'])
        if result['sha256']!=manifest['database']['sha256']:raise EngineError("Restored database does not match the original snapshot")
        self.apply_configuration(request.expected,restore=True)
        override=self.operation/'restore.json'
        value=canonical({'services':{name:{'image':metadata['SelectedReference']} for name in SERVICES}})
        if override.exists():
            if self.paths.read(override)!=value:raise EngineError('Original restore configuration changed')
        else:self.paths.publish(override,value)
        self.runner.run(self.plans.activate(override));self.wait_healthy(request.expected)


def create_docker_adapter(paths,profile,enrollment,*,mailbox=None,resolver=None,runner=None):
    """Fixed platform gate; no silent POSIX fallback on native Windows."""
    if os.name=='nt':raise EngineError('Native Windows maintenance is not qualified')
    factory=mailbox.adapter_factory if mailbox else PosixDockerAdapter
    adapter=factory(paths,profile,enrollment,
        runner=runner or (mailbox.runner if mailbox else None),
        resolver=resolver or (mailbox.resolver if mailbox else None))
    if mailbox:
        adapter.known_identities.update(mailbox.adapter.known_identities)
    return adapter
