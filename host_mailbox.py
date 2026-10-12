"""Fixed Docker-exec host enrollment, observations and original request mailbox.

No daemon/network work happens on import. The injected runner is useful for
offline proof; production uses the enrolled local context and fixed app shim.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import uuid

from docker_adapter import INSPECT_IMAGE, PosixDockerAdapter
from host_engine import EngineError
from maintenance_protocol import (Enrollment, HASH, OWNER, VERSION, ImageIdentity,
    canonical, canonical_uuid, exact_fields, parse_json, signed, verify, verify_request)
from recovery_set import MAX_CONFIG, file_digest


@dataclass(frozen=True)
class Observation:
    image: ImageIdentity
    hello: dict
    configuration: dict
    containers: dict


class HostMailbox:
    def __init__(self,paths,profile,enrollment=None,*,runner=None,resolver=None,adapter_factory=PosixDockerAdapter):
        self.paths,self.profile,self.enrollment=paths,profile.validate(paths),enrollment
        self.adapter_factory=adapter_factory
        self.adapter=adapter_factory(paths,profile,enrollment,runner=runner,resolver=resolver)
        self.runner,self.resolver=self.adapter.runner,self.adapter.resolver
        self.verified_images={};self.verified_targets=set();self.pending_envelopes={};self.operation_adapter=None

    def _hello(self,data,*,allow_unenrolled=False):
        if self.enrollment is None:
            value=parse_json(data)
        else:
            envelope=parse_json(data)
            if allow_unenrolled and isinstance(envelope,dict) and envelope.get('enrolled') is False:
                value=envelope
            else:value=verify(self.enrollment,data)
        exact_fields(value,('protocol','owner_id','credential_version','owner_active','config_generation',
            'version','supported','enrolled','pending'))
        if (value['protocol']!='keep.app-hello.v1' or not isinstance(value['owner_id'],str)
                or not OWNER.fullmatch(value['owner_id']) or type(value['credential_version']) is not int
                or value['credential_version']<0 or type(value['owner_active']) is not bool
                or type(value['supported']) is not bool or type(value['enrolled']) is not bool
                or not isinstance(value['config_generation'],str) or not HASH.fullmatch(value['config_generation'])
                or not isinstance(value['version'],str) or not VERSION.fullmatch(value['version'])
                or self.enrollment is None and value['enrolled'] is not False
                or self.enrollment and value['owner_id']!=self.enrollment.owner_id
                or not value['owner_active'] or not value['supported']):
            raise EngineError('Current owner or fixed application layout is unavailable')
        if not value['enrolled'] and value['pending'] is not None:
            raise EngineError('Unenrolled application returned a request')
        return value

    def _configuration(self):
        value={str(path):file_digest(self.paths,path,limit=MAX_CONFIG) for path in self.adapter.config_paths}
        path=self.profile.state/'configuration.json'
        if path.exists() or path.is_symlink():
            if parse_json(self.paths.read(path))!=value:raise EngineError('Host installation configuration changed')
        return value

    def probe(self,*,allow_unenrolled=False):
        rows=self.adapter.discover()
        self.adapter.no_foreign_writers(tuple(row['Id'] for row in rows.values()))
        if any(row['State'].get('Running') is not True or row['State'].get('Health')!='healthy' for row in rows.values()):
            raise EngineError('Both Keep services must be running and healthy')
        architecture=self.adapter.run('native engine architecture',(*self.adapter.plans.base,'info','--format','{{.Architecture}}'),limit=4096).strip()
        arch={b'amd64':'amd64',b'x86_64':'amd64',b'arm64':'arm64',b'aarch64':'arm64'}.get(architecture)
        if arch is None:raise EngineError('Docker architecture is unsupported')
        metadata=self.adapter.json('current native image selection',(*self.adapter.plans.base,'image','inspect',
            '--platform','linux/'+arch,'--format',INSPECT_IMAGE,rows['keep-app']['Image']),limit=65536)
        labels=metadata.get('Labels') if isinstance(metadata,dict) else None
        version=labels.get('org.opencontainers.image.version') if isinstance(labels,dict) else None
        if not isinstance(version,str) or not VERSION.fullmatch(version):raise EngineError('Current image release is invalid')
        cache=(metadata.get('Id'),version,arch,labels.get('org.opencontainers.image.revision'))
        image=self.verified_images.get(cache)
        if image is None:
            image=self.resolver.resolve_version(version,arch)
            self.adapter.image(image)
            self.verified_images[cache]=image
        # Cached registry proof never replaces current daemon/topology/config,
        # source/native descriptor or local image configuration verification.
        self.adapter.image(image)
        rows=self.adapter.discover(images={image.image_id})
        hello=self._hello(self.runner.run(self.adapter.plans.mailbox(rows['keep-app']['Id'],'hello')),
            allow_unenrolled=allow_unenrolled)
        if hello['version']!=image.version:raise EngineError('Application and selected image versions differ')
        return Observation(image,hello,self._configuration(),{service:row['Id'] for service,row in rows.items()})

    def enroll(self,enrollment,observation):
        if not isinstance(enrollment,Enrollment) or enrollment.owner_id!=observation.hello.get('owner_id'):
            raise EngineError('Enrollment owner changed')
        self.enrollment=self.adapter.enrollment=enrollment
        current=self.probe(allow_unenrolled=True)
        if (current.image!=observation.image or current.configuration!=observation.configuration
                or current.containers!=observation.containers or any(current.hello[field]!=observation.hello[field]
                    for field in ('owner_id','credential_version','config_generation','version'))):
            raise EngineError('Enrollment observation changed')
        challenge=str(uuid.uuid4())
        value={'protocol':'keep.enrollment.v1','install_id':enrollment.install_id,'owner_id':enrollment.owner_id,
            'epoch':enrollment.epoch,'key':enrollment.key.hex(),'challenge':challenge,'expected':observation.image.as_dict()}
        reply=verify(enrollment,self.runner.run(self.adapter.plans.mailbox(current.containers['keep-app'],'enroll',canonical(value))))
        exact_fields(reply,('protocol','install_id','owner_id','epoch','challenge'))
        if reply!={'protocol':'keep.enrolled.v1','install_id':enrollment.install_id,'owner_id':enrollment.owner_id,
                'epoch':enrollment.epoch,'challenge':challenge}:raise EngineError('Enrollment challenge does not match')
        confirmed=self.probe()
        if (confirmed.image!=current.image or confirmed.configuration!=current.configuration or confirmed.containers!=current.containers
                or not confirmed.hello['enrolled'] or any(confirmed.hello[field]!=current.hello[field]
                    for field in ('owner_id','credential_version','config_generation','version'))):
            raise EngineError('Enrollment activation observation changed')
        return confirmed

    def advisory(self,target=None,active_request_id=None):
        if self.enrollment is None:raise EngineError('Host is not enrolled')
        current=self.probe()
        if active_request_id is not None:canonical_uuid(active_request_id)
        if target is not None:
            target=ImageIdentity.from_dict(target.as_dict())
            if target.architecture!=current.image.architecture or tuple(map(int,target.version.split('.')))<=tuple(map(int,current.image.version.split('.'))):
                raise EngineError('Advertised release does not match the current installation')
            marker=canonical(target.as_dict())
            if marker not in self.verified_targets:
                if self.resolver.resolve(target)!=target:raise EngineError('Advertised release identity changed')
                self.verified_targets.add(marker)
        value={'protocol':'keep.host-advisory.v1','install_id':self.enrollment.install_id,'epoch':self.enrollment.epoch,
            'target':target.as_dict() if target else None,'host_active_request':active_request_id}
        return self._hello(self.runner.run(self.adapter.plans.mailbox(current.containers['keep-app'],'hello',signed(self.enrollment,value))))

    def poll(self):
        observed=self.probe();pending=observed.hello['pending']
        if pending is None:return None
        data=canonical(pending);request=verify_request(self.enrollment,data)
        if request.expected!=observed.image or request.credential_version!=observed.hello['credential_version']:
            raise EngineError('Pending request differs from the current authority or image')
        self.pending_envelopes[request.request_id]=data
        return request

    def queue(self,operation='install',*,request_id):
        """Trusted local operator path; caller durably retains UUID first.

        No automatic transport retry or generated replacement UUID. Follow an
        uncertain reply with ordinary signed polling/reconciliation.
        """
        if self.enrollment is None or operation not in ('install','restart'):
            raise EngineError('Local operation is unavailable')
        canonical_uuid(request_id)
        observed=self.probe()
        value={'protocol':'keep.host-queue.v1','install_id':self.enrollment.install_id,
            'epoch':self.enrollment.epoch,'request_id':request_id,'operation':operation}
        reply=verify(self.enrollment,self.runner.run(self.adapter.plans.mailbox(
            observed.containers['keep-app'],'queue',signed(self.enrollment,value))))
        exact_fields(reply,('protocol','install_id','epoch','request_id','operation','state'))
        if (reply['protocol']!='keep.host-queued.v1' or reply['install_id']!=self.enrollment.install_id
                or type(reply['epoch']) is not int or reply['epoch']!=self.enrollment.epoch
                or reply['request_id']!=request_id or reply['operation']!=operation
                or reply['state'] not in ('queued','claimed','completed','aborted')):
            raise EngineError('Local queue result does not match original request')
        return reply

    def request_envelope(self,request):
        data=self.pending_envelopes.get(request.request_id)
        if data is None or self.accepted_request(data)!=request:raise EngineError('Original polled request is unavailable')
        return data

    def accepted_request(self,data):
        # Callers may use this historical verifier ONLY for an exact retained
        # accepted request plus its matching durable private operation journal.
        value=verify(self.enrollment,data)
        issued=value.get('issued_at') if isinstance(value,dict) else None
        request=verify_request(self.enrollment,data,now=issued)
        if canonical(parse_json(data))!=data:raise EngineError('Original request encoding is not canonical')
        return request

    def command(self,request,verb,*,post_commit=False):
        return self._operation_adapter(request).mailbox(verb)

    def publish_status(self,request,record):
        return self._operation_adapter(request).publish_status(request,record)

    def _operation_adapter(self,request):
        if self.operation_adapter is None or self.operation_adapter.request!=request:
            self.operation_adapter=self.adapter_factory(self.paths,self.profile,self.enrollment,
                runner=self.runner,resolver=self.resolver)
            self.operation_adapter.known_identities.update(self.adapter.known_identities)
            self.operation_adapter.bind(request)
        return self.operation_adapter
