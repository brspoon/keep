#!/usr/bin/env python3
"""Execute real native Keep maintenance in an isolated Docker29 daemon.

Requires preloaded source-packaged Keep and exactly pinned tooling images. All
synthetic manifests are published only to the owned internal test registry. The
production adapter, command runner, signed mailbox and app barrier are used
unchanged; only release resolution and deterministic failure injection are local
test substitutions. Importing this file does not invoke Docker or the network.
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import replace
import hashlib
import http.client
import ipaddress
import json
import os
import platform
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import tarfile
import threading
import time
import uuid

def helper_source(script):
    """Fixed packaged layouts only, never a browser/operator module path."""
    parent = Path(script).resolve().parent
    packaged = parent / 'maintenance_host'
    if packaged.is_dir():
        return packaged
    return parent if (parent / 'docker_adapter.py').is_file() else parent.parent


def neutral_source(script):
    parent = Path(script).resolve().parent
    return parent if (parent/'maintenance_app.py').is_file() and (parent/'maintenance_mailbox.py').is_file() else parent.parent


HOST_SOURCE = helper_source(__file__)
NEUTRAL_SOURCE = neutral_source(__file__)
sys.path.insert(0, str(HOST_SOURCE))

from docker_adapter import INSPECT_CONTAINER, INSPECT_HELPER, PosixDockerAdapter
from host_cli import HostState, enroll, load_backend
from host_engine import BoundedRunner, EngineError, HostEngine, Plan
from host_mailbox import HostMailbox
from maintenance_protocol import ImageIdentity, canonical, canonical_uuid, parse_json
from private_store import Journal, Profile, create_private_paths
from helper_bundle import create_root, source_bundle, stage_bundle
from recovery_set import verify_docker_save

DRAFT = HOST_SOURCE
INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
TOOLING = [
 {'repository':'library/docker','index_digest':'sha256:5efed980cba3fc126cf54e21a5a6ff8849d05b6e0623d6e7612f48e9cd6cd17e',
  'native':{'amd64':'sha256:77759fdec1efef224ba7110ef7b5b3c6af6164ffaef5441d3beba059bde8b857','arm64':'sha256:c9da39e30475d7bf353436738239d02fb1c2a52a1c968322beccb6ec239707d8'}},
 {'repository':'library/registry','index_digest':'sha256:325b4b29b041e82803abeb703e201655e4e23ab83264ec1a7c9ddb0a5b14a6e0',
  'native':{'amd64':'sha256:3d527cee870ddd0fc8a31f99b2fdfb6451801a8dd4f5a92c1ec36dae24c14274','arm64':'sha256:16c9340cae30cbf9b5ced3f3e77340f3bf4064971685540f4257a0254069c6b2'}}]


FAILURE_CODES = frozenset(('validation_failed', 'command_failed', 'command_timeout',
    'command_unavailable', 'metadata_invalid', 'host_not_native', 'daemon_not_native',
    'tool_not_native', 'tool_identity_unavailable', 'registry_endpoint_invalid'))


class TrialError(RuntimeError):
    def __init__(self, message, *, code='validation_failed', returncode=None):
        super().__init__(message)
        self.code = code if code in FAILURE_CODES else 'validation_failed'
        self.returncode = returncode if type(returncode) is int and -255 <= returncode <= 255 else None


def require(value, message, *, code='validation_failed'):
    if not value:
        raise TrialError(message, code=code)


def failure_details(error):
    """Retain fixed source locations and literal errors, never process output."""
    names=('host_engine.py','docker_adapter.py','host_mailbox.py')
    literals=set()
    for name in names:
        tree=ast.parse((HOST_SOURCE/name).read_bytes())
        for node in ast.walk(tree):
            if (isinstance(node,ast.Call) and isinstance(node.func,ast.Name)
                    and node.func.id=='EngineError' and node.args
                    and isinstance(node.args[0],ast.Constant)
                    and isinstance(node.args[0].value,str)):
                literals.add(node.args[0].value)
    allowed={str((HOST_SOURCE/name).resolve()):name for name in names}
    allowed[str(Path(__file__).resolve())]=Path(__file__).name
    result=[];seen=set()
    while error is not None and id(error) not in seen and len(result)<8:
        seen.add(id(error));entry={'type':type(error).__name__,'frames':[]}
        if type(error) is EngineError and str(error) in literals:entry['literal']=str(error)
        trace=error.__traceback__
        while trace is not None:
            code=trace.tb_frame.f_code
            module=allowed.get(str(Path(code.co_filename).resolve()))
            if module and re.fullmatch('[A-Za-z_][A-Za-z_0-9]{0,80}',code.co_name):
                entry['frames'].append({'module':module,'function':code.co_name,'line':trace.tb_lineno})
                entry['frames']=entry['frames'][-12:]
            trace=trace.tb_next
        result.append(entry)
        error=error.__cause__ or (error.__context__ if not error.__suppress_context__ else None)
    return result


VOLUME_ERROR_TYPES=frozenset(('VolumeError','JSONDecodeError','OSError','FileNotFoundError','PermissionError',
    'FileExistsError','IsADirectoryError','NotADirectoryError','Error','DatabaseError','OperationalError',
    'IntegrityError','ValueError','TypeError','UnicodeDecodeError','MemoryError','OverflowError',
    'RecursionError','RuntimeError','AssertionError','Exception'))
VOLUME_ERROR_PREFIX=b'Fixed Keep volume operation failed '
MERGE_DIAGNOSTIC_STREAMS=('import subprocess,sys\n'
    'p=subprocess.Popen(sys.argv[1:],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n'
    'while body:=p.stdout.read(256):\n'
    ' sys.stdout.buffer.write(body);sys.stdout.buffer.flush()\n'
    'p.stdout.close();sys.exit(p.wait())\n')


def volume_error_diagnostic(body,source):
    """Discard every byte unless it is the fixed bounded worker diagnostic."""
    if not isinstance(body,bytes) or len(body)>1024 or not body.startswith(VOLUME_ERROR_PREFIX):return None
    line=body.removesuffix(b'\n')
    if b'\n' in line or b'\r' in line:return None
    try:value=parse_json(line[len(VOLUME_ERROR_PREFIX):],1024)
    except Exception:return None
    if (not isinstance(value,dict) or set(value)!={'type','lines'} or not isinstance(value['type'],str) or value['type'] not in VOLUME_ERROR_TYPES
            or not isinstance(value['lines'],list) or len(value['lines'])>8
            or any(type(number) is not int or not 1<=number<=len(source.splitlines()) for number in value['lines'])):return None
    return value


def startup_error_codes(value):
    """Fixed classifications only; never return or retain runtime error text."""
    if value is None or value=='':return []
    if type(value) is not str:return ['unavailable']
    try:
        if len(value.encode('utf-8'))>4096:return ['unavailable']
    except UnicodeError:return ['unavailable']
    text=value.lower()
    groups=(('oci_runtime',('oci runtime','runc create','failed to create task')),
            ('cgroup',('cgroup',)),('pids_limit',('pids.max','pids limit','pids controller')),
            ('memory_limit',('memory.max','memory limit','memory controller','memory cgroup')),
            ('permission',('permission denied','operation not permitted')))
    codes=[code for code,tokens in groups if any(token in text for token in tokens)]
    return codes or ['unclassified']


def snapshot_helper_diagnostic(adapter):
    """Read only the original verified helper, before trial cleanup."""
    unavailable={'available':False}
    try:
        original=parse_json(adapter.paths.read(adapter.operation/'helper-snapshot.json',limit=4096))
        require(isinstance(original,dict) and set(original)=={'container_id','source_sha256'}
            and original['source_sha256']==adapter.source_sha
            and re.fullmatch('[a-f0-9]{64}',original['container_id'] or ''), 'Original snapshot diagnostic identity differs')
        identifier=original['container_id']
        selected=adapter.inspect(identifier,helper=True)
        require(selected.get('Id')==identifier,'Snapshot diagnostic selected another helper')
        adapter.validate_helper(selected,'snapshot',stopped=False)
        format=INSPECT_HELPER[:-1]+(',"OpenStdin":{{json .Config.OpenStdin}},"Tty":{{json .Config.Tty}},'
            '"ExitCode":{{json .State.ExitCode}},"OOMKilled":{{json .State.OOMKilled}},'
            '"ErrorPresent":{{if index .State "Error"}}true{{else}}false{{end}},"StartupError":{{json (index .State "Error")}}}')
        observed=adapter.json('verified snapshot diagnostic state',(*adapter.plans.base,'inspect','--format',format,identifier),limit=65536)
        require(observed.get('Id')==identifier,'Snapshot diagnostic identity changed')
        adapter.validate_helper(observed,'snapshot',stopped=False)
        startup_errors=startup_error_codes(observed.pop('StartupError',None))
        require(all(type(observed.get(key)) is bool for key in ('OpenStdin','Tty','OOMKilled','ErrorPresent'))
            and type(observed.get('ExitCode')) is int and 0<=observed['ExitCode']<=255,'Snapshot diagnostic fields differ')
        # The fixed wrapper preserves the CLI's process group and forwards both
        # log channels into the existing bounded runner. No shell or raw log is
        # recorded; malformed, foreign or excessive output is discarded.
        arguments=(sys.executable,'-B','-c',MERGE_DIAGNOSTIC_STREAMS,*adapter.plans.base,'logs','--tail','1',identifier)
        body=adapter.runner.run(Plan('read fixed snapshot helper diagnostic',arguments,30,1024))
        return {'available':True,'open_stdin':observed['OpenStdin'],'tty':observed['Tty'],
            'exit_code':observed['ExitCode'],'oom_killed':observed['OOMKilled'],'error_present':observed['ErrorPresent'],
            'startup_error_codes':startup_errors,
            'worker':volume_error_diagnostic(body,adapter.source)}
    except Exception:return unavailable


SERVICE_ERROR_TYPES=VOLUME_ERROR_TYPES|frozenset(('MaintenanceError','StorageError','ProtocolError',
    'AttributeError','NameError','KeyError','ImportError','ModuleNotFoundError','SyntaxError'))
SERVICE_SOURCE_FILES=frozenset(('app.py','onboarding.py','maintenance_app.py','maintenance_mailbox.py',
    'maintenance_protocol.py','private_store.py','maintenance_trial_fixture.py','maintenance_portable_fixture.py'))


def service_log_diagnostic(body,sources):
    """Extract only the latest typed traceback and verified source locations."""
    if not isinstance(body,bytes) or len(body)>4096:return None
    try:lines=body.decode('utf-8').splitlines()
    except UnicodeError:return None
    frames=None;result=None
    for line in lines:
        if line=='Traceback (most recent call last):':
            frames=[];continue
        if frames is None:continue
        frame=re.fullmatch(r'  File "([^"\r\n]+)", line ([0-9]{1,5})(?:, in [^\r\n]*)?',line)
        if frame:
            source=sources.get(frame[1]);number=int(frame[2])
            if source and type(source.get('lines')) is int and 1<=number<=source['lines']:
                frames.append({'module':source['module'],'line':number});frames=frames[-8:]
            continue
        error=re.fullmatch(r'(?:[A-Za-z_][A-Za-z_0-9]*\.)*([A-Za-z_][A-Za-z_0-9]*)(?::.*)?',line)
        if error and error[1] in SERVICE_ERROR_TYPES:
            result={'type':error[1],'frames':frames};frames=None
    return result


def health_error_codes(value):
    if type(value) is not str:return ['unavailable']
    if not value:return []
    try:
        if len(value.encode('utf-8'))>4096:return ['unavailable']
    except UnicodeError:return ['unavailable']
    groups=(('connection_refused','ConnectionRefusedError'),('http_error','HTTPError'),
            ('missing_file','FileNotFoundError'),('permission','PermissionError'),('assertion_failure','AssertionError'))
    codes=[code for code,token in groups if token in value]
    return codes or startup_error_codes(value)


def service_source_locations(trial):
    result={}
    for name in sorted(SERVICE_SOURCE_FILES):
        record=trial.report.get('source_files',{}).get(name)
        if not isinstance(record,dict):continue
        body=trial.paths.read(trial.root/'image-source'/name,limit=1048576)
        require(hashlib.sha256(body).hexdigest()==record.get('fixture_sha256'),'Service diagnostic source differs')
        result['/app/'+name]={'module':name,'lines':len(body.splitlines())}
    return result


def paired_service_diagnostic(trial,adapter,request,original_ids):
    """Read only an exact original pair or this request's recreated pair."""
    try:
        require(set(original_ids)=={'keep-app','keep-digest'} and len(set(original_ids.values()))==2 and all(isinstance(value,str)
            and re.fullmatch('[a-f0-9]{64}',value) for value in original_ids.values()),'Original service identities unavailable')
        identities={request.expected.image_id}
        if request.target:identities.add(request.target.image_id)
        rows=adapter.discover(images=identities)
        require(set(rows)=={'keep-app','keep-digest'},'Diagnostic service topology differs')
        base_files=tuple(str(path) for path in adapter.profile.compose_files)
        for service in ('keep-app','keep-digest'):
            selected=rows[service];identifier=selected['Id']
            require(isinstance(identifier,str) and re.fullmatch('[a-f0-9]{64}',identifier),'Diagnostic service identity differs')
            if identifier!=original_ids[service]:
                files=tuple((selected.get('Labels') or {}).get('com.docker.compose.project.config_files','').split(','))
                require(files in (base_files+(str(adapter.operation/'activate.json'),),
                    base_files+(str(adapter.operation/'restore.json'),)),'Recreated service belongs to another request')
        sources=service_source_locations(trial)
        result=[]
        for service in ('keep-app','keep-digest'):
            selected=rows[service];identifier=selected['Id']
            format=INSPECT_CONTAINER[:-1]+(',"ExitCode":{{json .State.ExitCode}},"OOMKilled":{{json .State.OOMKilled}},'
                '"StartupError":{{json (index .State "Error")}},'
                '"HealthExitCode":{{$code := -1}}{{with index .State "Health"}}{{range index . "Log"}}{{$code = .ExitCode}}{{end}}{{end}}{{$code}},'
                '"HealthOutput":{{$text := ""}}{{with index .State "Health"}}{{range index . "Log"}}{{$text = .Output}}{{end}}{{end}}{{json $text}}}')
            observed=adapter.json('verified failed service state',(*adapter.plans.base,'inspect','--format',format,identifier),limit=65536)
            require(observed.get('Id')==identifier and all(observed.get(key)==selected.get(key)
                for key in ('Image','Source','Manifest','Labels','Mounts','Guard')),'Service diagnostic identity changed')
            adapter.mounts(observed)
            state=observed.get('State') or {}
            require(state.get('Status') in ('created','running','paused','restarting','removing','exited','dead')
                and type(state.get('Running')) is bool and type(state.get('Restarting')) is bool
                and state.get('Health') in (None,'starting','healthy','unhealthy')
                and type(observed.get('ExitCode')) is int and 0<=observed['ExitCode']<=255
                and type(observed.get('OOMKilled')) is bool and type(observed.get('HealthExitCode')) is int
                and -1<=observed['HealthExitCode']<=255,'Service diagnostic state differs')
            row={'service':service,'container_id':identifier,'status':state['Status'],'running':state['Running'],
                'restarting':state['Restarting'],'health':state.get('Health'),'exit_code':observed['ExitCode'],
                'oom_killed':observed['OOMKilled'],'startup_error_codes':startup_error_codes(observed.pop('StartupError',None)),
                'health_exit_code':observed['HealthExitCode'],'health_error_codes':health_error_codes(observed.pop('HealthOutput',None))}
            try:
                arguments=(sys.executable,'-B','-c',MERGE_DIAGNOSTIC_STREAMS,*adapter.plans.base,'logs','--tail','32',identifier)
                body=adapter.runner.run(Plan('read fixed failed service diagnostic',arguments,30,4096))
                row['traceback']=service_log_diagnostic(body,sources)
            except Exception:row['traceback']=None
            result.append(row)
        return {'available':True,'services':result}
    except Exception:return {'available':False}


DIND_ENTRYPOINT='/usr/local/bin/dockerd-entrypoint.sh'


def dind_arguments(registry=None):
    # An explicit first dockerd argument skips the vendor script's default TCP
    # listener injection while preserving its pinned Dind/cgroup startup wrapper.
    arguments=['dockerd','--host=unix:///trial-socket/docker.sock']
    if registry is not None:
        require(isinstance(registry,str) and re.fullmatch('keep-maintenance-native-[a-f0-9]{12}',registry),
            'Owned daemon registry identity differs')
        arguments+=['--registry-mirror=http://'+registry+'-registry:5000',
                    '--insecure-registry='+registry+'-registry:5000']
    return arguments


def dind_startup_matches(record,registry=None):
    config=record.get('Config') if isinstance(record,dict) else None
    return isinstance(config,dict) and config.get('Entrypoint')==[DIND_ENTRYPOINT] and config.get('Cmd')==dind_arguments(registry)


def pinned_tool_identity(inspected, tool, architecture):
    """Accept Docker's exact familiar/fully qualified approved repo spellings."""
    if inspected.get('Architecture') != architecture or inspected.get('Os') != 'linux':
        return False
    digest, native = tool['index_digest'], tool['native'][architecture]
    identifier = inspected.get('Id')
    if not isinstance(identifier, str) or not DIGEST.fullmatch(identifier):
        return False
    repository=tool['repository'];familiar=repository.removeprefix('library/')
    allowed={name+'@'+digest for name in (familiar,repository,'docker.io/'+repository,'index.docker.io/'+repository)}
    references = inspected.get('RepoDigests') or []
    if not isinstance(references, list) or not all(isinstance(value, str) for value in references):
        return False
    index_bound = bool(allowed.intersection(references))
    descriptor = inspected.get('Descriptor')
    if descriptor is not None:
        if (not isinstance(descriptor, dict)
                or not (descriptor.get('digest') == digest and descriptor.get('mediaType') in
                    (INDEX, 'application/vnd.docker.distribution.manifest.list.v2+json')
                    or descriptor.get('digest') == native and descriptor.get('mediaType') in
                    (MANIFEST, 'application/vnd.docker.distribution.manifest.v2+json'))):
            return False
        # Some daemon/client pairs retain a config Id alongside the selected
        # descriptor. That shape additionally needs the approved index name.
        return identifier == descriptor['digest'] if identifier in (digest, native) else index_bound
    return index_bound


def candidate_configuration(archive_path, inspected):
    """Derive the canonical config digest from actual Docker-save bytes."""
    require(isinstance(inspected,dict) and isinstance(inspected.get('Id'),str) and DIGEST.fullmatch(inspected['Id'])
        and inspected.get('Architecture') in ('amd64','arm64') and inspected.get('Os')=='linux'
        and isinstance(inspected.get('Config'),dict),'Candidate inspection is invalid')
    require(archive_path.stat().st_size<=32*1024**3,'Candidate export exceeded bound')
    with tarfile.open(archive_path,mode='r:') as archive:
        members={}
        for member in archive:
            require(len(members)<4096 and member.name not in members,'Candidate archive inventory invalid')
            members[member.name]=member
        def small(name,limit=524288):
            require(isinstance(name,str) and name in members,'Candidate metadata unavailable')
            member=members[name]
            require(member.isfile() and 0<member.size<=limit,'Candidate metadata exceeded bound')
            value=archive.extractfile(member).read(limit+1)
            require(len(value)==member.size,'Candidate metadata truncated')
            return value
        def blob(descriptor):
            require(isinstance(descriptor,dict) and isinstance(descriptor.get('digest'),str)
                and DIGEST.fullmatch(descriptor['digest']) and type(descriptor.get('size')) is int
                and 0<descriptor['size']<=524288,'Candidate descriptor invalid')
            digest=descriptor['digest']
            value=small('blobs/sha256/'+digest[7:])
            require(len(value)==descriptor['size'] and 'sha256:'+hashlib.sha256(value).hexdigest()==digest,'Candidate descriptor bytes differ')
            return parse_json(value,524288),digest
        if 'oci-layout' in members:
            layout=parse_json(small('oci-layout'))
            require(isinstance(layout,dict) and layout.get('imageLayoutVersion')=='1.0.0','Candidate OCI layout invalid')
            wrapper=parse_json(small('index.json'))
            require(isinstance(wrapper,dict) and type(wrapper.get('schemaVersion')) is int and wrapper['schemaVersion']==2
                and isinstance(wrapper.get('manifests'),list) and 1<=len(wrapper['manifests'])<=16,'Candidate OCI wrapper invalid')
            index_types=(INDEX,'application/vnd.docker.distribution.manifest.list.v2+json')
            native_types=(MANIFEST,'application/vnd.docker.distribution.manifest.v2+json')
            candidates=[]
            for root_descriptor in wrapper['manifests']:
                document,root_digest=blob(root_descriptor)
                require(isinstance(document,dict) and type(document.get('schemaVersion')) is int
                    and document['schemaVersion']==2 and document.get('mediaType') in index_types+native_types,
                    'Candidate OCI root invalid')
                root_type=document['mediaType']
                require(root_descriptor.get('mediaType',root_type)==root_type,'Candidate OCI root type differs')
                if 'platform' in root_descriptor:
                    platform_info=root_descriptor['platform']
                    require(isinstance(platform_info,dict) and platform_info.get('os')=='linux'
                        and platform_info.get('architecture')==inspected['Architecture'],'Candidate OCI root platform differs')
                native_digest,native_type=root_digest,root_type
                if root_type in index_types:
                    children=document.get('manifests')
                    require(isinstance(children,list) and 1<=len(children)<=16,'Candidate index inventory invalid')
                    require(all(isinstance(row,dict) and isinstance(row.get('platform'),dict) for row in children),
                        'Candidate native platform invalid')
                    selected=[row for row in children if row['platform'].get('os')=='linux'
                        and row['platform'].get('architecture')==inspected['Architecture']]
                    require(len(selected)==1,'Candidate native descriptor unavailable or ambiguous')
                    document,native_digest=blob(selected[0])
                    require(isinstance(document,dict) and type(document.get('schemaVersion')) is int
                        and document['schemaVersion']==2 and document.get('mediaType') in native_types,
                        'Candidate native manifest invalid')
                    native_type=document['mediaType']
                    require(selected[0].get('mediaType',native_type)==native_type,'Candidate native type differs')
                config_descriptor=document.get('config')
                require(isinstance(config_descriptor,dict) and config_descriptor.get('mediaType',
                    'application/vnd.oci.image.config.v1+json') in ('application/vnd.oci.image.config.v1+json',
                    'application/vnd.docker.container.image.v1+json'),'Candidate configuration descriptor invalid')
                configuration,digest=blob(config_descriptor)
                if inspected['Id'] in (root_digest,native_digest,digest):
                    candidates.append((configuration,digest,{root_digest:root_type,native_digest:native_type}))
            require(len(candidates)==1,'Candidate immutable graph unavailable or ambiguous')
            configuration,digest,descriptors=candidates[0]
            observed=inspected.get('Descriptor')
            if observed is not None:
                require(isinstance(observed,dict) and observed.get('digest') in descriptors
                    and observed.get('mediaType')==descriptors[observed['digest']],'Candidate live descriptor differs')
        else:
            manifests=parse_json(small('manifest.json'))
            require(isinstance(manifests,list) and len(manifests)==1 and isinstance(manifests[0],dict),
                'Candidate export must contain one image')
            raw=small(manifests[0]['Config'])
            digest='sha256:'+hashlib.sha256(raw).hexdigest()
            require(digest==inspected['Id'],'Candidate classic config identity differs')
            configuration=parse_json(raw,524288)
        require(isinstance(configuration,dict) and isinstance(configuration.get('config'),dict),'Candidate configuration invalid')
        config=configuration['config']
        require(isinstance(config.get('User'),str) and isinstance(config.get('Labels'),dict)
            and configuration.get('architecture')==inspected['Architecture'] and configuration.get('os')==inspected['Os']
            and config.get('User')==inspected['Config'].get('User')
            and config.get('Labels')==inspected['Config'].get('Labels'),'Candidate archive and live configuration differ')
        if 'RootFS' in inspected:
            actual=inspected['RootFS'];rootfs=configuration.get('rootfs')
            require(isinstance(actual,dict) and actual.get('Type')=='layers' and isinstance(actual.get('Layers'),list)
                and len(actual['Layers'])<=1024 and all(isinstance(value,str) and DIGEST.fullmatch(value) for value in actual['Layers'])
                and isinstance(rootfs,dict) and rootfs.get('type')=='layers' and rootfs.get('diff_ids')==actual['Layers'],
                'Candidate archive and live root filesystem differ')
        return digest


def run(argv, *, env=None, timeout=120, stdin=None, stdout=None):
    try:
        result = subprocess.run([str(arg) for arg in argv], stdin=stdin,
            stdout=stdout or subprocess.PIPE, stderr=subprocess.PIPE, env=env,
            timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        raise TrialError('Bounded trial command could not complete', code='command_timeout') from error
    except OSError as error:
        raise TrialError('Bounded trial command could not complete', code='command_unavailable') from error
    if result.returncode:
        raise TrialError('Trial command failed; preserve its private evidence',
            code='command_failed', returncode=result.returncode)
    return result.stdout


def validate_fixture_tmpfs(configuration):
    """Check the actual Compose parser result before creating any resources."""
    services=configuration.get('services') if isinstance(configuration,dict) else None
    require(isinstance(services,dict) and set(services)=={'keep-app','keep-digest'},
        'Parsed fixture services differ',code='metadata_invalid')
    for service in services.values():
        tmpfs=service.get('tmpfs') if isinstance(service,dict) else None
        require(tmpfs in (['/tmp:size=64m,mode=1777'],'/tmp:size=64m,mode=1777'),
            'Parsed fixture tmpfs differs',code='metadata_invalid')


def registry_resource_proof(proof):
    def checked(value):
        require(value, 'Owned registry endpoint proof differs', code='registry_endpoint_invalid')
    checked(isinstance(proof,dict) and set(proof)=={'project','network_id','container_id','image_id','members'})
    project=proof['project'];network_id=proof['network_id'];identifier=proof['container_id']
    checked(isinstance(project,str) and re.fullmatch(r'keep-maintenance-native-[a-f0-9]{12}',project))
    checked(all(isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) for value in (network_id,identifier)))
    checked(isinstance(proof['image_id'],str) and DIGEST.fullmatch(proof['image_id']))
    members=proof['members']
    checked(isinstance(members,list) and 1<=len(members)<=2
        and all(isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) for value in members)
        and len(set(members))==len(members)
        and identifier in members)


def owned_registry_address(proof, network, container):
    """Select IPv4 only from the exact owned internal bridge and pinned tool."""
    registry_resource_proof(proof)
    def checked(value):
        require(value, 'Owned registry endpoint proof differs', code='registry_endpoint_invalid')
    project=proof['project'];network_id=proof['network_id'];identifier=proof['container_id']
    members=proof['members']
    checked(isinstance(network,dict) and network.get('Id')==network_id and network.get('Name')==project
        and network.get('Internal') is True and network.get('Driver')=='bridge' and network.get('Scope')=='local'
        and (network.get('Labels') or {}).get('io.keep.maintenance.trial')==project)
    containers=network.get('Containers')
    checked(isinstance(containers,dict) and identifier in containers and set(containers)<=set(members))
    checked(isinstance(container,dict) and container.get('Id')==identifier
        and container.get('Image')==proof['image_id'] and container.get('State',{}).get('Running') is True
        and (container.get('Config',{}).get('Labels') or {}).get('io.keep.maintenance.trial')==project
        and container.get('Config',{}).get('Image')==TOOLING[1]['repository']+'@'+TOOLING[1]['index_digest'])
    attached=container.get('NetworkSettings',{}).get('Networks')
    checked(isinstance(attached,dict) and set(attached)=={project} and isinstance(attached[project],dict))
    endpoint=attached[project];member=containers[identifier]
    checked(isinstance(member,dict) and endpoint.get('NetworkID')==network_id
        and isinstance(endpoint.get('EndpointID'),str) and re.fullmatch('[a-f0-9]{64}',endpoint['EndpointID'])
        and member.get('EndpointID')==endpoint['EndpointID'] and member.get('Name')==project+'-registry')
    configurations=network.get('IPAM',{}).get('Config')
    checked(isinstance(configurations,list) and 1<=len(configurations)<=2)
    try:
        subnets=[ipaddress.ip_network(row['Subnet'],strict=True) for row in configurations if isinstance(row,dict)]
        selected=[subnet for subnet in subnets if isinstance(subnet,ipaddress.IPv4Network)]
        address=ipaddress.IPv4Address(endpoint.get('IPAddress'))
        private=[ipaddress.IPv4Network(value) for value in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
        checked(len(subnets)==len(configurations) and len(selected)==1)
        subnet=selected[0]
        checked(any(subnet.subnet_of(value) for value in private) and address in subnet
            and address not in (subnet.network_address,subnet.broadcast_address)
            and endpoint.get('IPAddress')==str(address) and type(endpoint.get('IPPrefixLen')) is int
            and endpoint['IPPrefixLen']==subnet.prefixlen and member.get('IPv4Address')==str(address)+'/'+str(subnet.prefixlen))
        for row in configurations:
            if row.get('Gateway'):
                checked(str(address)!=row['Gateway'])
    except (KeyError,TypeError,ValueError):
        raise TrialError('Owned registry endpoint proof differs',code='registry_endpoint_invalid') from None
    return str(address)


class RegistryGraph:
    """Trial-only owned registry; no credentials, proxies or external fallback."""
    def __init__(self, port, architecture):
        require(type(port) is int and 1 <= port <= 65535, 'Invalid fixture registry port')
        self.host, self.port, self.architecture = '127.0.0.1', port, architecture
        self.identities, self.configurations, self.configuration_bytes = {}, {}, {}

    @classmethod
    def owned(cls, architecture, proof, network, container):
        address=owned_registry_address(proof,network,container)
        result=cls(5000,architecture)
        result.host=address
        return result

    def request(self, method, path, data=None, content_type=None):
        require(path.startswith('/v2/brspoon/keep/') or path == '/v2/', 'Unscoped fixture registry path')
        connection = http.client.HTTPConnection(self.host, self.port, timeout=15)
        try:
            connection.request(method, path, body=data, headers={'Accept': INDEX+','+MANIFEST+','+'application/vnd.docker.distribution.manifest.v2+json',
                **({'Content-Type': content_type} if content_type else {})})
            response = connection.getresponse()
            require(response.status in (200, 201), 'Fixture registry response failed')
            body = response.read(1048577)
            require(len(body) <= 1048576, 'Fixture registry metadata exceeded bound')
            return body, response.getheader('Docker-Content-Digest')
        finally:
            connection.close()

    def blob(self, kind, digest):
        require(DIGEST.fullmatch(digest), 'Invalid fixture content digest')
        body, header = self.request('GET', '/v2/brspoon/keep/'+kind+'/'+digest)
        require('sha256:'+hashlib.sha256(body).hexdigest() == digest, 'Fixture content digest changed')
        if header:
            require(header == digest, 'Fixture digest header changed')
        return body

    def register(self, native_tag, version, revision):
        body, native = self.request('GET', '/v2/brspoon/keep/manifests/'+native_tag)
        require(native == 'sha256:'+hashlib.sha256(body).hexdigest(), 'Pushed native manifest changed')
        parsed = parse_json(body, 1048576)
        require(parsed.get('mediaType') in (MANIFEST, 'application/vnd.docker.distribution.manifest.v2+json'), 'Pushed fixture must be a native manifest')
        descriptor = {'mediaType': parsed['mediaType'], 'digest': native, 'size': len(body),
            'platform': {'os': 'linux', 'architecture': self.architecture}}
        index = canonical({'schemaVersion': 2, 'mediaType': INDEX, 'manifests': [descriptor]})
        digest = 'sha256:'+hashlib.sha256(index).hexdigest()
        _, received = self.request('PUT', '/v2/brspoon/keep/manifests/'+version, index, INDEX)
        require(received == digest, 'Fixture index publication changed')
        identity = ImageIdentity(digest, native, parsed['config']['digest'], version, revision, self.architecture)
        self.identities[identity.reference] = identity
        self.resolve(identity)
        return identity

    def resolve(self, identity):
        require(self.identities.get(identity.reference) == identity, 'Unknown trial-only release')
        index = parse_json(self.blob('manifests', identity.index_digest), 1048576)
        require(index.get('mediaType') == INDEX and len(index.get('manifests', [])) == 1, 'Trial release index changed')
        descriptor = index['manifests'][0]
        require(descriptor.get('digest') == identity.native_digest and descriptor.get('platform') == {'os':'linux','architecture':self.architecture}, 'Trial native selection changed')
        manifest_raw = self.blob('manifests', identity.native_digest)
        require(len(manifest_raw) == descriptor.get('size'), 'Trial native descriptor size changed')
        manifest = parse_json(manifest_raw, 1048576)
        require(manifest.get('config', {}).get('digest') == identity.image_id, 'Trial config identity changed')
        config_raw = self.blob('blobs', identity.image_id)
        require(len(config_raw) == manifest['config'].get('size'), 'Trial config descriptor size changed')
        self.configurations[identity.reference] = PosixDockerAdapter.configuration_proof(config_raw, identity)
        self.configuration_bytes[identity.reference] = config_raw
        return identity

    def resolve_version(self, version, architecture):
        require(architecture == self.architecture, 'Trial architecture changed')
        match = [image for image in self.identities.values() if image.version == version]
        require(len(match) == 1, 'Unknown fixture version')
        return self.resolve(match[0])

    def latest(self, architecture, installed_version):
        raise TrialError('Automatic discovery is not used by the native fixture')


class NoNetworkResolver:
    def __init__(self):
        self.configurations, self.configuration_bytes = {}, {}
    def resolve(self, identity):
        raise TrialError('Fresh recovery must not consult a registry or release cache')
    def resolve_version(self, version, architecture):
        raise TrialError('Fresh recovery must not consult a registry or release cache')


class ArchiveOnlyResolver(NoNetworkResolver):
    def __init__(self, paths, archive, identity):
        super().__init__()
        self.archive_proof=verify_docker_save(paths,archive,identity)
        with tarfile.open(archive,mode='r:') as saved:
            # Empty-store recovery must carry the original immutable index,
            # selected native manifest and config in the archive itself.
            for digest in (identity.index_digest,identity.native_digest,identity.image_id):
                member=saved.getmember('blobs/sha256/'+digest[7:])
                require(member.isfile(),'Original immutable archive graph missing')
            config=saved.extractfile('blobs/sha256/'+identity.image_id[7:]).read(524289)
        require(len(config)<=524288,'Archive configuration exceeded bound')
        self.configurations[identity.reference]=PosixDockerAdapter.configuration_proof(config,identity)
        self.configuration_bytes[identity.reference]=config


def child_helper(state_directory, identifier, *, crash=False):
    """A genuinely new helper process reconstructs only durable private state."""
    paths=create_private_paths()
    root=paths.check(Path(state_directory).resolve(),directory=True)
    canonical_uuid(identifier)
    resolver=NoNetworkResolver()
    if crash:
        graph=parse_json(paths.read(root/'trial-registry-graph.json',limit=1048576),1048576)
        require(graph.get('schema')=='keep.maintenance-trial-graph.v1','Invalid trial graph')
        proof=graph['registry']
        registry_resource_proof(proof)
        docker=Path(shutil.which('docker') or '').resolve(strict=True)
        outer_env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),
            'DOCKER_CONFIG':str(root.parent/'outer-config'),'HOME':str(root.parent)}
        def inspect(*args):
            rows=parse_json(run((docker,'--host','unix:///var/run/docker.sock',*args),env=outer_env),1048576)
            require(isinstance(rows,list) and len(rows)==1 and isinstance(rows[0],dict),'Invalid retained registry inspection')
            return rows[0]
        # The private graph retains identities, not a user-selected HTTP host.
        # A new helper revalidates both actual resources before any connection.
        resolver=RegistryGraph.owned(graph['architecture'],proof,
            inspect('network','inspect',proof['network_id']),inspect('inspect',proof['container_id']))
        resolver.identities={value.reference:value for value in (ImageIdentity.from_dict(item) for item in graph['images'])}
    def factory(paths,profile,enrollment=None):
        class Backend:
            def __init__(inner):
                inner.mailbox=HostMailbox(paths,profile,enrollment,resolver=resolver)
            def engine(inner):
                adapter=PosixDockerAdapter(paths,profile,enrollment,resolver=resolver,runner=inner.mailbox.runner)
                return HostEngine(paths,profile,adapter)
        return Backend()
    state,backend=load_backend(paths,root,backend_factory=factory)
    request=backend.mailbox.accepted_request(paths.read(root/'accepted-requests'/(identifier+'.json'),limit=65536))
    require(request.request_id==identifier,'Child helper request differs')
    if crash:
        class TerminateAfterCommit(PosixDockerAdapter):
            def open_gate_and_verify(inner,request):
                super().open_gate_and_verify(request)
                app=inner.discover(images={request.target.image_id})['keep-app']['Id']
                inner.run('protected post-commit fixture write',(*inner.plans.base,'exec',app,'python','-B',
                    '/app/maintenance_trial_fixture.py','write'),limit=65536)
                paths.publish(root/('trial-crashed-'+identifier+'.json'),canonical({'request_id':identifier,'pid':os.getpid(),'phase':'committed'}))
                # Terminate the process without unwinding HostEngine or retaining
                # any Request, resolver, adapter or controller object in memory.
                os._exit(91)
        adapter=TerminateAfterCommit(paths,backend.mailbox.profile,backend.mailbox.enrollment,
            resolver=resolver,runner=backend.mailbox.runner)
        HostEngine(paths,backend.mailbox.profile,adapter).execute(request)
        raise TrialError('Post-commit termination did not occur')
    result=backend.engine().resume(request)
    paths.publish(root/('trial-resumed-'+identifier+'.json'),canonical({'request_id':identifier,
        'pid':os.getpid(),'phase':result['phase'],'sequence':result['sequence'],'network_resolution':False}))
    return 0


class NativeTrial:
    def __init__(self, source, integration, candidate, architecture, evidence):
        require(sys.platform == 'linux' and os.name == 'posix', 'Execute on a native Linux runner')
        self.source, self.integration, self.architecture = source.resolve(), integration.resolve(), architecture
        self.candidate, self.evidence = candidate, evidence.resolve()
        self.paths = create_private_paths()
        self.temp = Path(tempfile.mkdtemp(prefix='keep-maintenance-native-')).resolve()
        os.chmod(self.temp, 0o700)
        self.root = create_root(self.paths, self.temp/'private')
        self.tool_state = self.paths.mkdir(self.root/'tool-state')
        self.installation = self.paths.mkdir(self.root/'installation')
        self.state = self.paths.mkdir(self.root/'state')
        self.config = self.paths.mkdir(self.root/'docker-config')
        self.outer_config = self.paths.mkdir(self.root/'outer-config')
        self.socket = self.paths.mkdir(self.root/'socket')
        self.docker = Path(shutil.which('docker') or '').resolve(strict=True)
        require(self.docker.is_file(), 'Pinned Docker executable is unavailable')
        self.env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'DOCKER_CONFIG': str(self.outer_config), 'HOME': str(self.root)}
        self.name = 'keep-maintenance-native-'+uuid.uuid4().hex[:12]
        self.tools, self.outer_images = [], []
        self.network = None
        self.profile = None
        self.report = {'schema':'keep.maintenance-native-trial.v1','architecture':architecture,
            'project':self.name,
            'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'images':{}, 'source_files':{},
            'phases':[], 'cleanup':{}, 'outcome':'running', 'limitations':[
                'Synthetic local Plex owner; no live Plex authentication or provider deliveries.',
                'Fixture-derived images add a deterministic schema marker and intentional health failure.',
                'This native Linux evidence does not qualify Docker Desktop on macOS or Windows.']}

    def outer(self, *args, **kwargs):
        return run((self.docker, '--host', 'unix:///var/run/docker.sock', *args), env=self.env, **kwargs)

    def inner(self, *args, **kwargs):
        require(self.profile is not None, 'Isolated daemon is not enrolled')
        return run((self.profile.docker_executable, '--context', self.profile.docker_context, *args),
            env={'PATH':self.env['PATH'],'HOME':str(self.root),'DOCKER_CONFIG':str(self.config)}, **kwargs)

    def tooling_probe(self, step, action, *, reference=None, records='tooling_preflight', version=None):
        # These probes precede enrollment and inspect only public tooling. Keep
        # fixed status codes and selected metadata; never copy stderr or argv.
        entry={'step':step,'status':'running'}
        if reference is not None:entry['reference']=reference
        if version is not None:entry['version']=version
        self.report.setdefault(records, []).append(entry)
        try:
            value=action()
            entry.update(value)
            entry['status']='passed'
            return value
        except Exception as error:
            entry['status']='failed'
            entry['error_code']=error.code if isinstance(error,TrialError) else 'metadata_invalid'
            if isinstance(error,TrialError) and error.returncode is not None:
                entry['exit_code']=error.returncode
            raise

    def image_probe(self, step, action, *, version=None):
        return self.tooling_probe(step,action,records='image_staging',version=version)

    def image_command(self, step, action, *, version=None):
        def complete():
            action()
            return {'completed':True}
        return self.image_probe(step,complete,version=version)

    def compose_probe(self, step, action):
        return self.tooling_probe(step,action,records='compose_setup')

    def compose_command(self, step, action):
        def complete():
            action()
            return {'completed':True}
        return self.compose_probe(step,complete)

    def tooling_preflight(self):
        architectures={'x86_64':'amd64','amd64':'amd64','aarch64':'arm64','arm64':'arm64'}
        def host_native():
            actual=architectures.get(platform.machine())
            require(actual == self.architecture, 'Host CPU is not native', code='host_not_native')
            return {'architecture':actual}
        self.tooling_probe('host-native-architecture',host_native)
        def client_version():
            value=parse_json(self.outer('version','--format','{{json .Client.Version}}'),256)
            require(isinstance(value,str) and re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[A-Za-z0-9_.+-]{0,32}',value),
                'Invalid tooling client version', code='metadata_invalid')
            return {'client_version':value}
        self.tooling_probe('outer-client-version',client_version)
        def daemon_native():
            outer_arch=self.outer('info','--format','{{.Architecture}}').decode().strip()
            actual=architectures.get(outer_arch)
            require(actual == self.architecture, 'Runner is not native', code='daemon_not_native')
            return {'architecture':actual}
        self.tooling_probe('outer-native-architecture',daemon_native)
        for tool in TOOLING:
            ref = tool['repository']+'@'+tool['index_digest']
            def inspect_tool():
                # Tooling was already pulled on this native runner. Older outer
                # clients cannot accept image-inspect --platform; validate the
                # observed native platform and immutable identity explicitly.
                rows=parse_json(self.outer('image','inspect',ref),1048576)
                require(isinstance(rows,list) and len(rows)==1 and isinstance(rows[0],dict),
                    'Invalid tooling inspection', code='metadata_invalid')
                inspected=rows[0]
                require(inspected.get('Architecture') == self.architecture and inspected.get('Os') == 'linux',
                    'Tooling is not native', code='tool_not_native')
                require(pinned_tool_identity(inspected,tool,self.architecture),
                    'Pinned tooling index identity unavailable', code='tool_identity_unavailable')
                return {'reference':ref,'native_digest':tool['native'][self.architecture],
                    'local_id':inspected['Id'],'architecture':self.architecture,'os':'linux'}
            result=self.tooling_probe('outer-tool-image-inspect',inspect_tool,reference=ref)
            self.report.setdefault('tooling', []).append(result)

    def tooling(self):
        self.tooling_preflight()
        def create_network():
            self.network=self.outer('network','create','--internal','--label','io.keep.maintenance.trial='+self.name,self.name).decode().strip()
            require(re.fullmatch('[a-f0-9]{64}',self.network),'Invalid owned network identity',code='metadata_invalid')
            return {'network_id':self.network,'internal':True}
        self.tooling_probe('owned-internal-network-create',create_network)
        registry_data=self.paths.mkdir(self.tool_state/'registry-data')
        daemon_data=self.paths.mkdir(self.tool_state/'daemon-data')
        def start_registry():
            registry=self.outer('run','--detach','--name',self.name+'-registry','--label','io.keep.maintenance.trial='+self.name,
                '--network',self.name,'--mount','type=bind,source='+str(registry_data)+',target=/var/lib/registry',
                TOOLING[1]['repository']+'@'+TOOLING[1]['index_digest']).decode().strip()
            require(re.fullmatch('[a-f0-9]{64}',registry),'Invalid owned registry identity',code='metadata_invalid')
            self.tools.append(registry)
            return {'container_id':registry}
        registry=self.tooling_probe('owned-registry-container-start',start_registry)['container_id']
        def registry_endpoint():
            def inspect(*args):
                rows=parse_json(self.outer(*args),1048576)
                require(isinstance(rows,list) and len(rows)==1 and isinstance(rows[0],dict),'Invalid owned registry inspection',code='metadata_invalid')
                return rows[0]
            self.registry_proof={'project':self.name,'network_id':self.network,'container_id':registry,
                'image_id':self.report['tooling'][1]['local_id'],'members':list(self.tools)}
            self.resolver=RegistryGraph.owned(self.architecture,self.registry_proof,
                inspect('network','inspect',self.network),inspect('inspect',registry))
            return {'network_id':self.network,'container_id':registry,'endpoint_kind':'owned-internal-ipv4','port':5000}
        self.tooling_probe('owned-registry-endpoint-inspect',registry_endpoint)
        def registry_ready():
            deadline=time.monotonic()+30
            while True:
                try:
                    self.resolver.request('GET','/v2/')
                    return {'ready':True}
                except (OSError,http.client.HTTPException,TrialError):
                    require(time.monotonic()<deadline,'Owned registry is unavailable',code='registry_endpoint_invalid')
                    time.sleep(.2)
        self.tooling_probe('owned-registry-http-ready',registry_ready)
        def start_dind():
            dind=self.outer('run','--detach','--privileged','--name',self.name+'-daemon','--label','io.keep.maintenance.trial='+self.name,
                '--network',self.name,'--entrypoint',DIND_ENTRYPOINT,'--env','DOCKER_TLS_CERTDIR=', '--mount','type=bind,source='+str(daemon_data)+',target=/var/lib/docker','--mount','type=bind,source='+str(self.socket)+',target=/trial-socket',
                TOOLING[0]['repository']+'@'+TOOLING[0]['index_digest'],*dind_arguments(self.name)).decode().strip()
            require(re.fullmatch('[a-f0-9]{64}',dind),'Invalid owned daemon identity',code='metadata_invalid')
            self.tools.append(dind)
            row=json.loads(self.outer('inspect',dind))[0]
            require(row.get('Id')==dind and dind_startup_matches(row,self.name),'Owned daemon startup wrapper differs')
            self.registry_proof['members']=list(self.tools)
            return {'container_id':dind,'control_transport':'unix'}
        dind=self.tooling_probe('owned-dind-container-start',start_dind)['container_id']
        # The daemon's exact pinned native image also supplies the matching
        # Docker29 client and Compose binary; the runner's older CLI must not
        # silently drop modern native descriptor fields in inspect responses.
        binaries=self.paths.mkdir(self.root/'bin')
        selected=binaries/'docker'
        plugins=self.paths.mkdir(self.config/'cli-plugins')
        plugin=plugins/'docker-compose'
        def copy_binary(source,binary):
            self.outer('cp',dind+':'+source,binary)
            require(binary.is_file() and not binary.is_symlink(),'Pinned client binary is unavailable')
            os.chmod(binary,0o500)
            self.paths.check(binary)
            return {'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
        self.tooling_probe('pinned-docker-client-copy',lambda:copy_binary('/usr/local/bin/docker',selected))
        self.tooling_probe('pinned-compose-client-copy',lambda:copy_binary('/usr/local/libexec/docker/cli-plugins/docker-compose',plugin))
        self.report['client_binary_sha256']=hashlib.sha256(selected.read_bytes()).hexdigest()
        self.report['compose_binary_sha256']=hashlib.sha256(plugin.read_bytes()).hexdigest()
        def socket_ready():
            deadline=time.monotonic()+90
            while not (self.socket/'docker.sock').exists():
                require(time.monotonic()<deadline,'Isolated Unix socket did not appear')
                time.sleep(.2)
            self.outer('exec',dind,'chown',str(os.geteuid())+':'+str(os.getegid()),'/trial-socket/docker.sock')
            self.outer('exec',dind,'chmod','600','/trial-socket/docker.sock')
            return {'control_transport':'unix'}
        self.tooling_probe('isolated-unix-socket-ready',socket_ready)
        endpoint = 'unix://'+str(self.socket/'docker.sock')
        local_env = {'PATH':self.env['PATH'],'HOME':str(self.root),'DOCKER_CONFIG':str(self.config)}
        def create_context():
            run((selected,'context','create',self.name,'--docker','host='+endpoint),env=local_env)
            return {'context':self.name,'control_transport':'unix'}
        self.tooling_probe('isolated-context-create',create_context)
        self.profile = Profile(self.installation,self.state,selected,self.config,self.name,endpoint,'temporary',self.name,
            self.name+'_keep-data',(self.installation/'compose.yml',),self.installation/'.env')
        def daemon_ready():
            deadline=time.monotonic()+90
            while True:
                try:
                    daemon=parse_json(self.inner('info','--format','{{json .ID}}'),256)
                    require(isinstance(daemon,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9:-]{0,127}',daemon),
                        'Invalid isolated daemon identity',code='metadata_invalid')
                    return {'daemon_id':daemon}
                except TrialError:
                    require(time.monotonic()<deadline,'Isolated daemon is unavailable')
                    time.sleep(.2)
        daemon=self.tooling_probe('isolated-daemon-ready',daemon_ready)['daemon_id']
        self.profile = replace(self.profile, daemon_id=daemon)
        def daemon_native():
            require(self.inner('info','--format','{{.OSType}}').strip()==b'linux','Isolated daemon must use Linux containers',code='daemon_not_native')
            native=self.inner('info','--format','{{.Architecture}}').decode().strip()
            require({'x86_64':'amd64','amd64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(native)==self.architecture,
                'Isolated daemon is not native',code='daemon_not_native')
            return {'architecture':self.architecture,'os':'linux'}
        self.tooling_probe('isolated-native-platform-verify',daemon_native)

    def images(self):
        base={}
        def inspect_base():
            rows=parse_json(self.outer('image','inspect',self.candidate),1048576)
            require(isinstance(rows,list) and len(rows)==1 and isinstance(rows[0],dict),'Candidate inspection invalid',code='metadata_invalid')
            base.update(rows[0])
            require(isinstance(base.get('Id'),str) and DIGEST.fullmatch(base['Id']),'Candidate image identity invalid',code='metadata_invalid')
            require(base.get('Architecture')==self.architecture and base.get('Os')=='linux','Source-packaged base is not native')
            labels=base.get('Config',{}).get('Labels') or {}
            revision=labels.get('org.opencontainers.image.revision');version=labels.get('org.opencontainers.image.version')
            require(isinstance(revision,str) and re.fullmatch('[a-f0-9]{40}',revision),'Base image needs its full source revision')
            require(isinstance(version,str) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',version)
                and len(version)<=32,'Candidate version invalid',code='metadata_invalid')
            return {'image_id':base['Id'],'version':version,'revision':revision,'architecture':self.architecture,'os':'linux'}
        observed=self.image_probe('candidate-inspect',inspect_base)
        revision=observed['revision']
        archive=self.tool_state/'source-packaged-base.tar'
        def export_base():
            self.outer('image','save','--output',archive,self.candidate,timeout=300)
            require(archive.is_file() and 0<archive.stat().st_size<=32*1024**3,'Candidate export unavailable')
            return {'archive_created':True,'bytes':archive.stat().st_size}
        self.image_probe('candidate-export',export_base)
        config_digest=self.image_probe('candidate-export-verify',lambda:{'config_digest':candidate_configuration(archive,base)})['config_digest']
        def revalidate_base(reference):
            require(json.loads(self.outer('image','inspect',reference))[0]['Id']==base['Id'],'Source-packaged candidate alias changed')
            return {'image_id':base['Id']}
        self.image_probe('candidate-reinspect',lambda:revalidate_base(self.candidate))
        self.report['candidate']={'version':base['Config']['Labels'].get('org.opencontainers.image.version'),
            'revision':revision,'architecture':self.architecture,'os':'linux','image_id':config_digest}
        self.report['base_image'] = {'id':base['Id'], 'config_digest':config_digest,'revision':revision,'reference':self.candidate,
            'version':base['Config']['Labels'].get('org.opencontainers.image.version')}
        self.base_alias=self.name+'-base:source'
        def tag_base():
            self.outer('image','tag',self.candidate,self.base_alias)
            self.outer_images.append((self.base_alias,base['Id']))
            return revalidate_base(self.base_alias)
        self.image_probe('owned-base-alias-create',tag_base)
        base['fixture_reference']=self.base_alias
        staged={}
        def stage_fixture():
            staged['build']=self.stage_source(base)
            return {'files':len(self.report['source_files'])}
        self.image_probe('fixture-source-stage',stage_fixture)
        build=staged['build']
        self.images_by_schema={}
        for schema in (1,2,3,4):
            version='0.0.'+str(schema)
            self.paths.publish(build/'VERSION',(version+'\n').encode(),overwrite=schema>1)
            self.paths.publish(build/'TRIAL_SCHEMA',(str(schema)+'\n').encode(),overwrite=schema>1)
            tag=self.name+'-image:'+version
            self.image_probe('fixture-base-alias-revalidate',lambda:revalidate_base(self.base_alias),version=version)
            def build_fixture():
                self.outer('build','--network','none','--pull=false','--label','org.opencontainers.image.version='+version,
                    '--label','org.opencontainers.image.revision='+revision,'--tag',tag,str(build),timeout=300)
                metadata=json.loads(self.outer('image','inspect',tag))[0]
                require(isinstance(metadata.get('Id'),str) and DIGEST.fullmatch(metadata['Id']),'Fixture image identity invalid')
                self.outer_images.append((tag,metadata['Id']))
                revalidate_base(self.base_alias)
                return {'image_id':metadata['Id']}
            self.image_probe('fixture-image-build',build_fixture,version=version)
            archive=self.tool_state/('source-'+version+'.tar')
            self.image_command('fixture-image-export',lambda:self.outer('image','save','--output',archive,tag,timeout=300),version=version)
            self.image_command('fixture-image-load',lambda:self.inner('image','load','--input',archive,timeout=300),version=version)
            mirror=self.name+'-registry:5000/brspoon/keep:native-'+str(schema)
            self.image_command('fixture-registry-tag',lambda:self.inner('image','tag',tag,mirror),version=version)
            self.image_command('fixture-registry-push',lambda:self.inner('push','--platform','linux/'+self.architecture,mirror,timeout=300),version=version)
            identities={}
            def verify_fixture():
                identities['image']=self.resolver.register('native-'+str(schema),version,revision)
                return {'image_id':identities['image'].image_id,'native_digest':identities['image'].native_digest}
            self.image_probe('fixture-registry-graph-verify',verify_fixture,version=version)
            identity=identities['image']
            # Resolve official-name immutable URI through the internal mirror.
            self.image_command('fixture-immutable-pull',lambda:self.inner('pull',identity.reference,timeout=300),version=version)
            self.images_by_schema[schema]=identity
            self.report['images'][version]=identity.as_dict()
        self.paths.publish(self.state/'trial-registry-graph.json',canonical({'schema':'keep.maintenance-trial-graph.v1',
            'architecture':self.architecture,'registry':self.registry_proof,
            'images':[image.as_dict() for image in self.images_by_schema.values()]}))

    def stage_source(self, base):
        revision=base['Config']['Labels']['org.opencontainers.image.revision']
        build = self.paths.mkdir(self.root/'image-source')
        files = {'app.py':self.integration/'app.py','onboarding.py':self.integration/'onboarding.py',
            **{name:NEUTRAL_SOURCE/name for name in ('maintenance_app.py','maintenance_mailbox.py','maintenance_protocol.py','private_store.py')},
            'maintenance_trial_fixture.py':(DRAFT/'maintenance_trial_fixture.py' if (DRAFT/'maintenance_trial_fixture.py').is_file() else self.source/'tests/maintenance_trial_fixture.py'),
            'maintenance_portable_fixture.py':self.source/'tests/portable_trial.py'}
        for path in sorted((self.integration/'templates').glob('about*.html')):
            files['templates/'+path.name]=path
        for name in ('keep-maintenance.js','keep-maintenance.css','keep-about.js'):
            path=self.integration/'static'/name
            if path.is_file():files['static/'+name]=path
        for name,path in files.items():
            body=path.read_bytes()
            self.report['source_files'][name]={'source_sha256':hashlib.sha256(body).hexdigest(),'fixture_sha256':hashlib.sha256(body).hexdigest()}
            if name=='maintenance_mailbox.py':
                false_count=body.count(b'RUNTIME_QUALIFIED = False')
                true_count=body.count(b'RUNTIME_QUALIFIED = True')
                require((false_count,true_count) in ((1,0),(0,1)), 'Qualification constant is ambiguous or unavailable')
                if false_count:
                    body=body.replace(b'RUNTIME_QUALIFIED = False',b'RUNTIME_QUALIFIED = True')
                self.report['source_files'][name]['fixture_sha256']=hashlib.sha256(body).hexdigest()
            if '/' in name and not (build/Path(name).parent).exists():self.paths.mkdir(build/Path(name).parent)
            self.paths.publish(build/name,body)
        require(isinstance(base.get('fixture_reference'),str) and re.fullmatch('[a-z0-9][a-z0-9_.-]{0,100}:source',base['fixture_reference']),
            'Owned local source base alias is required')
        dockerfile = ('FROM '+base['fixture_reference']+'\nUSER root\n'+''.join('COPY --chown=10001:10001 '+name+' /app/'+name+'\n' for name in files)
            +'COPY --chown=10001:10001 VERSION TRIAL_SCHEMA /app/\nUSER 10001:10001\n'
            +'LABEL org.opencontainers.image.source="https://github.com/brspoon/keep"\n'
            +'CMD ["python","-B","/app/maintenance_trial_fixture.py","web"]\n')
        self.paths.publish(build/'Dockerfile',dockerfile.encode())
        return build

    def compose(self):
        previous=self.images_by_schema[1]
        env=('KEEP_IMAGE='+previous.reference+'\nKEEP_DB_PATH=/app/data/keep.sqlite3\n'
            +'FLASK_SECRET_KEY=synthetic-maintenance-native-fixture\nKEEP_WEBHOOK_SECRET=synthetic-maintenance-native-fixture\n'
            +'EMAIL_ENABLED=false\nPUSHOVER_ENABLED=false\nPLEX_OWNER_ID=7\n')
        self.paths.publish(self.profile.env_file,env.encode())
        self.paths.publish(self.installation/'VERSION',(previous.version+'\n').encode())
        # Fixed services and the real named-volume/Compose label topology.
        composition='''name: %s
x-keep: &keep
  image: ${KEEP_IMAGE}
  env_file: .env
  restart: "no"
  network_mode: none
  volumes: [keep-data:/app/data]
  read_only: true
  tmpfs: ["/tmp:size=64m,mode=1777"]
  cap_drop: [ALL]
  security_opt: [no-new-privileges:true]
services:
  keep-app:
    <<: *keep
    command: [python, -B, /app/maintenance_trial_fixture.py, web]
    healthcheck:
      test: [CMD, python, -c, "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)"]
      interval: 1s
      timeout: 4s
      retries: 2
      start_period: 2s
  keep-digest:
    <<: *keep
    command: [python, -B, /app/maintenance_trial_fixture.py, worker]
    healthcheck:
      test: [CMD, python, -c, "import os,time; assert time.time()-os.path.getmtime('/app/data/digest-worker.heartbeat')<300"]
      interval: 1s
      timeout: 4s
      retries: 2
      start_period: 2s
volumes:
  keep-data:
'''%self.name
        self.paths.publish(self.profile.compose_files[0],composition.encode())
        def prepare_configuration():
            self.profile.validate(self.paths)
            return {'services':2,'data_volumes':1}
        self.compose_probe('fixture-configuration-prepare',prepare_configuration)
        self.compose_args=('compose','--project-name',self.profile.project,'--project-directory',str(self.installation),
            '--env-file',str(self.profile.env_file),'--file',str(self.profile.compose_files[0]))
        def validate_configuration():
            parsed=parse_json(self.inner(*self.compose_args,'config','--format','json'),1048576)
            validate_fixture_tmpfs(parsed)
            return {'services':2,'tmpfs_mounts_per_service':1}
        self.compose_probe('fixture-compose-config-verify',validate_configuration)
        self.compose_command('fixture-compose-create',lambda:self.inner(*self.compose_args,'create','--pull','never'))
        self.compose_command('fixture-database-seed',lambda:self.inner('run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true',
            '--env-file',self.profile.env_file,'--mount','type=volume,source='+self.profile.volume+',target=/app/data',
            '--tmpfs','/tmp:size=64m,mode=1777','--entrypoint','python',previous.reference,'-B','/app/maintenance_trial_fixture.py','seed',timeout=120))
        self.compose_command('fixture-compose-start',lambda:self.inner(*self.compose_args,'up','--detach','--no-build','--pull','never'))
        self.compose_command('fixture-paired-health',lambda:self.wait(previous))
        resolver=self.resolver
        def factory(paths,profile,enrollment=None):
            class Backend:
                def __init__(inner):
                    inner.mailbox=HostMailbox(paths,profile,enrollment,resolver=resolver)
                    inner.target=None
                def engine(inner):
                    adapter=PosixDockerAdapter(paths,profile,enrollment,resolver=resolver,runner=inner.mailbox.runner)
                    adapter.known_identities.update(inner.mailbox.adapter.known_identities)
                    return HostEngine(paths,profile,adapter)
            return Backend()
        self.factory=factory
        prepared={}
        def package_source():
            prepared['bundle']=source_bundle(self.paths,DRAFT,version=previous.version,revision=previous.revision)
            return {'sha256':hashlib.sha256(prepared['bundle']).hexdigest()}
        self.compose_probe('helper-source-package',package_source)
        def stage_source():
            prepared['staged']=stage_bundle(self.paths,self.state,prepared['bundle'],version=previous.version,
                revision=previous.revision,expected_sha256=hashlib.sha256(prepared['bundle']).hexdigest())
            return {'staged':True}
        self.compose_probe('helper-source-stage',stage_source)
        def read_source_proof():
            prepared['proof']=HostState(self.paths,self.state).source_proof(prepared['staged'])
            return {'sha256':prepared['proof']['archive_sha256']}
        self.compose_probe('helper-source-proof',read_source_proof)
        source_proof=prepared['proof']
        self.report['helper_bundle_sha256']=source_proof['archive_sha256']
        self.report['helper_sources']=source_proof['manifest']['files']
        def enroll_source():
            prepared['activation']=enroll(self.paths,self.profile,source_proof=source_proof,backend_factory=factory)
            return {'install_id':prepared['activation']['install_id']}
        self.compose_probe('signed-enrollment',enroll_source)
        activation=prepared['activation']
        def reload_source():
            self.host_state,self.backend=load_backend(self.paths,self.state,backend_factory=factory)
            return {'enrolled':True}
        self.compose_probe('enrolled-host-reload',reload_source)
        self.report['activation']={'install_id':activation['install_id'],'context':self.profile.docker_context,'daemon_id':self.profile.daemon_id}

    def wait(self,image):
        mailbox=HostMailbox(self.paths,self.profile,resolver=self.resolver)
        mailbox.adapter.known_identities[image.image_id]=image
        deadline=time.monotonic()+90
        while True:
            rows=mailbox.adapter.discover(images={image.image_id})
            if all(row['State']['Running'] and row['State']['Health']=='healthy' for row in rows.values()):return
            require(time.monotonic()<deadline,'Fixture services did not become healthy')
            time.sleep(.2)

    def ids(self):
        return self.backend.mailbox.probe().containers

    def fixture(self,mode):
        return parse_json(self.inner('exec',self.ids()['keep-app'],'python','-B','/app/maintenance_trial_fixture.py',mode),65536) if mode=='inspect' else self.inner('exec',self.ids()['keep-app'],'python','-B','/app/maintenance_trial_fixture.py',mode)

    def request(self,operation,target=None,identifier=None):
        mailbox=self.backend.mailbox
        mailbox.advisory(target=target)
        identifier=identifier or str(uuid.uuid4())
        intent=self.state/('trial-request-'+identifier+'.json')
        if not intent.exists():self.paths.publish(intent,canonical({'request_id':identifier,'operation':operation}))
        mailbox.queue(operation,request_id=identifier)
        request=mailbox.poll()
        require(request is not None and request.request_id==identifier,'Signed queued request unavailable')
        self.host_state.retain_request(mailbox,request)
        return request

    def execute(self,request,adapter_class=PosixDockerAdapter):
        adapter=adapter_class(self.paths,self.profile,self.backend.mailbox.enrollment,resolver=self.resolver,runner=self.backend.mailbox.runner)
        adapter.known_identities.update(self.backend.mailbox.adapter.known_identities)
        original_ids={}
        assertion=getattr(adapter,'assert_runtime',None)
        if callable(assertion):
            def observed_runtime(identity,profile):
                value=assertion(identity,profile)
                try:
                    if not original_ids:original_ids.update({name:row['Id'] for name,row in adapter.containers.items()})
                except Exception:pass
                return value
            adapter.assert_runtime=observed_runtime
        try:return HostEngine(self.paths,self.profile,adapter).execute(request)
        except Exception:
            # Diagnostic collection must never replace the original failure.
            try:diagnostic=snapshot_helper_diagnostic(adapter)
            except Exception:diagnostic={'available':False}
            self.report.setdefault('volume_diagnostics',[]).append(diagnostic)
            try:services=paired_service_diagnostic(self,adapter,request,original_ids)
            except Exception:services={'available':False}
            self.report.setdefault('service_diagnostics',[]).append(services)
            raise

    def record(self,name,action):
        entry={'name':name,'status':'running'};self.report['phases'].append(entry)
        try:
            value=action()
            if value:entry.update(value)
            entry['status']='passed'
        except Exception as error:
            entry['status']='failed';entry['error_type']=type(error).__name__
            entry['failure_details']=failure_details(error)
            if isinstance(error,TrialError):entry['error_code']=error.code
            raise

    def assert_completed_helpers_removed(self,request):
        operation=self.state/'operations'/request.request_id
        receipt=parse_json(self.paths.read(operation/'helper-cleanup-receipt.json',limit=4096))
        terminal=Journal(self.paths,self.state,request.request_id,request.payload_sha256).records()[-1]
        require(terminal['phase'] in ('success','recovered') and receipt.get('request_id')==request.request_id
            and receipt.get('payload_sha256')==request.payload_sha256 and receipt.get('phase')==terminal['phase'],
            'Completed helper cleanup receipt differs')
        helpers=receipt.get('containers')
        require(isinstance(helpers,dict) and 1<=len(helpers)<=5,'Completed helper cleanup inventory is invalid')
        for identifier,purpose in helpers.items():
            require(re.fullmatch('[a-f0-9]{64}',identifier) and purpose in ('snapshot','preserve','prepare-restore','restore','upload'),
                'Completed helper cleanup identity is invalid')
            original=parse_json(self.paths.read(operation/('helper-'+purpose+'.json'),limit=4096))
            require(original.get('container_id')==identifier,'Completed helper creation record was not retained')
            require(not self.inner('ps','--all','--no-trunc','--filter','id='+identifier,'--format','{{.ID}}').strip(),
                'A completed helper remains before trial teardown')
        require(not self.inner('ps','--all','--no-trunc','--filter',
            'label=io.keep.maintenance.install='+self.backend.mailbox.enrollment.install_id,'--filter',
            'label=io.keep.maintenance.operation='+request.request_id,'--format','{{.ID}}').strip(),
            'Completed operation left an unrecorded helper')
        return len(helpers)

    def restart_and_drain(self):
        request=self.request('restart')
        trial=self
        proof={}
        class ObserveDrain(PosixDockerAdapter):
            def close_gate_and_drain(inner,request):
                # Start after the engine's last pre-drain status/authority call.
                # A preexisting lease must not merely delay claim/status before
                # the gate closes: this handshake observes the actual drain.
                app=inner.discover(images={request.expected.image_id})['keep-app']['Id']
                environment={'PATH':trial.env['PATH'],'HOME':str(trial.root),'DOCKER_CONFIG':str(trial.config)}
                writer=subprocess.Popen((str(trial.profile.docker_executable),'--context',trial.profile.docker_context,
                    'exec',app,'python','-B','/app/maintenance_trial_fixture.py','hold',request.request_id),
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment)
                errors=[]
                def drain():
                    try:super(ObserveDrain,inner).close_gate_and_drain(request)
                    except BaseException as error:errors.append(error)
                thread=None
                def observation():
                    return parse_json(trial.inner('exec',app,'python','-B','/app/maintenance_trial_fixture.py','gate'),65536)
                try:
                    deadline=time.monotonic()+10
                    while not observation()['writer_ready']:
                        require(writer.poll() is None and time.monotonic()<deadline,'Controlled protected writer did not acquire its lease')
                        time.sleep(.05)
                    thread=threading.Thread(target=drain)
                    thread.start()
                    deadline=time.monotonic()+10
                    while True:
                        view=observation()
                        if view['closed']:break
                        require(not errors and time.monotonic()<deadline,'Drain did not close admission while writer was held')
                        time.sleep(.05)
                    require(view['request_id']==request.request_id and not view['drained'] and view['writer_ready']
                        and view['writer_done'] is None and request.request_id not in view['drain_writes'] and writer.poll() is None,
                        'Protected writer was not held across actual gate closure')
                    code="import urllib.request,urllib.error;\ntry: print(urllib.request.urlopen('http://127.0.0.1:5000/login',timeout=3).status)\nexcept urllib.error.HTTPError as e: print(e.code)"
                    require(trial.inner('exec',app,'python','-B','-c',code).strip()==b'503','Ordinary HTTP admission was not refused during drain')
                    require(writer.poll() is None and not observation()['drained'],'Drain completed before controlled writer release')
                    proof.update(gate_closed_with_writer_held=True,ordinary_http_status=503)
                    trial.inner('exec',app,'python','-B','/app/maintenance_trial_fixture.py','release',request.request_id)
                    writer.communicate(timeout=10)
                    require(writer.returncode==0,'Controlled admitted writer was interrupted')
                    thread.join(timeout=25)
                    require(not thread.is_alive() and not errors,'Actual drain did not complete after final protected write')
                    view=observation()
                    require(view['closed'] and view['drained'] and view['writer_done']==request.request_id
                        and request.request_id in view['drain_writes'],'Drain did not retain the completed protected write')
                    proof['protected_write_before_stop']=True
                finally:
                    if writer.poll() is None:
                        try:trial.inner('exec',app,'python','-B','/app/maintenance_trial_fixture.py','release',request.request_id)
                        finally:
                            try:writer.communicate(timeout=5)
                            except subprocess.TimeoutExpired:writer.kill();writer.communicate(timeout=5)
                    if thread is not None:thread.join(timeout=25)
            def stop_and_verify_both(inner,profile):
                require(proof.get('protected_write_before_stop') is True,'Service stop preceded protected writer completion')
                super().stop_and_verify_both(profile)
            def snapshot_matched_state(inner,request,profile):
                result=super().snapshot_matched_state(request,profile)
                snapshot=inner.operation/'recovery/database.sqlite3'
                with sqlite3.connect(snapshot.as_uri()+'?mode=ro',uri=True) as db:
                    row=db.execute("SELECT version FROM user_feature_acknowledgements WHERE feature_key='maintenance-drain-write'").fetchone()
                require(row==(request.request_id,),'Matched SQLite snapshot omitted the final admitted write')
                proof['protected_write_in_snapshot']=True
                return result
        result=self.execute(request,ObserveDrain)
        require(result['phase']=='success','Restart did not finish')
        after=self.ids()
        require(self.fixture('inspect')['schema']==1,'Restart changed database schema')
        journal=Journal(self.paths,self.state,request.request_id,request.payload_sha256)
        old_rows=journal.records()
        self.backend.mailbox.queue('restart',request_id=request.request_id)
        result=self.execute(request)
        require(result==old_rows[-1] and journal.records()==old_rows and self.ids()==after,'Duplicate operation repeated a cutover')
        removed=self.assert_completed_helpers_removed(request)
        return {'request_id':request.request_id,'journal_records':len(old_rows),'duplicate_operation_unchanged':True,
                'completed_helpers_removed':removed,**proof}

    def successful_install(self):
        request=self.request('install',self.images_by_schema[2]);result=self.execute(request)
        require(result['phase']=='success' and self.fixture('inspect')['schema']==2,'Real candidate schema migration failed')
        require(self.backend.mailbox.probe().image==self.images_by_schema[2],'Candidate native/config identity mismatch')
        require(self.profile.env_file.read_text().splitlines()[0]=='KEEP_IMAGE='+self.images_by_schema[2].reference,'Normal image environment setting not applied')
        return {'request_id':request.request_id,'schema':2,
                'completed_helpers_removed':self.assert_completed_helpers_removed(request)}

    def failed_upgrade(self):
        before={str(path):path.read_bytes() for path in (self.profile.env_file,*self.profile.compose_files,self.installation/'VERSION')}
        request=self.request('install',self.images_by_schema[3])
        try:self.execute(request)
        except EngineError:pass
        else:raise TrialError('Intentional unhealthy candidate unexpectedly succeeded')
        journal=Journal(self.paths,self.state,request.request_id,request.payload_sha256).records()
        require(journal[-1]['phase']=='recovered','Matched recovery was not completed')
        require(self.fixture('inspect')['schema']==2 and self.backend.mailbox.probe().image==request.expected,'Real DB/image rollback failed')
        require(all(path.read_bytes()==body for name,body in before.items() for path in (Path(name),)),'Matching configuration was not restored')
        recovery=self.state/'operations'/request.request_id/'recovery'
        require(all((recovery/name).is_file() for name in ('database.sqlite3','image.tar','manifest.json','protected-fingerprint.json')),'Original recovery set was not retained')
        # Inspect the preserved FAILED volume database using the current app,
        # whose admission is open. It must contain the failed migration marker3.
        code="from pathlib import Path; import sqlite3; roots=list(Path('/app/data/.maintenance/recovery').glob('"+request.request_id+"/failed/*/keep.sqlite3')); assert len(roots)==1; db=sqlite3.connect(roots[0].as_uri()+'?mode=ro',uri=True); assert db.execute('SELECT value FROM maintenance_trial_schema').fetchone()==(3,); print('preserved')"
        require(self.inner('exec',self.ids()['keep-app'],'python','-B','-c',code).strip()==b'preserved','Failed migrated database evidence was lost')
        self.reacquire_request=request
        return {'request_id':request.request_id,'schema_restored':2,'failed_schema_preserved':3,'matched_recovery_retained':True,
                'completed_helpers_removed':self.assert_completed_helpers_removed(request)}

    def empty_store_reacquisition(self):
        request=self.reacquire_request
        identity=request.expected
        archive=self.state/'operations'/request.request_id/'recovery/image.tar'
        resolver=ArchiveOnlyResolver(self.paths,archive,identity)
        socket=self.paths.mkdir(self.root/'empty-store-socket')
        data=self.paths.mkdir(self.tool_state/'empty-store-daemon-data')
        name=self.name+'-empty-daemon'
        daemon=self.outer('run','--detach','--privileged','--name',name,'--label','io.keep.maintenance.trial='+self.name,
            '--network','none','--entrypoint',DIND_ENTRYPOINT,'--env','DOCKER_TLS_CERTDIR=',
            '--mount','type=bind,source='+str(socket)+',target=/trial-socket',
            '--mount','type=bind,source='+str(data)+',target=/var/lib/docker',
            TOOLING[0]['repository']+'@'+TOOLING[0]['index_digest'],*dind_arguments()).decode().strip()
        self.tools.append(daemon)
        row=json.loads(self.outer('inspect',daemon))[0]
        require(row.get('Id')==daemon and dind_startup_matches(row),'Empty-store startup wrapper differs')
        deadline=time.monotonic()+90
        while not (socket/'docker.sock').exists():
            require(time.monotonic()<deadline,'Empty-store socket did not appear');time.sleep(.2)
        self.outer('exec',daemon,'chown',str(os.geteuid())+':'+str(os.getegid()),'/trial-socket/docker.sock')
        self.outer('exec',daemon,'chmod','600','/trial-socket/docker.sock')
        endpoint='unix://'+str(socket/'docker.sock')
        context=self.name+'-empty'
        env={'PATH':self.env['PATH'],'HOME':str(self.root),'DOCKER_CONFIG':str(self.config)}
        def empty(*args,**kwargs):
            return run((self.profile.docker_executable,'--context',context,*args),env=env,**kwargs)
        run((self.profile.docker_executable,'context','create',context,'--docker','host='+endpoint),env=env)
        deadline=time.monotonic()+90
        while True:
            try:
                daemon_id=json.loads(empty('info','--format','{{json .ID}}'));break
            except TrialError:
                require(time.monotonic()<deadline,'Empty-store daemon did not start');time.sleep(.2)
        require(not empty('image','ls','--all','--quiet').strip(),'Reacquisition daemon was not empty')
        require(json.loads(empty('info','--format','{{json .RegistryConfig.Mirrors}}')) in ([],None),'Empty-store daemon has a registry mirror')
        require(json.loads(self.outer('inspect',daemon))[0]['HostConfig']['NetworkMode']=='none','Reacquisition daemon has external network access')
        empty('image','load','--input',archive,timeout=300)
        state=self.paths.mkdir(self.root/'empty-store-state')
        profile=replace(self.profile,state=state,docker_context=context,docker_endpoint=endpoint,daemon_id=daemon_id)
        adapter=PosixDockerAdapter(self.paths,profile,None,resolver=resolver)
        adapter.assert_daemon()
        observed=adapter.image(identity)
        code="import json,os,platform;from pathlib import Path;print(json.dumps({'uid':os.getuid(),'machine':platform.machine(),'version':Path('/app/VERSION').read_text().strip()}))"
        identifier=empty('create','--name',self.name+'-empty-proof','--label','io.keep.maintenance.trial='+self.name,
            '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pull','never',
            '--entrypoint','python',observed['SelectedReference'],'-B','-c',code).decode().strip()
        row=json.loads(empty('inspect',identifier))[0]
        require(row['Id']==identifier and (row['Config'].get('Labels') or {}).get('io.keep.maintenance.trial')==self.name,
            'Empty-store proof container identity changed')
        descriptor=row.get('ImageManifestDescriptor')
        require(isinstance(descriptor,dict) and descriptor.get('digest')==identity.native_digest,
            'Reloaded original index did not select the original native manifest')
        runtime=parse_json(empty('start','--attach',identifier),65536)
        require(runtime['uid']==10001 and runtime['version']==identity.version
            and {'x86_64':'amd64','amd64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(runtime['machine'])==self.architecture,
            'Reacquired original image runtime differs')
        require(not json.loads(empty('inspect',identifier))[0]['State']['Running'],'Empty-store proof container did not exit')
        empty('rm',identifier)
        require(not empty('ps','--all','--no-trunc','--format','{{.ID}}').strip(),'Empty-store proof container remains')
        self.empty_store_cleanup={'daemon_container_id':daemon,'proof_container_id':identifier,'proof_container_absent':True}
        return {'request_id':request.request_id,'image':identity.as_dict(),'empty_before_load':True,
            'original_index_loaded':True,'original_native_selected':True,'original_config_verified':True,
            'registry_assistance':False,'prior_cache_assistance':False,'runtime_uid':runtime['uid'],
            'archive_sha256':resolver.archive_proof['sha256']}

    def committed_crash(self):
        request=self.request('install',self.images_by_schema[4])
        command=(sys.executable,'-B',str(Path(__file__).resolve()),'--child-execute',request.request_id,'--state',str(self.state))
        result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=600,
            env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        require(result.returncode==91,'Real helper process did not terminate at the commit boundary')
        crash=parse_json(self.paths.read(self.state/('trial-crashed-'+request.request_id+'.json')))
        require(crash['request_id']==request.request_id and crash['phase']=='committed','Original terminated helper receipt differs')
        rows=Journal(self.paths,self.state,request.request_id,request.payload_sha256).records()
        require(rows[-1]['phase']=='committed','Process termination did not retain durable commit boundary')
        require(self.fixture('inspect')['new_writes']==1,'New admitted write did not commit before helper termination')
        resumed=subprocess.run((sys.executable,'-B',str(Path(__file__).resolve()),'--child-resume',request.request_id,'--state',str(self.state)),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        require(resumed.returncode==0,'Fresh helper could not reconstruct and resume the original private state')
        receipt=parse_json(self.paths.read(self.state/('trial-resumed-'+request.request_id+'.json')))
        require(receipt['request_id']==request.request_id and receipt['phase']=='success' and receipt['pid']!=crash['pid']
            and receipt['pid']!=os.getpid() and receipt['network_resolution'] is False,'Fresh helper reconstruction proof differs')
        require(self.fixture('inspect')=={'schema':4,'new_writes':1,'owner':'7'},'Fresh committed resume rolled back new writes')
        latest=Journal(self.paths,self.state,request.request_id,request.payload_sha256).records()
        require(not any(row['phase'].startswith('recover') for row in latest),'Post-commit resume attempted rollback')
        return {'request_id':request.request_id,'terminated_helper_pid':crash['pid'],'fresh_helper_pid':receipt['pid'],
            'new_admitted_write_preserved':True,'fresh_private_state_reconstruction':True,'registry_assistance':False,
            'post_commit_rollback':False,'schema':4,
            'completed_helpers_removed':self.assert_completed_helpers_removed(request)}

    def cleanup(self):
        # Only exact owned disposable tools/data. Recovery files remain in the
        # private host evidence directory; production helper cleanup is separate.
        if self.profile:
            containers=self.inner('ps','--all','--no-trunc','--format','{{.ID}}').decode().split()
            rows={identifier:json.loads(self.inner('inspect',identifier))[0] for identifier in containers}
            identities=tuple(getattr(self,'images_by_schema',{}).values())
            project_rows=[row for row in rows.values() if (row.get('Config',{}).get('Labels') or {}).get('com.docker.compose.project')==self.name]
            service_ids=set()
            if project_rows:
                adapter=PosixDockerAdapter(self.paths,self.profile,None,resolver=self.resolver)
                adapter.known_identities.update({image.image_id:image for image in identities})
                service_ids={row['Id'] for row in adapter.discover(images={image.image_id for image in identities}).values()}
            install_id=self.report.get('activation',{}).get('install_id')
            enrollment=None
            if isinstance(install_id,str) and install_id:
                try:canonical_uuid(install_id)
                except Exception:raise TrialError('Invalid activation identity; cleanup held') from None
                active=HostState(self.paths,self.state).active()
                mailbox=getattr(getattr(self,'backend',None),'mailbox',None)
                enrollment=getattr(mailbox,'enrollment',None)
                require(active is not None and active[0]['install_id']==install_id
                    and enrollment is not None and enrollment.install_id==install_id,
                    'Unverified activation identity; cleanup held')
            # Preflight every container and volume before any stop/removal. An
            # unrelated unlabeled resource must remain untouched even if owned
            # services appeared earlier in the Docker inventory.
            for identifier in containers:
                row=rows[identifier]
                require(row.get('Id')==identifier and re.fullmatch('[a-f0-9]{64}',identifier), 'Container identity changed; cleanup held')
                labels=row.get('Config',{}).get('Labels') or {}
                owned=identifier in service_ids
                if not owned and enrollment is not None and labels.get('io.keep.maintenance.install')==install_id:
                    operation=canonical_uuid(labels.get('io.keep.maintenance.operation'))
                    purpose=labels.get('io.keep.maintenance.purpose')
                    require(purpose in ('snapshot','preserve','prepare-restore','restore','upload'),'Unknown helper purpose; cleanup held')
                    request=mailbox.accepted_request(self.paths.read(self.state/'accepted-requests'/(operation+'.json'),limit=65536))
                    require(request.request_id==operation,'Helper operation identity differs; cleanup held')
                    selected=PosixDockerAdapter(self.paths,self.profile,enrollment,resolver=self.resolver,runner=mailbox.runner)
                    selected.bind(request)
                    original=parse_json(self.paths.read(selected.operation/('helper-'+purpose+'.json')))
                    require(original=={'container_id':identifier,'source_sha256':selected.source_sha},'Original helper ID/source differs; cleanup held')
                    selected.validate_helper(selected.inspect(identifier,helper=True),purpose,stopped=False)
                    owned=True
                require(owned,'Unexpected isolated daemon container; cleanup held')
            volumes=self.inner('volume','ls','--format','{{.Name}}').decode().split()
            for name in volumes:
                require(name==self.profile.volume,'Unexpected isolated volume; cleanup held')
            for identifier in containers:
                row=rows[identifier]
                if row['State']['Running']:self.inner('stop','--time','15',identifier,timeout=30)
                require(not json.loads(self.inner('inspect',identifier))[0]['State']['Running'],'Cleanup stop failed')
                self.inner('rm',identifier)
            for name in volumes:
                self.inner('volume','rm',name)
            self.report['cleanup']['trial_containers_removed']=len(containers)
            self.report['cleanup']['trial_volumes_removed']=volumes
            require(not self.inner('ps','--all','--no-trunc','--format','{{.ID}}').strip(),'Isolated trial containers remain')
            require(not self.inner('volume','ls','--format','{{.Name}}').strip(),'Isolated trial volumes remain')
            self.report['cleanup']['owned_service_helper_ids']=containers
            self.report['cleanup']['project']=self.name
        for index,identifier in reversed(list(enumerate(self.tools))):
            row=json.loads(self.outer('inspect',identifier))[0]
            if index:
                require(dind_startup_matches(row,self.name if index==1 else None),'Owned daemon startup changed')
            require((row.get('Config',{}).get('Labels') or {}).get('io.keep.maintenance.trial')==self.name,'Tooling identity changed')
            self.outer('stop','--time','15',identifier,timeout=30)
            self.outer('rm',identifier)
            require(not self.outer('ps','--all','--no-trunc','--filter','id='+identifier,'--format','{{.ID}}').strip(),'Owned tooling container remains')
        if self.network:
            row=json.loads(self.outer('network','inspect',self.network))[0]
            require(row.get('Labels',{}).get('io.keep.maintenance.trial')==self.name and not row.get('Containers'),'Tooling network changed')
            self.outer('network','rm',self.network)
            require(not self.outer('network','ls','--no-trunc','--filter','id='+self.network,'--format','{{.ID}}').strip(),'Owned tooling network remains')
        for tag,identifier in self.outer_images:
            actual=json.loads(self.outer('image','inspect',tag))[0]
            require(actual['Id']==identifier,'Fixture image alias changed')
            refs=self.outer('ps','--all','--no-trunc','--filter','ancestor='+identifier,'--format','{{.ID}}').strip()
            require(not refs,'Fixture image still referenced; cleanup held')
            self.outer('image','rm',tag)
            require(not self.outer('image','ls','--no-trunc','--filter','reference='+tag,'--format','{{.ID}}').strip(),'Owned fixture image alias remains')
        retained_ids=set(self.outer('image','ls','--all','--no-trunc','--quiet').decode().split())
        for tag,identifier in self.outer_images:
            if tag!=getattr(self,'base_alias',None):
                require(identifier not in retained_ids,'Owned fixture image ID remains')
        if getattr(self,'base_alias',None):
            require(json.loads(self.outer('image','inspect',self.candidate))[0]['Id']==self.report['base_image']['id'],
                'Original source-packaged candidate changed during cleanup')
        self.report['cleanup']['tooling_containers_removed']=self.tools
        self.report['cleanup']['fixture_images_removed']=len(self.outer_images)
        self.report['cleanup']['owned_image_aliases']=[{'alias':tag,'image_id':identifier} for tag,identifier in self.outer_images]
        self.report['cleanup']['owned_network_id']=self.network
        self.report['cleanup']['empty_store']=getattr(self,'empty_store_cleanup',None)
        self.report['cleanup']['source_candidate_preserved']=True
        self.report['cleanup']['resources_absent']=True

    def execute_all(self):
        try:
            self.record('isolated-native-daemon',self.tooling)
            self.record('source-packaged-real-registry-graphs',self.images)
            self.record('signed-enrollment-and-paired-compose',self.compose)
            self.record('restart-active-work-drain-and-duplicate',self.restart_and_drain)
            self.record('real-schema-upgrade',self.successful_install)
            self.record('unhealthy-schema-upgrade-matched-rollback',self.failed_upgrade)
            self.record('empty-store-original-index-reacquisition',self.empty_store_reacquisition)
            self.record('post-commit-crash-preserves-new-write',self.committed_crash)
            self.report['outcome']='passed'
        except Exception:
            self.report['outcome']='failed'
            raise
        finally:
            try:self.cleanup()
            except Exception as error:
                self.report['outcome']='failed';self.report['cleanup']['held']=type(error).__name__
                self.report['cleanup']['failure_details']=failure_details(error)
            self.report['private_evidence_directory']=str(self.root)
            self.evidence.parent.mkdir(parents=True,exist_ok=True)
            self.evidence.write_bytes(canonical(self.report)+b'\n')
            os.chmod(self.evidence,0o600)


def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ('--child-execute','--child-resume'):
        parser=argparse.ArgumentParser(description='Fixed native-trial child helper')
        parser.add_argument(argv[0],required=True,dest='identifier')
        parser.add_argument('--state',type=Path,required=True)
        args=parser.parse_args(argv)
        try:return child_helper(args.state,args.identifier,crash=argv[0]=='--child-execute')
        except Exception as error:
            print('Native helper child failed: '+type(error).__name__,file=sys.stderr)
            return 1
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-directory',type=Path,required=True)
    parser.add_argument('--integration-source',type=Path,required=True)
    parser.add_argument('--candidate-image',required=True)
    parser.add_argument('--architecture',choices=('amd64','arm64'),required=True)
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        trial=NativeTrial(args.source_directory,args.integration_source,args.candidate_image,args.architecture,args.evidence)
        trial.execute_all()
        require(trial.report['outcome']=='passed','Native qualification or cleanup failed')
    except (TrialError,EngineError,OSError,ValueError) as error:
        print('Native maintenance qualification failed: '+type(error).__name__,file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())
