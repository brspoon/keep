"""Fixed anonymous HTTPS authority for a published Keep release and OCI identity.

No requests occur at import time. Tests inject a byte-response client. URLs,
repository, redirects and registry token scope are fixed by this module.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from urllib.parse import urlsplit
import urllib.request

from maintenance_protocol import ImageIdentity, VERSION, canonical, parse_json
from host_engine import EngineError

MAX_JSON=524288
DIGEST=re.compile(r'sha256:[a-f0-9]{64}\Z')
MEDIA=('application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json',
       'application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json')


class HTTPSClient:
    HOSTS=frozenset(('api.github.com','github.com','release-assets.githubusercontent.com','auth.docker.io','registry-1.docker.io'))

    @classmethod
    def allowed(cls,url):
        parsed=urlsplit(url)
        if (parsed.scheme!='https' or parsed.hostname not in cls.HOSTS or parsed.username is not None
                or parsed.password is not None or parsed.port not in (None,443) or parsed.fragment):
            raise EngineError('Release transport destination is not allowed')
        return parsed

    def get(self,url,*,headers=None):
        self.allowed(url)
        allowed=self.allowed
        class Redirects(urllib.request.HTTPRedirectHandler):
            max_redirections=3
            max_repeats=1
            def redirect_request(self,req,fp,code,msg,response_headers,newurl):
                target=allowed(newurl)
                if req.has_header('Authorization') and target.hostname!=urlsplit(req.full_url).hostname:
                    raise EngineError('Registry authentication may not cross hosts')
                return super().redirect_request(req,fp,code,msg,response_headers,newurl)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirects())
        request=urllib.request.Request(url,headers={'User-Agent':'Keep-maintenance','Accept':'application/json',**(headers or {})})
        deadline=time.monotonic()+60
        try:
            with opener.open(request,timeout=15) as response:
                if response.status!=200:raise EngineError('Published release information is unavailable')
                declared=response.headers.get('Content-Length')
                if declared is not None and (not declared.isdecimal() or int(declared)>MAX_JSON):
                    raise EngineError('Published release information exceeded its bound')
                content=bytearray()
                while block:=response.read(65536):
                    content.extend(block)
                    if len(content)>MAX_JSON or time.monotonic()>deadline:
                        raise EngineError('Published release information exceeded its bound')
                return bytes(content),dict(response.headers)
        except (OSError,urllib.error.HTTPError,urllib.error.URLError) as error:
            raise EngineError('Published release transport failed') from error


class OfficialReleaseResolver:
    def __init__(self,client=None):
        self.client=client or HTTPSClient()
        self.configurations={};self.configuration_bytes={}

    def json(self,url,headers=None):
        body,metadata=self.client.get(url,headers=headers)
        return parse_json(body,MAX_JSON),body,metadata

    def _resolve(self,version,architecture,expected=None):
        if not isinstance(version,str) or not VERSION.fullmatch(version) or architecture not in ('amd64','arm64'):
            raise EngineError('Release selection is invalid')
        api='https://api.github.com/repos/brspoon/keep/releases/tags/'+version
        release,_,_=self.json(api)
        if (not isinstance(release,dict) or release.get('draft') is not False or release.get('prerelease') is not False
                or release.get('immutable') is not True or release.get('tag_name')!=version
                or type(release.get('id')) is not int or release['id']<=0 or not release.get('published_at')
                or release.get('html_url')!='https://github.com/brspoon/keep/releases/tag/'+version):
            raise EngineError('Keep release is not a finalized stable release')
        name='keep-'+version+'-release-materials.json'
        assets=release.get('assets')
        if not isinstance(assets,list) or len(assets)>64 or sum(asset.get('name')==name for asset in assets if isinstance(asset,dict))!=1:
            raise EngineError('Published release identity asset is unavailable')
        record,_,_=self.json('https://github.com/brspoon/keep/releases/download/'+version+'/'+name)
        if (not isinstance(record,dict) or record.get('version')!=version
                or not isinstance(record.get('images'),dict) or set(record['images'])!={'amd64','arm64'}):
            raise EngineError('Published release materials do not match')
        selected=record['images'][architecture]
        if not isinstance(selected,dict):raise EngineError('Published native release identity does not match')
        for arch,value in record['images'].items():
            if (not isinstance(value,dict) or value.get('architecture')!=arch or value.get('version')!=version
                    or value.get('revision')!=record.get('revision') or not DIGEST.fullmatch(str(value.get('native_digest')))
                    or not DIGEST.fullmatch(str(value.get('config_digest')))):
                raise EngineError('Published native release identity does not match')
        token,_,_=self.json('https://auth.docker.io/token?service=registry.docker.io&scope=repository:brspoon/keep:pull')
        token=token.get('token') if isinstance(token,dict) else None
        if not isinstance(token,str) or not 1<=len(token)<=16384 or any(ord(c)<33 for c in token):
            raise EngineError('Anonymous registry authorization is invalid')
        headers={'Authorization':'Bearer '+token,'Accept':', '.join(MEDIA)}
        registry='https://registry-1.docker.io/v2/brspoon/keep/manifests/'
        index,index_bytes,index_headers=self.json(registry+version,headers)
        digest='sha256:'+hashlib.sha256(index_bytes).hexdigest()
        declared=next((value for name,value in index_headers.items() if name.lower()=='docker-content-digest'),digest)
        if (declared!=digest or not isinstance(index,dict) or index.get('schemaVersion')!=2
                or index.get('mediaType') not in MEDIA[:2]):
            raise EngineError('Published index identity does not match')
        manifests=index.get('manifests')
        if not isinstance(manifests,list) or not 2<=len(manifests)<=16 or any(not isinstance(entry,dict) for entry in manifests):
            raise EngineError('Published index native children are incomplete')
        for arch,value in record['images'].items():
            matches=[entry for entry in manifests if isinstance(entry.get('platform'),dict)
                     and entry['platform'].get('os')=='linux' and entry['platform'].get('architecture')==arch]
            if len(matches)!=1 or matches[0].get('digest')!=value['native_digest']:
                raise EngineError('Published native manifest does not match')
        target=ImageIdentity.from_dict({'index_digest':digest,'native_digest':selected['native_digest'],
            'image_id':selected['config_digest'],'version':version,'revision':record.get('revision'),'architecture':architecture})
        if expected is not None and target!=expected:
            raise EngineError('Published release does not match the accepted immutable identity')
        manifest,manifest_bytes,metadata=self.json(registry+target.native_digest,headers)
        if ('sha256:'+hashlib.sha256(manifest_bytes).hexdigest()!=target.native_digest or not isinstance(manifest,dict) or manifest.get('schemaVersion')!=2
                or manifest.get('mediaType') not in MEDIA[2:] or not isinstance(manifest.get('config'),dict)
                or manifest['config'].get('digest')!=target.image_id):
            raise EngineError('Published native configuration does not match')
        layers=manifest.get('layers')
        if not isinstance(layers,list) or not 1<=len(layers)<=128 or any(
                not isinstance(layer,dict) or not isinstance(layer.get('digest'),str) or not DIGEST.fullmatch(layer['digest'])
                or type(layer.get('size')) is not int or not 0<=layer['size']<=4*1024**3 for layer in layers):
            raise EngineError('Published native layers are invalid')
        if sum(layer['size'] for layer in layers)>32*1024**3:raise EngineError('Published native layers exceed the image bound')
        configuration,configuration_bytes,_=self.json('https://registry-1.docker.io/v2/brspoon/keep/blobs/'+target.image_id,headers)
        if not isinstance(configuration,dict) or not isinstance(configuration.get('config'),dict):
            raise EngineError('Published native configuration bytes do not match')
        labels=configuration['config'].get('Labels',{})
        rootfs=configuration.get('rootfs',{})
        if ('sha256:'+hashlib.sha256(configuration_bytes).hexdigest()!=target.image_id
                or configuration.get('architecture')!=architecture or configuration.get('os')!='linux'
                or not isinstance(labels,dict)
                or labels.get('org.opencontainers.image.version')!=version
                or labels.get('org.opencontainers.image.revision')!=target.revision
                or labels.get('org.opencontainers.image.source')!='https://github.com/brspoon/keep'
                or configuration['config'].get('User')!='10001:10001' or not isinstance(rootfs,dict)
                or rootfs.get('type')!='layers' or not isinstance(rootfs.get('diff_ids'),list)
                or len(rootfs['diff_ids'])!=len(layers) or any(not DIGEST.fullmatch(str(value)) for value in rootfs['diff_ids'])):
            raise EngineError('Published native configuration bytes do not match')
        self.configurations[target.reference]={'RootFS':rootfs['diff_ids'],'User':'10001:10001','Labels':labels}
        self.configuration_bytes[target.reference]=configuration_bytes
        return target

    def resolve(self,target):
        target=ImageIdentity.from_dict(target.as_dict())
        return self._resolve(target.version,target.architecture,target)

    def resolve_version(self,version,architecture):
        return self._resolve(version,architecture)

    def latest(self,architecture,installed_version):
        if not isinstance(installed_version,str) or not VERSION.fullmatch(installed_version):
            raise EngineError('Installed release version is invalid')
        release,_,_=self.json('https://api.github.com/repos/brspoon/keep/releases/latest')
        version=release.get('tag_name') if isinstance(release,dict) else None
        if not isinstance(version,str) or not VERSION.fullmatch(version):raise EngineError('Latest release is unavailable')
        if tuple(map(int,version.split('.')))<=tuple(map(int,installed_version.split('.'))):return None
        return self.resolve_version(version,architecture)
