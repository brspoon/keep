"""Bounded Docker29/containerd-style archive verification without Docker."""
from dataclasses import replace
import gzip
import hashlib
import io
import tarfile
from unittest.mock import patch

from maintenance_protocol import canonical
from private_store import StorageError
from recovery_set import verify_docker_save
from test_drafts import DraftFixture, image


class OCIArchiveTests(DraftFixture):
    def fixture(self,*,compression='gzip',wrong_diff=False,raw=None):
        raw=raw if raw is not None else b'bounded synthetic uncompressed native filesystem\n'*20
        layer=gzip.compress(raw,mtime=0) if compression=='gzip' else raw
        sha=lambda data:'sha256:'+hashlib.sha256(data).hexdigest()
        mime='application/vnd.oci.image.layer.v1.tar'+('+gzip' if compression=='gzip' else '+zstd' if compression=='zstd' else '')
        config=canonical({'os':'linux','architecture':'amd64','config':{'User':'10001:10001','Labels':{
            'org.opencontainers.image.version':'2.25.0','org.opencontainers.image.revision':'d'*40,
            'org.opencontainers.image.source':'https://github.com/brspoon/keep'}},
            'rootfs':{'type':'layers','diff_ids':['sha256:'+'0'*64 if wrong_diff else sha(raw)]}})
        native=canonical({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json',
            'config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':sha(config),'size':len(config)},
            'layers':[{'mediaType':mime,'digest':sha(layer),'size':len(layer)}]})
        child={'mediaType':'application/vnd.oci.image.manifest.v1+json','digest':sha(native),'size':len(native),
            'platform':{'os':'linux','architecture':'amd64'}}
        index=canonical({'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','manifests':[
            child,{'mediaType':'application/vnd.oci.image.manifest.v1+json','digest':'sha256:'+'8'*64,'size':100,
                'platform':{'os':'linux','architecture':'arm64'}}]})
        identity=replace(image('2.25.0','d'),index_digest=sha(index),native_digest=sha(native),image_id=sha(config))
        path=lambda data:'blobs/sha256/'+sha(data)[7:]
        members={'oci-layout':canonical({'imageLayoutVersion':'1.0.0'}),'index.json':canonical({
            'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','manifests':[
                {'mediaType':'application/vnd.oci.image.index.v1+json','digest':sha(index),'size':len(index)}]}),
            path(index):index,path(native):native,path(config):config,path(layer):layer,
            'manifest.json':canonical([{'Config':path(config),'RepoTags':None,'Layers':[path(layer)]}])}
        return identity,members

    def archive(self,members):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as tar:
            for name,data in members.items():
                info=tarfile.TarInfo(name);info.size=len(data);tar.addfile(info,io.BytesIO(data))
        path=self.state/'image.tar';self.paths.publish(path,stream.getvalue(),overwrite=True)
        return path

    def test_original_index_native_config_compressed_blob_and_uncompressed_diff_are_verified(self):
        for compression in ('gzip','raw'):
            identity,members=self.fixture(compression=compression)
            with self.subTest(compression=compression):
                proof=verify_docker_save(self.paths,self.archive(members),identity)
                self.assertGreater(proof['bytes'],0)
        self.assertFalse((self.state/'blobs').exists())

    def test_native_only_export_cannot_replace_original_index_recovery(self):
        identity,members=self.fixture();members['index.json']=canonical({'schemaVersion':2,
            'mediaType':'application/vnd.oci.image.index.v1+json','manifests':[
                {'mediaType':'application/vnd.oci.image.manifest.v1+json','digest':identity.native_digest,
                    'size':len(members['blobs/sha256/'+identity.native_digest[7:]])}]})
        with self.assertRaises(StorageError):verify_docker_save(self.paths,self.archive(members),identity)

    def test_changed_native_config_and_layer_bytes_hold_without_extraction(self):
        for field in ('index_digest','native_digest','image_id'):
            identity,members=self.fixture()
            with self.subTest(field=field),self.assertRaises(StorageError):
                verify_docker_save(self.paths,self.archive(members),replace(identity,**{field:'sha256:'+'0'*64}))
        identity,members=self.fixture();layer=next(name for name,data in members.items() if data.startswith(b'\x1f\x8b'))
        members[layer]+=b'corrupt'
        with self.assertRaises(StorageError):verify_docker_save(self.paths,self.archive(members),identity)

    def test_wrong_uncompressed_diff_and_unsupported_zstd_hold(self):
        for args in ({'wrong_diff':True},{'compression':'zstd'}):
            identity,members=self.fixture(**args)
            with self.subTest(args=args),self.assertRaises(StorageError):
                verify_docker_save(self.paths,self.archive(members),identity)

    def test_streaming_decompression_has_size_and_deadline_bounds(self):
        identity,members=self.fixture(raw=b'x'*100000);path=self.archive(members)
        with patch('recovery_set.MAX_IMAGE',path.stat().st_size),self.assertRaises(StorageError):
            # All compressed/metadata bytes match their descriptors and fit
            # admission; the expanded native filesystem exceeds its bound.
            verify_docker_save(self.paths,path,identity)
        identity,members=self.fixture();path=self.archive(members)
        with patch('recovery_set.time.monotonic',side_effect=[0,301]),self.assertRaises(StorageError):
            verify_docker_save(self.paths,path,identity)

    def test_unknown_blob_and_docker_compatibility_metadata_substitution_hold(self):
        identity,members=self.fixture();members['blobs/sha256/'+'0'*64]=b'foreign'
        with self.assertRaises(StorageError):verify_docker_save(self.paths,self.archive(members),identity)
        identity,members=self.fixture();members['manifest.json']=canonical([{'Config':'other.json','RepoTags':None,'Layers':[]}])
        with self.assertRaises(StorageError):verify_docker_save(self.paths,self.archive(members),identity)
