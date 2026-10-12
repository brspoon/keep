"""Bounded Docker29/containerd-style archive verification without Docker."""
from dataclasses import replace
import copy
import gzip
import hashlib
import io
import tarfile
from unittest.mock import patch

from maintenance_protocol import canonical, parse_json
from private_store import StorageError
from recovery_set import (verify_docker_save, ATTESTATION_TYPE, ATTESTATION_LAYER,
                          EMPTY_CONFIG, EMPTY_DIGEST, MAX_ATTESTATION_JSON)
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

    def attested(self, *, mutate=None, inline=True, stored_empty=True, layer_body=None, wrong_diff=False):
        identity,members=self.fixture(wrong_diff=wrong_diff)
        native=parse_json(members['blobs/sha256/'+identity.index_digest[7:]])['manifests'][0]
        statement=canonical({'_type':'https://in-toto.io/Statement/v0.1',
            'subject':[{'name':'synthetic-native','digest':{'sha256':identity.native_digest[7:]}}],
            'predicateType':'https://slsa.dev/provenance/v1','predicate':{}}) if layer_body is None else layer_body
        layer_sha='sha256:'+hashlib.sha256(statement).hexdigest()
        config={'mediaType':EMPTY_CONFIG,'digest':EMPTY_DIGEST,'size':2}
        if inline:config['data']='e30='
        manifest={'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json',
            'artifactType':ATTESTATION_TYPE,'subject':{key:native[key] for key in ('mediaType','digest','size')},
            'config':config,'layers':[{'mediaType':ATTESTATION_LAYER,'digest':layer_sha,'size':len(statement),
                'annotations':{'in-toto.io/predicate-type':'https://slsa.dev/provenance/v1'}}]}
        descriptor={'mediaType':'application/vnd.oci.image.manifest.v1+json','artifactType':ATTESTATION_TYPE,
                    'annotations':{'io.containerd.manifest.subject':identity.native_digest}}
        if mutate:mutate(manifest,descriptor)
        body=canonical(manifest);digest='sha256:'+hashlib.sha256(body).hexdigest()
        descriptor.update(digest=digest,size=len(body))
        top=parse_json(members['index.json']);top['manifests'].append(descriptor)
        members['index.json']=canonical(top)
        members['blobs/sha256/'+digest[7:]]=body
        members['blobs/sha256/'+layer_sha[7:]]=statement
        if stored_empty:members['blobs/sha256/'+EMPTY_DIGEST[7:]]=b'{}'
        return identity,members

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

    def test_docker29_subject_bound_attestation_preserves_original_image_and_archive_bytes(self):
        for inline,stored in ((True,True),(True,False),(False,True)):
            identity,members=self.attested(inline=inline,stored_empty=stored)
            original_index=members['blobs/sha256/'+identity.index_digest[7:]]
            # Selection is by the exact original index, not its array position.
            top=parse_json(members['index.json']);top['manifests'].reverse();members['index.json']=canonical(top)
            path=self.archive(members);before=path.read_bytes()
            with self.subTest(inline=inline,stored=stored):
                proof=verify_docker_save(self.paths,path,identity)
                self.assertEqual(proof,{'sha256':hashlib.sha256(before).hexdigest(),'bytes':len(before)})
                self.assertEqual(path.read_bytes(),before)
                self.assertEqual('sha256:'+hashlib.sha256(original_index).hexdigest(),identity.index_digest)
        self.assertFalse((self.state/'blobs').exists())

    def test_unrelated_runnable_or_wrong_subject_attachments_are_rejected(self):
        mutations=(
            lambda manifest,desc:manifest['subject'].update(digest='sha256:'+'0'*64),
            lambda manifest,desc:manifest['subject'].update(size=manifest['subject']['size']+1),
            lambda manifest,desc:manifest['subject'].update(size=float(manifest['subject']['size'])),
            lambda manifest,desc:manifest['subject'].update(mediaType='application/vnd.oci.image.index.v1+json'),
            lambda manifest,desc:manifest.update(artifactType='application/other'),
            lambda manifest,desc:manifest['config'].update(mediaType='application/vnd.oci.image.config.v1+json'),
            lambda manifest,desc:desc.update(platform={'os':'linux','architecture':'amd64'}),
            lambda manifest,desc:manifest['layers'][0].update(mediaType='application/vnd.oci.image.layer.v1.tar'),
            lambda manifest,desc:desc.update(annotations={'io.containerd.image.name':'other/app:latest'}),
            lambda manifest,desc:desc.update(annotations={'io.containerd.manifest.subject':'sha256:'+'0'*64}),
        )
        for mutate in mutations:
            identity,members=self.attested(mutate=mutate)
            with self.subTest(mutate=mutate),self.assertRaises(StorageError):
                verify_docker_save(self.paths,self.archive(members),identity)

    def test_original_index_is_still_required_once_with_related_attachments(self):
        for change in ('missing','duplicate-index','extra-index','duplicate-attestation'):
            identity,members=self.attested();top=parse_json(members['index.json'])
            if change=='missing':top['manifests'].pop(0)
            elif change=='duplicate-index':top['manifests'].append(copy.deepcopy(top['manifests'][0]))
            elif change=='extra-index':
                top['manifests'].append({**top['manifests'][0],'digest':'sha256:'+'0'*64})
            else:top['manifests'].append(copy.deepcopy(top['manifests'][1]))
            members['index.json']=canonical(top)
            with self.subTest(change=change),self.assertRaises(StorageError):
                verify_docker_save(self.paths,self.archive(members),identity)

    def test_empty_inline_configuration_is_verified_only_for_attestations(self):
        for changes in ({'data':'bm90LWVtcHR5'},{'data':'e31='},{'data':'e30=\n'},
                        {'digest':'sha256:'+'0'*64},{'size':3},{'size':True},{'urls':['https://example.invalid']},
                        {'data':None}):
            identity,members=self.attested(mutate=lambda manifest,desc:manifest['config'].update(changes))
            with self.subTest(changes=changes),self.assertRaises(StorageError):
                verify_docker_save(self.paths,self.archive(members),identity)
        identity,members=self.attested();members['blobs/sha256/'+EMPTY_DIGEST[7:]]=b'[]'
        with self.assertRaises(StorageError):verify_docker_save(self.paths,self.archive(members),identity)
        identity,members=self.attested(inline=False,stored_empty=False)
        with self.assertRaises(StorageError):verify_docker_save(self.paths,self.archive(members),identity)
        # The ordinary native image configuration must still reject data even
        # when its inline bytes claim to be a valid empty descriptor.
        identity,members=self.attested()
        native_name='blobs/sha256/'+identity.native_digest[7:]
        native=parse_json(members[native_name]);native['config']['data']='e30='
        body=canonical(native);digest='sha256:'+hashlib.sha256(body).hexdigest()
        root=parse_json(members['blobs/sha256/'+identity.index_digest[7:]])
        root['manifests'][0].update(digest=digest,size=len(body))
        index=canonical(root);index_sha='sha256:'+hashlib.sha256(index).hexdigest()
        members['blobs/sha256/'+digest[7:]]=body;members['blobs/sha256/'+index_sha[7:]]=index
        top=parse_json(members['index.json']);top['manifests'][0].update(digest=index_sha,size=len(index))
        members['index.json']=canonical(top)
        with self.assertRaisesRegex(StorageError,'descriptor'):
            verify_docker_save(self.paths,self.archive(members),replace(identity,index_digest=index_sha,native_digest=digest))

    def test_attestation_and_payload_bytes_json_and_bounds_are_verified(self):
        identity,members=self.attested();top=parse_json(members['index.json']);att_name='blobs/sha256/'+top['manifests'][1]['digest'][7:]
        members[att_name]+=b'corrupt'
        with self.assertRaises(StorageError):verify_docker_save(self.paths,self.archive(members),identity)
        for body in (b'not JSON',b'[]',b'x'*(MAX_ATTESTATION_JSON+1)):
            identity,members=self.attested(layer_body=body)
            with self.subTest(body_size=len(body)),self.assertRaises(StorageError):
                verify_docker_save(self.paths,self.archive(members),identity)
        identity,members=self.attested(mutate=lambda manifest,desc:manifest['layers'][0].update(size=100000))
        with self.assertRaises(StorageError):verify_docker_save(self.paths,self.archive(members),identity)

    def test_distinct_related_attachments_are_bounded_and_do_not_add_an_image(self):
        identity,members=self.attested();top=parse_json(members['index.json'])
        original=top['manifests'][1]
        body=parse_json(members['blobs/sha256/'+original['digest'][7:]])
        for number in range(1,17):
            changed={**body,'annotations':{'synthetic.test':str(number)}}
            data=canonical(changed);digest='sha256:'+hashlib.sha256(data).hexdigest()
            members['blobs/sha256/'+digest[7:]]=data
            top['manifests'].append({**original,'digest':digest,'size':len(data)})
            members['index.json']=canonical(top)
            if number == 1:
                verify_docker_save(self.paths,self.archive(members),identity)
        with self.assertRaises(StorageError):verify_docker_save(self.paths,self.archive(members),identity)

    def test_attached_metadata_does_not_bypass_native_config_or_uncompressed_layer_hashes(self):
        identity,members=self.attested(wrong_diff=True)
        with self.assertRaisesRegex(StorageError,'uncompressed layer'):
            verify_docker_save(self.paths,self.archive(members),identity)
        identity,members=self.attested();layer=next(name for name,data in members.items() if data.startswith(b'\x1f\x8b'))
        members[layer]+=b'corrupt'
        with self.assertRaises(StorageError):verify_docker_save(self.paths,self.archive(members),identity)
        identity,members=self.attested()
        with self.assertRaises(StorageError):
            verify_docker_save(self.paths,self.archive(members),replace(identity,image_id='sha256:'+'0'*64))
