"""Synthetic publication-gate tests; these fixtures never qualify native Docker."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import release_materials as materials


def write_maintenance_sources(root):
    """Small distinct source bytes for isolated parser/integrity tests only."""
    root = Path(root).resolve()
    repository = Path(materials.__file__).resolve().parents[1]
    files = {'app.py', 'onboarding.py', 'maintenance_app.py', 'maintenance_mailbox.py',
             'maintenance_protocol.py', 'private_store.py', *materials.HELPER_FILES,
             'tests/maintenance_trial_fixture.py', 'tests/portable_trial.py',
             'static/keep-maintenance.js', 'static/keep-maintenance.css', 'static/keep-about.js',
             'templates/about.html', 'templates/about_maintenance.html'}
    for name in files:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        original = repository / name
        path.write_bytes(original.read_bytes() if original.is_file()
                         else ('# synthetic source: ' + name + '\n').encode())
    if not (repository / 'maintenance_mailbox.py').is_file():
        (root / 'maintenance_mailbox.py').write_bytes(b'RUNTIME_QUALIFIED = False\n')
    tooling = [{'repository': 'library/' + name, 'index_digest': 'sha256:' + str(number) * 64,
                'native': {'amd64': 'sha256:' + str(number + 2) * 64,
                           'arm64': 'sha256:' + str(number + 4) * 64}}
               for number, name in enumerate(('docker', 'registry'), 1)]
    (root / 'scripts').mkdir(exist_ok=True)
    runner = repository / 'scripts/maintenance_container_trial.py'
    (root / 'scripts/maintenance_container_trial.py').write_bytes(
        runner.read_bytes() if runner.is_file() else ('TOOLING = ' + repr(tooling) + '\n').encode())


def synthetic_maintenance_proof(root, identity):
    """Build self-contained unit input, never a real execution receipt."""
    arch = identity['architecture']
    with patch.object(materials, 'MAINTENANCE_ROOT', Path(root).resolve()):
        runner, sources, helpers, tools = materials.maintenance_sources()
        bundle, _ = materials.helper_package(materials.MAINTENANCE_ROOT, '0.0.1', identity['revision'])
    project = 'keep-maintenance-native-012345abcdef'
    images = {}
    for number in range(1, 5):
        def digest(kind):
            return 'sha256:' + hashlib.sha256(
                ('synthetic-maintenance-' + arch + '-' + str(number) + '-' + kind).encode()).hexdigest()
        images['0.0.' + str(number)] = {
            'index_digest': digest('index'),
            'native_digest': digest('native'),
            'image_id': digest('config'),
            'version': '0.0.' + str(number), 'revision': identity['revision'], 'architecture': arch}
    phases = [{'name': name, 'status': 'passed'} for name in materials.MAINTENANCE_PHASES]
    fields = {
        3: {'request_id': '10000000-0000-4000-8000-000000000001', 'journal_records': 12,
            'gate_closed_with_writer_held': True, 'ordinary_http_status': 503,
            'protected_write_before_stop': True, 'protected_write_in_snapshot': True,
            'duplicate_operation_unchanged': True, 'completed_helpers_removed': 1},
        4: {'request_id': '10000000-0000-4000-8000-000000000002', 'schema': 2, 'completed_helpers_removed': 1},
        5: {'request_id': '10000000-0000-4000-8000-000000000003', 'schema_restored': 2,
            'failed_schema_preserved': 3, 'matched_recovery_retained': True, 'completed_helpers_removed': 4},
        6: {'request_id': '10000000-0000-4000-8000-000000000003', 'image': images['0.0.2'],
            'empty_before_load': True, 'original_index_loaded': True, 'original_native_selected': True,
            'original_config_verified': True, 'registry_assistance': False, 'prior_cache_assistance': False,
            'runtime_uid': 10001, 'archive_sha256': 'c' * 64},
        7: {'request_id': '10000000-0000-4000-8000-000000000004', 'terminated_helper_pid': 100,
            'fresh_helper_pid': 101, 'new_admitted_write_preserved': True,
            'fresh_private_state_reconstruction': True, 'registry_assistance': False,
            'post_commit_rollback': False, 'schema': 4, 'completed_helpers_removed': 1},
    }
    for index, extra in fields.items():
        phases[index].update(extra)
    return {'schema': 'keep.maintenance-native-trial.v1', 'architecture': arch, 'outcome': 'passed',
            'candidate': {'version': identity['version'], 'revision': identity['revision'], 'architecture': arch,
                          'os': 'linux', 'image_id': identity['config_digest']},
            'base_image': {'id': identity['config_digest'], 'config_digest': identity['config_digest'],
                           'revision': identity['revision'], 'version': identity['version'], 'reference': 'keep-ci:latest'},
            'project': project, 'runner_sha256': runner, 'source_files': sources,
            'activation': {'install_id': '10000000-0000-4000-8000-000000000000',
                           'context': project, 'daemon_id': 'synthetic-native-daemon'},
            'helper_sources': helpers, 'helper_bundle_sha256': hashlib.sha256(bundle).hexdigest(),
            'tooling': [{'reference': tool['repository'] + '@' + tool['index_digest'],
                         'native_digest': tool['native'][arch], 'local_id': 'sha256:' + str(index + 1) * 64}
                        for index, tool in enumerate(tools)],
            'client_binary_sha256': 'b' * 64, 'compose_binary_sha256': 'c' * 64,
            'images': images, 'phases': phases,
            'cleanup': {'resources_absent': True, 'trial_volumes_removed': [project + '_keep-data'],
                        'trial_containers_removed': 2, 'fixture_images_removed': 5,
                        'tooling_containers_removed': [character * 64 for character in 'abc'],
                        'project': project, 'source_candidate_preserved': True,
                        'owned_service_helper_ids': ['d' * 64, 'e' * 64],
                        'owned_image_aliases': [{'alias': project + '-base:source', 'image_id': identity['config_digest']}]
                            + [{'alias': project + '-image:' + version, 'image_id': image['index_digest']}
                               for version, image in images.items()],
                        'owned_network_id': 'f' * 64,
                        'empty_store': {'daemon_container_id': 'c' * 64, 'proof_container_id': '1' * 64,
                                        'proof_container_absent': True}}}


class MaintenanceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        write_maintenance_sources(self.root)
        changed = patch.object(materials, 'MAINTENANCE_ROOT', self.root)
        changed.start()
        self.addCleanup(changed.stop)
        self.identity = {'version': '2.26.0', 'revision': 'a' * 40, 'architecture': 'amd64',
                         'config_digest': 'sha256:' + 'd' * 64}
        self.proof = synthetic_maintenance_proof(self.root, self.identity)

    def validate(self, proof=None):
        return materials.maintenance_evidence_bytes(json.dumps(self.proof if proof is None else proof).encode(),
                                                    'amd64', self.identity)

    def test_original_formatting_is_preserved_and_both_native_architectures_are_bound(self):
        for arch in materials.ARCHES:
            identity = {**self.identity, 'architecture': arch}
            proof = synthetic_maintenance_proof(self.root, identity)
            path = self.root / ('proof-' + arch + '.json')
            data = ('  ' + json.dumps(proof, indent=3) + '\r\n').encode()
            path.write_bytes(data)
            self.assertEqual(materials.maintenance_evidence(path, arch, identity), proof)
            self.assertEqual(path.read_bytes(), data)

    def test_missing_oversized_symlink_and_duplicate_json_cannot_be_used(self):
        path = self.root / 'missing.json'
        with self.assertRaises(ValueError): materials.maintenance_evidence(path, 'amd64', self.identity)
        path.write_bytes(b'x' * (materials.MAINTENANCE_LIMIT + 1))
        with self.assertRaises(ValueError): materials.maintenance_evidence(path, 'amd64', self.identity)
        path.unlink(); path.symlink_to(self.root / 'app.py')
        with self.assertRaises(ValueError): materials.maintenance_evidence(path, 'amd64', self.identity)
        for data in (b'{"outcome":"failed","outcome":"passed"}', b'{"value":NaN}', b'[]'):
            with self.assertRaises(ValueError): materials.maintenance_evidence_bytes(data, 'amd64', self.identity)

    def test_other_candidate_or_failed_outcome_is_rejected(self):
        for key, value in (('image_id', 'sha256:' + 'e' * 64), ('version', '2.25.0'),
                           ('revision', 'b' * 40), ('architecture', 'arm64'), ('os', 'windows')):
            proof = copy.deepcopy(self.proof); proof['candidate'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate(proof)
        for key, value in (('outcome', 'failed'), ('architecture', 'arm64'), ('schema', 'mock-native.v1')):
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate({**self.proof, key: value})

    def test_current_application_fixture_helper_and_runner_bytes_are_required(self):
        for name in ('app.py', 'onboarding.py', 'maintenance_app.py', 'maintenance_mailbox.py',
                     'tests/maintenance_trial_fixture.py', 'tests/portable_trial.py', 'host_engine.py',
                     'scripts/maintenance_container_trial.py', 'static/keep-maintenance.js'):
            path = self.root / name; original = path.read_bytes()
            path.write_bytes(original + b'# changed after native trial\n')
            with self.subTest(name=name), self.assertRaises(ValueError): self.validate()
            path.write_bytes(original)
        proof = copy.deepcopy(self.proof); proof['source_files']['maintenance_mailbox.py']['fixture_sha256'] = '0' * 64
        with self.assertRaises(ValueError): self.validate(proof)
        proof = copy.deepcopy(self.proof); proof['helper_sources'].pop('host_engine.py')
        with self.assertRaises(ValueError): self.validate(proof)

    def test_every_lifecycle_phase_is_required_in_order_once(self):
        for index in range(len(self.proof['phases'])):
            for action in ('missing', 'failed', 'skipped', 'duplicate'):
                proof = copy.deepcopy(self.proof)
                if action == 'missing': proof['phases'].pop(index)
                elif action == 'duplicate': proof['phases'].append(proof['phases'][index])
                else: proof['phases'][index]['status'] = action
                with self.subTest(index=index, action=action), self.assertRaises(ValueError): self.validate(proof)

    def test_elapsed_time_same_process_and_cached_archive_are_insufficient(self):
        for index, key, value in ((3, 'gate_closed_with_writer_held', False), (3, 'ordinary_http_status', 200),
                                  (3, 'protected_write_in_snapshot', False), (3, 'duplicate_operation_unchanged', False),
                                  (5, 'matched_recovery_retained', False), (6, 'empty_before_load', False),
                                  (6, 'registry_assistance', True), (6, 'prior_cache_assistance', True),
                                  (6, 'original_index_loaded', False), (7, 'fresh_private_state_reconstruction', False),
                                  (7, 'fresh_helper_pid', 100), (7, 'post_commit_rollback', True),
                                  (7, 'new_admitted_write_preserved', False)):
            proof = copy.deepcopy(self.proof); proof['phases'][index][key] = value
            with self.subTest(key=key, index=index), self.assertRaises(ValueError): self.validate(proof)

    def test_resource_holds_wrong_volume_and_incomplete_cleanup_block_publication(self):
        for key, value in (('resources_absent', False), ('trial_volumes_removed', ['other_data']),
                           ('fixture_images_removed', 4), ('trial_containers_removed', 0),
                           ('held', 'TrialError'), ('tooling_containers_removed', ['a' * 64, 'b' * 64])):
            proof = copy.deepcopy(self.proof); proof['cleanup'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate(proof)

    def test_trial_teardown_cannot_substitute_for_completed_helper_cleanup(self):
        for index in (3,4,5,7):
            for value in (None,0,True,99):
                proof=copy.deepcopy(self.proof)
                if value is None:proof['phases'][index].pop('completed_helpers_removed')
                else:proof['phases'][index]['completed_helpers_removed']=value
                with self.subTest(index=index,value=value),self.assertRaises(ValueError):self.validate(proof)

    def test_enrollment_namespace_and_exact_cleanup_identities_are_required(self):
        changes = ((('activation', 'context'), 'other'), (('activation', 'install_id'), 'bad'),
                   (('cleanup', 'project'), 'other'), (('cleanup', 'source_candidate_preserved'), False),
                   (('cleanup', 'owned_service_helper_ids'), ['d' * 64, 'd' * 64]),
                   (('cleanup', 'owned_network_id'), 'short-id'),
                   (('cleanup', 'empty_store', 'proof_container_absent'), False),
                   (('cleanup', 'empty_store', 'daemon_container_id'), 'f' * 64))
        for keys, value in changes:
            proof = copy.deepcopy(self.proof); node = proof
            for key in keys[:-1]: node = node[key]
            node[keys[-1]] = value
            with self.subTest(keys=keys), self.assertRaises(ValueError): self.validate(proof)
        proof = copy.deepcopy(self.proof)
        proof['cleanup']['owned_image_aliases'][1]['alias'] = 'other/image:0.0.1'
        with self.assertRaises(ValueError): self.validate(proof)


if __name__ == '__main__':
    unittest.main()
