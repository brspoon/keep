"""A component review needs complete, matching runtime and all-layer proof."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from scripts import image_distribution as image


class SQLiteComponentReviewTests(unittest.TestCase):
    def fixture(self):
        lock = json.loads((ROOT / 'docs/os-package-sources.json').read_bytes())
        origin = next(row for row in lock['origins'] if row['origin'] == 'sqlite')
        vendor = origin['packages'][0]
        package = {'name': 'sqlite-libs', 'version': '3.53.4-r0', 'origin': 'sqlite',
            'provides': ['so:libsqlite3.so.0=3.53.4'],
            'payloads': ['usr/lib/libsqlite3.so.0', 'usr/lib/libsqlite3.so.3.53.4']}
        inventory = {'os_packages': [{**{key: vendor[key] for key in
            ('name', 'version', 'build_commit', 'license')}, 'origin': 'sqlite'}],
            'sqlite_cli': {'schema': 1, 'scope': 'runtime-filesystem', 'success': True,
                'findings': [], 'checked_bin_directories': ['/usr/bin', '/venv/bin'],
                'apk_metadata': {'path': '/lib/apk/db/installed', 'sha256': 'a' * 64,
                                  'packages': [package]}}}
        layers = {'architecture': 'amd64', 'config_sha256': 'e' * 64, 'success': True, 'findings': [],
            'layers': [{'diff_id': 'sha256:' + 'b' * 64, 'files': 10, 'bytes': 100}],
            'sqlite_cli': {'schema': 1, 'scope': 'all-image-layers', 'success': True,
                'layers_scanned': 1, 'files_scanned': 10, 'elf_files_scanned': 2,
                'findings': [], 'limitations': image.SQLITE_CLI_LIMITATIONS,
                'apk_metadata': [{'layer': 0, 'path': 'lib/apk/db/installed',
                    'sha256': 'a' * 64, 'packages': [copy.deepcopy(package)]}]}}
        return inventory, layers

    def setUp(self):
        # The build/provenance check has its own real-byte/native tests. This
        # class exercises the component-review boundary after that check.
        self.verifier = self.enterContext(patch('collect_package_sources.verify_sqlite_replacement'))

    def test_matching_library_only_input_and_complete_layers_are_required(self):
        inventory, layers = self.fixture()
        review = image.validate_sqlite_cli_review(inventory, layers, 'amd64', root=ROOT,
                                                 image_config_sha256='e' * 64)
        self.assertEqual(review['justification'], 'vulnerable_code_not_present')
        self.assertEqual(review['runtime_apk_metadata_sha256'], 'a' * 64)
        self.verifier.assert_called_once_with(inventory, 'amd64', root=ROOT)

    def test_missing_wrong_architecture_preparation_or_incomplete_proof_blocks(self):
        mutations = (
            lambda i, l: i.pop('sqlite_cli'),
            lambda i, l: l.pop('sqlite_cli'),
            lambda i, l: l.update(architecture='arm64'),
            lambda i, l: l.update(config_sha256='f' * 64),
            lambda i, l: l.update(success=False),
            lambda i, l: l['sqlite_cli'].update(layers_scanned=0),
            lambda i, l: l['sqlite_cli'].update(files_scanned=True),
            lambda i, l: l['sqlite_cli'].update(elf_files_scanned=0),
            lambda i, l: l['sqlite_cli'].update(apk_metadata=[]),
            lambda i, l: i['sqlite_cli'].update(checked_bin_directories=['/usr/bin']),
            lambda i, l: i['sqlite_cli']['apk_metadata'].update(sha256='c' * 64),
            lambda i, l: i['os_packages'][0].update(build_commit='unreviewed'),
            lambda i, l: l['sqlite_cli']['apk_metadata'][0].update(layer=1),
            lambda i, l: l['sqlite_cli'].update(limitations='No limitations'),
            lambda i, l: l['sqlite_cli']['apk_metadata'].append(
                copy.deepcopy(l['sqlite_cli']['apk_metadata'][0])),
        )
        for number, mutate in enumerate(mutations):
            inventory, layers = self.fixture()
            mutate(inventory, layers)
            with self.subTest(number=number), self.assertRaises(ValueError):
                image.validate_sqlite_cli_review(inventory, layers, 'amd64', root=ROOT,
                                                 image_config_sha256='e' * 64)
        inventory, layers = self.fixture()
        self.verifier.side_effect = ValueError('Preparation does not qualify')
        with self.assertRaisesRegex(ValueError, 'Preparation'):
            image.validate_sqlite_cli_review(inventory, layers, 'amd64', root=ROOT,
                                             image_config_sha256='e' * 64)

    def test_shell_package_payload_or_deleted_lower_layer_blocks(self):
        for mutation in ('package', 'payload', 'provider', 'marker', 'malformed'):
            inventory, layers = self.fixture()
            package = layers['sqlite_cli']['apk_metadata'][0]['packages'][0]
            if mutation == 'package':
                package['name'] = 'sqlite'
            elif mutation == 'payload':
                package['payloads'].append('usr/bin/sqlite3')
            elif mutation == 'provider':
                package['provides'].append('cmd:sqlite3=3.53.4')
            elif mutation == 'malformed':
                layers['sqlite_cli']['apk_metadata'][0]['packages'] = [None]
            else:
                layers['sqlite_cli']['findings'].append({'layer': 0, 'rule': 'sqlite-cli-elf-markers'})
            # A later metadata layer is library-only. Earlier evidence still
            # blocks rather than being erased by the final runtime inventory.
            layers['layers'].append({'diff_id': 'sha256:' + 'd' * 64, 'files': 1, 'bytes': 10})
            layers['sqlite_cli'].update(layers_scanned=2, files_scanned=11)
            layers['sqlite_cli']['apk_metadata'].append({'layer': 1,
                **copy.deepcopy(inventory['sqlite_cli']['apk_metadata'])})
            layers['sqlite_cli']['apk_metadata'][-1]['path'] = 'lib/apk/db/installed'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                image.validate_sqlite_cli_review(inventory, layers, 'amd64', root=ROOT,
                                                 image_config_sha256='e' * 64)
