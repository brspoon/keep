import copy
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path('scripts').resolve()))
import retain_registry as retention


def digest(number):
    return 'sha256:' + format(number, '064x')


def release(version, number):
    root, amd, arm = digest(number * 10), digest(number * 10 + 1), digest(number * 10 + 2)
    images = [{'os': 'linux', 'architecture': arch, 'digest': value}
              for arch, value in [('amd64', amd), ('arm64', arm)]]
    commit = 'sha-' + format(number, '040x')
    return [{'name': name, 'digest': root, 'images': copy.deepcopy(images)} for name in (version, commit)] + [
        {'name': commit + '-' + arch, 'digest': value,
         'images': [{'os': 'linux', 'architecture': arch, 'digest': value}]}
        for arch, value in [('amd64', amd), ('arm64', arm)]]


def scenario(count=5, current=5):
    tags = sum((release('2.0.' + str(n), n) for n in range(1, count + 1)), [])
    stable = copy.deepcopy(next(t for t in tags if t['name'] == '2.0.' + str(current)))
    stable['name'] = 'stable'
    tags.append(stable)
    return tags, {'version': '2.0.' + str(current),
                  'revision': format(current, '040x'),
                  'registry_digests': [stable['digest']]}


def operator_fixture(root, backup=None):
    state = root / '.registry-state'
    state.mkdir(exist_ok=True)
    state.chmod(0o700)
    backup = backup or root / 'full-backups'
    backup.mkdir(parents=True, exist_ok=True)
    configuration = {'backup_directory': str(backup), 'backup_pattern': 'keep-backup-*.tar.gz',
                     'containers': ['fixture-app', 'fixture-digest'], 'archive_prefix': 'keep'}
    path = state / 'retention-config.json'
    path.write_text(json.dumps(configuration))
    path.chmod(0o600)
    return configuration


def recovery_fixture(root, backup_root):
    record_dir = root / '.deploy-backups/registry-20261001T120000Z'
    record_dir.mkdir(parents=True)
    receipt = {'image': digest(900), 'version': '2.0.5', 'revision': 'a' * 40,
               'recovery': str(record_dir)}
    db_path = record_dir / 'database.sqlite3'
    with sqlite3.connect(db_path) as db:
        db.execute('CREATE TABLE fixture (value TEXT)')
        db.execute("INSERT INTO fixture VALUES ('synthetic')")
    (record_dir / 'images.json').write_text(json.dumps({'previous': [digest(901), digest(902)]}))
    (record_dir / 'deployed.json').write_text(json.dumps(receipt))
    config_names = ('.env', 'compose.yml', 'compose.override.yml', 'compose.registry.yml')
    for name in config_names:
        (root / name).write_text('synthetic ' + name + '\n')
    with tarfile.open(record_dir / 'configuration.tgz', 'w:gz') as saved:
        for name in config_names:
            data = (root / name).read_bytes()
            member = tarfile.TarInfo(name)
            member.size = len(data)
            saved.addfile(member, io.BytesIO(data))
    backup_root.mkdir(parents=True)
    operator_fixture(root, backup_root)
    archive = backup_root / 'keep-backup-synthetic.tar.gz'
    with tarfile.open(archive, 'w:gz') as saved:
        for name in config_names:
            data = (root / name).read_bytes()
            member = tarfile.TarInfo('keep/' + name)
            member.size = len(data)
            saved.addfile(member, io.BytesIO(data))
    return receipt, archive


class FakeRegistry:
    def __init__(self, rows):
        self.rows = copy.deepcopy(rows)
        self.deleted = []
        self.manifests = {}
        for row in rows:
            children = sorted({image['digest'] for image in row['images']} - {row['digest']})
            self.manifests[row['digest']] = {'children': children}
            for child in children:
                self.manifests.setdefault(child, {'children': []})

    def tags(self, expected_absent=()):
        return copy.deepcopy(self.rows)

    def delete_tag(self, tag):
        self.deleted.append(('tag', tag))
        self.rows = [t for t in self.rows if t['name'] != tag]

    def delete_manifest(self, digest):
        self.deleted.append(('manifest', digest))
        self.manifests.pop(digest, None)

    def manifest(self, digest):
        return copy.deepcopy(self.manifests.get(digest))


class RetentionTests(unittest.TestCase):
    def test_operator_configuration_requires_private_bounded_known_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = operator_fixture(root)
            path = root / '.registry-state/retention-config.json'
            self.assertEqual(retention.ROOT, Path(retention.__file__).resolve().parents[1])
            self.assertEqual(retention.operator_config(root), valid)
            with_floor = {**valid, 'minimum_release': '2.0.5'}
            path.write_text(json.dumps(with_floor))
            self.assertEqual(retention.operator_config(root), with_floor)
            malformed = [None, [], {}, {**valid, 'extra': True},
                         {**valid, 'backup_directory': 'relative'},
                         {**valid, 'backup_directory': str(root / 'missing')},
                         {**valid, 'backup_pattern': '../keep-*.tar.gz'},
                         {**valid, 'backup_pattern': '**/*.tar.gz'},
                         {**valid, 'backup_pattern': '*'},
                         {**valid, 'containers': ['fixture-app']},
                         {**valid, 'containers': ['fixture-app', 'fixture-app']},
                         {**valid, 'containers': ['fixture-app', '--all']},
                         {**valid, 'archive_prefix': '../keep'},
                         {**valid, 'archive_prefix': ''}]
            malformed += [{**valid, 'minimum_release': value} for value in
                          (None, 5, '', '02.0.5', '2.0.5-alpha', '2.0.5\n', '1' * 65 + '.0.0')]
            bodies = [json.dumps(value) for value in malformed]
            bodies += ['{', '{"backup_directory": "duplicate", "backup_directory": "field"}',
                       'x' * (retention.MAX_CONFIG_BYTES + 1)]
            for body in bodies:
                with self.subTest(body=body[:100]):
                    path.write_text(body)
                    with self.assertRaises(retention.Hold):
                        retention.operator_config(root)

    def test_unsafe_operator_configuration_holds_before_registry_access(self):
        for unsafe in ('missing', 'public_file', 'file_symlink', 'nonregular_file', 'directory_symlink',
                       'public_directory', 'wrong_directory_owner', 'wrong_file_owner'):
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                operator_fixture(root)
                state = root / '.registry-state'
                path = state / 'retention-config.json'
                info = path.stat()
                if unsafe == 'missing':
                    path.unlink()
                elif unsafe == 'public_file':
                    path.chmod(0o644)
                elif unsafe == 'file_symlink':
                    saved = path.with_name('saved-config.json')
                    path.rename(saved)
                    path.symlink_to(saved)
                elif unsafe == 'nonregular_file':
                    path.unlink()
                    os.mkfifo(path, mode=0o600)
                elif unsafe == 'directory_symlink':
                    saved = root / 'saved-state'
                    state.rename(saved)
                    state.symlink_to(saved, target_is_directory=True)
                elif unsafe == 'public_directory':
                    state.chmod(0o755)
                owner_patch = patch.object(retention.os, 'getuid', return_value=os.getuid() + 1)
                wrong_owner = os.stat_result(tuple(info[:4]) + (info.st_uid + 1,) + tuple(info[5:]))
                file_patch = patch.object(retention.os, 'fstat', return_value=wrong_owner)
                from contextlib import nullcontext
                guard = (owner_patch if unsafe == 'wrong_directory_owner' else
                         file_patch if unsafe == 'wrong_file_owner' else nullcontext())
                with guard, patch.object(retention, 'Registry') as registry, \
                        patch.object(retention, 'production') as production:
                    with self.assertRaises(retention.Hold):
                        retention.run(root, True)
                    registry.assert_not_called()
                    production.assert_not_called()

    def test_changed_operator_configuration_holds_before_first_registry_deletion(self):
        rows, live = scenario()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.git').mkdir()
            configuration = operator_fixture(root)
            state = root / '.registry-state'
            token = state / 'retention-token'
            token.write_text('synthetic'); token.chmod(0o600)
            registry = FakeRegistry(rows)
            original_tags = registry.tags

            def change_configuration(*args, **kwargs):
                changed = {**configuration, 'archive_prefix': 'changed'}
                (state / 'retention-config.json').write_text(json.dumps(changed))
                return original_tags(*args, **kwargs)

            with patch.object(registry, 'tags', side_effect=change_configuration), \
                    patch.object(retention, 'production', return_value=live), \
                    patch.object(retention, 'Registry', return_value=registry):
                with self.assertRaisesRegex(retention.Hold, 'configuration changed'):
                    retention.run(root, True)
            self.assertEqual(registry.deleted, [])
            self.assertTrue((state / 'retention-pending.json').is_file())

    def test_repository_visibility_accepts_public_and_private_but_requires_real_metadata(self):
        rows, _ = scenario()
        registry = retention.Registry.__new__(retention.Registry)
        registry.hub_token = 'synthetic'
        for private in (False, True):
            with self.subTest(private=private), patch.object(registry, 'request', side_effect=[
                    {'is_private': private}, {'count': len(rows), 'results': rows, 'next': None}]):
                self.assertEqual(registry.tags(), rows)
        for metadata in ({}, {'is_private': None}, {'is_private': 'false'}, {'is_private': 0}, [], None):
            with self.subTest(metadata=metadata), patch.object(registry, 'request', return_value=metadata) as request:
                with self.assertRaisesRegex(retention.Hold, 'visibility metadata'):
                    registry.tags()
                self.assertEqual(request.call_count, 1)

    def test_inventory_accepts_stale_low_count_but_rejects_missing_tags(self):
        rows, _ = scenario(count=2, current=2)
        registry = retention.Registry.__new__(retention.Registry)
        registry.hub_token = 'synthetic'
        for count in (5, len(rows) + 1):
            with patch.object(registry, 'request', side_effect=[{'is_private': True},
                {'count': count, 'results': rows, 'next': None}]):
                if count > len(rows):
                    with self.assertRaises(retention.Hold): registry.tags()
                else:
                    self.assertEqual(registry.tags(), rows)

    def test_inventory_accepts_only_exact_reviewed_post_delete_shortfall(self):
        rows, _ = scenario(count=2, current=2)
        removed = rows.pop(0)['name']
        registry = retention.Registry.__new__(retention.Registry)
        registry.hub_token = 'synthetic'
        page = {'count': len(rows) + 1, 'results': rows, 'next': None}
        with patch.object(registry, 'request', side_effect=[{'is_private': True}, page]):
            self.assertEqual(registry.tags(expected_absent={removed: digest(1)}), rows)
        with patch.object(registry, 'request', side_effect=[{'is_private': True},
                {'count': len(rows), 'results': rows, 'next': None}]):
            self.assertEqual(registry.tags(expected_absent={
                removed: digest(1), 'another-reviewed-tag': digest(2)}), rows)
        for expected_absent, count in (({}, len(rows) + 1),
                                       ({removed: digest(1)}, len(rows) + 2)):
            incomplete = {'count': count, 'results': rows, 'next': None}
            with patch.object(registry, 'request', side_effect=[{'is_private': True}, incomplete]):
                with self.assertRaises(retention.Hold):
                    registry.tags(expected_absent=expected_absent)

    def test_keeps_exactly_current_five_aliases_and_two_prior_version_tags(self):
        rows, live = scenario()
        proposed = retention.plan(rows, live)
        retained = {'2.0.5', 'stable', 'sha-' + live['revision'],
                    'sha-' + live['revision'] + '-amd64', 'sha-' + live['revision'] + '-arm64',
                    '2.0.4', '2.0.3'}
        self.assertEqual(set(proposed['retained_tags']), retained)
        self.assertEqual(proposed['retained_releases'], ['2.0.5', '2.0.4', '2.0.3'])
        self.assertEqual(set(proposed['tags']), {t['name'] for t in rows} - retained)
        self.assertEqual(set(proposed['manifests']), {digest(n * 10 + offset) for n in (1, 2) for offset in (0, 1, 2)})
        self.assertEqual(proposed['reviewed_artifacts'], {})

    def test_future_release_ahead_of_production_holds_cleanup(self):
        rows, live = scenario(current=4)
        with self.assertRaises(retention.Hold):
            retention.plan(rows, live)

    def test_numerical_versions_not_push_order(self):
        rows, live = scenario(count=12, current=12)
        proposed = retention.plan(list(reversed(rows)), live)
        self.assertEqual(proposed['retained_releases'], ['2.0.12', '2.0.11', '2.0.10'])
        self.assertEqual(set(proposed['retained_tags']), {
            '2.0.12', 'stable', 'sha-' + live['revision'], 'sha-' + live['revision'] + '-amd64',
            'sha-' + live['revision'] + '-arm64', '2.0.11', '2.0.10'})

    def test_shared_platform_and_custom_tags_are_protected(self):
        rows, live = scenario()
        custom = copy.deepcopy(rows[0])
        custom['name'] = 'manual-rollback'
        rows.append(custom)
        # The current index and its exact native alias consistently reuse a prior child.
        current_commit = 'sha-' + live['revision']
        for row in rows:
            if row['name'] in ('2.0.5', 'stable', current_commit):
                row['images'][0]['digest'] = digest(21)
            if row['name'] == current_commit + '-amd64':
                row['digest'] = digest(21)
                row['images'][0]['digest'] = digest(21)
        orphan = {'name': 'sha-' + format(999, '040x'), 'digest': digest(999),
                  'images': [{'os': 'linux', 'architecture': 'amd64', 'digest': digest(999)}]}
        transfer = {'name': 'transfer-99-1-amd64', 'digest': digest(998),
                    'images': [{'os': 'linux', 'architecture': 'amd64', 'digest': digest(998)}]}
        rows.extend([orphan, transfer])
        proposed = retention.plan(rows, live)
        self.assertIn('2.0.1', proposed['tags'])
        self.assertNotIn('manual-rollback', proposed['tags'])
        self.assertNotIn(orphan['name'], proposed['tags'])
        self.assertNotIn(transfer['name'], proposed['tags'])
        self.assertNotIn(digest(21), proposed['manifests'])
        # Old aliases are removable even where a retained version still references the digest.
        self.assertIn('sha-' + format(4, '040x') + '-amd64', proposed['tags'])

    def test_only_exact_digest_reviewed_orphan_and_transfer_tags_are_removable(self):
        rows, live = scenario()
        orphan = {'name': 'sha-' + format(999, '040x'), 'digest': digest(999),
                  'images': [{'os': 'linux', 'architecture': 'amd64', 'digest': digest(999)}]}
        transfer = {'name': 'transfer-99-1-arm64', 'digest': digest(998),
                    'images': [{'os': 'linux', 'architecture': 'arm64', 'digest': digest(998)}]}
        custom = {'name': 'operator-tag', 'digest': digest(997),
                  'images': [{'os': 'linux', 'architecture': 'amd64', 'digest': digest(997)}]}
        rows.extend([orphan, transfer, custom])
        reviewed = {orphan['name']: orphan['digest'], transfer['name']: transfer['digest']}
        proposed = retention.plan(rows, live, reviewed_artifacts=reviewed)
        self.assertEqual(proposed['reviewed_artifacts'], reviewed)
        self.assertEqual(proposed['tags'][orphan['name']], orphan['digest'])
        self.assertEqual(proposed['tags'][transfer['name']], transfer['digest'])
        self.assertNotIn(custom['name'], proposed['tags'])
        with self.assertRaises(retention.Hold):
            retention.plan(rows, live, reviewed_artifacts={
                orphan['name']: digest(996), transfer['name']: transfer['digest']})
        for changed in ({orphan['name']: orphan['digest'], 'transfer-99-2-arm64': transfer['digest']},):
            safe = retention.plan(rows, live, reviewed_artifacts=changed)
            self.assertNotIn(transfer['name'], safe['tags'])
            self.assertNotIn('transfer-99-2-arm64', safe['reviewed_artifacts'])

    def test_minimum_release_starts_with_five_tags_then_rolls_to_seven(self):
        for current in (5, 6, 7, 8):
            with self.subTest(current=current):
                rows, live = scenario(count=current, current=current)
                live['minimum_release'] = '2.0.5'
                proposed = retention.plan(rows, live)
                expected = {'stable', live['version'], 'sha-' + live['revision'],
                            'sha-' + live['revision'] + '-amd64',
                            'sha-' + live['revision'] + '-arm64'}
                expected.update('2.0.' + str(number)
                                for number in range(max(5, current - 2), current))
                self.assertEqual(set(proposed['retained_tags']), expected)
                self.assertEqual(proposed['minimum_release'], '2.0.5')
                for number in range(1, 5):
                    self.assertIn('2.0.' + str(number), proposed['tags'])
                    self.assertTrue({digest(number * 10), digest(number * 10 + 1),
                                     digest(number * 10 + 2)} <= set(proposed['manifests']))
                registry = FakeRegistry(rows)
                retention.apply(registry, proposed, lambda: live)
                self.assertEqual({row['name'] for row in registry.rows}, expected)
                self.assertEqual(retention.plan(registry.rows, live)['tags'], {})

    def test_future_or_invalid_minimum_release_and_staged_release_hold(self):
        rows, live = scenario()
        for floor in ('2.0.6', '3.0.0', '', '2.0.5-alpha', 5):
            with self.subTest(floor=floor), self.assertRaises(retention.Hold):
                retention.plan(rows, {**live, 'minimum_release': floor})
        staged, live = scenario(count=6, current=5)
        with self.assertRaisesRegex(retention.Hold, 'newer release is staged'):
            retention.plan(staged, {**live, 'minimum_release': '2.0.5'})

    def test_minimum_release_preserves_unknown_references_and_requires_health(self):
        rows, live = scenario()
        live['minimum_release'] = '2.0.5'
        custom = copy.deepcopy(rows[0]); custom['name'] = 'operator-rollback'
        orphan = {'name': 'sha-' + format(999, '040x'), 'digest': digest(999),
                  'images': [{'os': 'linux', 'architecture': 'amd64', 'digest': digest(999)}]}
        transfer = {'name': 'transfer-99-1-arm64', 'digest': digest(998),
                    'images': [{'os': 'linux', 'architecture': 'arm64', 'digest': digest(998)}]}
        rows.extend([custom, orphan, transfer])
        proposed = retention.plan(rows, live)
        preserved = {custom['name'], orphan['name'], transfer['name']}
        self.assertTrue(preserved <= set(proposed['retained_tags']))
        protected = retention.closure(custom) | retention.closure(orphan) | retention.closure(transfer)
        self.assertTrue(protected.isdisjoint(proposed['manifests']))
        registry = FakeRegistry(rows)
        def unhealthy():
            raise retention.Hold('unhealthy')
        with self.assertRaisesRegex(retention.Hold, 'unhealthy'):
            retention.apply(registry, proposed, unhealthy)
        self.assertEqual(registry.deleted, [])
        retention.apply(registry, proposed, lambda: live)
        self.assertTrue(preserved <= {row['name'] for row in registry.rows})
        deleted_manifests = {target for kind, target in registry.deleted if kind == 'manifest'}
        self.assertTrue(protected.isdisjoint(deleted_manifests))

    def test_changed_minimum_release_holds_before_each_remote_write(self):
        rows, live = scenario()
        live['minimum_release'] = '2.0.5'
        proposed = retention.plan(rows, live)
        changed = {**live, 'minimum_release': '2.0.4'}
        for initial in (changed, live):
            with self.subTest(initial_floor=initial['minimum_release']):
                registry = FakeRegistry(rows)
                proofs = iter((initial, changed))
                with self.assertRaisesRegex(retention.Hold, 'changed during cleanup'):
                    retention.apply(registry, proposed, lambda: next(proofs))
                self.assertEqual(len(registry.deleted), 0 if initial is changed else 1)

    def test_stable_pending_deployment_or_missing_platform_fails_closed(self):
        rows, live = scenario()
        for mutate in [lambda r: r[-1].update(digest=digest(999)),
                       lambda r: r[-1].update(images=r[-1]['images'][:1]),
                       lambda r: r.append(copy.deepcopy(r[0])),
                       lambda r: r[0].update(digest='bad')]:
            altered = copy.deepcopy(rows)
            mutate(altered)
            with self.assertRaises(retention.Hold):
                retention.plan(altered, live)

    def test_current_version_commit_index_and_two_native_aliases_must_agree(self):
        rows, live = scenario()
        commit = 'sha-' + live['revision']
        mutations = [
            lambda tags: next(t for t in tags if t['name'] == commit).update(digest=digest(999)),
            lambda tags: next(t for t in tags if t['name'] == commit + '-amd64').update(digest=digest(999)),
            lambda tags: next(t for t in tags if t['name'] == commit + '-arm64').update(images=[
                {'os': 'linux', 'architecture': 'amd64', 'digest': digest(12)}]),
            lambda tags: next(t for t in tags if t['name'] == '2.0.5').update(images=[
                {'os': 'linux', 'architecture': 'amd64', 'digest': digest(51)},
                {'os': 'linux', 'architecture': 'arm64', 'digest': digest(52)},
                {'os': 'linux', 'architecture': 'arm64', 'digest': digest(53)}]),
        ]
        for mutate in mutations:
            altered = copy.deepcopy(rows)
            mutate(altered)
            with self.subTest(mutation=mutate), self.assertRaises(retention.Hold):
                retention.plan(altered, live)
        altered_live = copy.deepcopy(live)
        altered_live['revision'] = 'f' * 40
        with self.assertRaises(retention.Hold):
            retention.plan(rows, altered_live)

    def test_no_old_releases_means_no_deletions(self):
        rows, live = scenario(count=2, current=2)
        proposed = retention.plan(rows, live)
        self.assertEqual(set(proposed['tags']), {
            'sha-' + format(1, '040x'), 'sha-' + format(1, '040x') + '-amd64',
            'sha-' + format(1, '040x') + '-arm64'})
        self.assertEqual(proposed['manifests'], [])

    def test_apply_removes_tags_before_unreferenced_manifests_and_keeps_protected(self):
        rows, live = scenario()
        registry = FakeRegistry(rows)
        proposed = retention.plan(rows, live)
        retention.apply(registry, proposed, lambda: live)
        self.assertEqual([kind for kind, _ in registry.deleted], ['tag'] * 14 + ['manifest'] * 6)
        self.assertEqual({r['name'] for r in registry.rows}, {r['name'] for r in rows} - set(proposed['tags']))
        self.assertEqual(retention.plan(registry.rows, live)['tags'], {})

    def test_changed_tag_new_reference_or_bad_health_stops_before_deletion(self):
        rows, live = scenario()
        proposed = retention.plan(rows, live)
        registry = FakeRegistry(rows)
        registry.rows[0]['digest'] = digest(999)
        with self.assertRaises(retention.Hold):
            retention.apply(registry, proposed, lambda: live)
        self.assertEqual(registry.deleted, [])
        registry = FakeRegistry(rows)
        extra = copy.deepcopy(rows[0]); extra['name'] = 'new-protected-alias'
        registry.rows.append(extra)
        retention.apply(registry, proposed, lambda: live)
        self.assertTrue(any(kind == 'tag' for kind, _ in registry.deleted))
        removed_manifests = {target for kind, target in registry.deleted if kind == 'manifest'}
        self.assertTrue(removed_manifests)
        self.assertTrue({digest(10), digest(11), digest(12)}.isdisjoint(removed_manifests))
        self.assertIn('new-protected-alias', {row['name'] for row in registry.rows})
        registry = FakeRegistry(rows)
        def unhealthy():
            raise retention.Hold('unhealthy')
        with self.assertRaises(retention.Hold):
            retention.apply(registry, proposed, unhealthy)
        self.assertEqual(registry.deleted, [])

    def test_health_rechecked_after_partial_cleanup(self):
        rows, live = scenario()
        registry = FakeRegistry(rows)
        checks = iter([live, retention.Hold('worker failed')])
        def check():
            value = next(checks)
            if isinstance(value, Exception): raise value
            return value
        with self.assertRaises(retention.Hold):
            retention.apply(registry, retention.plan(rows, live), check)
        self.assertEqual(len(registry.deleted), 1)

    def test_all_deletion_methods_are_hard_limited_to_keep(self):
        registry = object.__new__(retention.Registry)
        registry.hub_token = registry.registry_token = 'synthetic'
        with patch.object(registry, 'request') as request:
            for value in ('stable', 'latest', '../other', 'other/repo'):
                with self.assertRaises(retention.Hold): registry.delete_tag(value)
            request.assert_not_called()
            registry.delete_tag('2.0.1')
            registry.delete_manifest(digest(1))
            self.assertEqual(request.call_args_list[0].args[0], 'https://hub.docker.com/v2/repositories/brspoon/keep/tags/2.0.1/')
            self.assertEqual(request.call_args_list[1].args[0], 'https://registry-1.docker.io/v2/brspoon/keep/manifests/' + digest(1))

    def test_foreign_pagination_never_receives_token(self):
        registry = object.__new__(retention.Registry); registry.hub_token = 'synthetic'
        with patch.object(registry, 'request', side_effect=[{'is_private': True},
            {'count': 0, 'results': [], 'next': 'https://other.test/tags'}]) as request:
            with self.assertRaises(retention.Hold): registry.tags()
        self.assertEqual(request.call_count, 2)

    def test_production_receipt_health_and_readonly_integrity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); operator_fixture(root)
            receipt = {'image': digest(9), 'version': '2.0.5', 'revision': 'a' * 40}
            (root / '.registry-state/deployed.json').write_text(json.dumps(receipt))
            container = {'Image': digest(9), 'State': {'Status': 'running', 'Health': {'Status': 'healthy'}},
                'Config': {'Labels': {'org.opencontainers.image.version': '2.0.5', 'org.opencontainers.image.revision': 'a' * 40}}}
            with patch.object(retention, 'recovery'), patch.object(retention, 'docker', side_effect=[json.dumps([container, container]),
                json.dumps([{'RepoDigests': ['brspoon/keep@' + digest(50)]}]), '']) as docker:
                live = retention.production(root)
            self.assertEqual(live['version'], '2.0.5')
            self.assertEqual(docker.call_args_list[0].args, ('inspect', 'fixture-app', 'fixture-digest'))
            self.assertEqual(docker.call_args.args[1], 'fixture-app')
            self.assertIn('mode=ro', docker.call_args.args[-1])
            bad = copy.deepcopy(container); bad['State']['Health']['Status'] = 'unhealthy'
            with patch.object(retention, 'docker', return_value=json.dumps([container, bad])), self.assertRaises(retention.Hold):
                retention.production(root)
            (root / '.registry-state/update-request').touch()
            with patch.object(retention, 'docker') as docker, self.assertRaises(retention.Hold):
                retention.production(root)
            docker.assert_not_called()

    def test_production_propagates_floor_and_future_floor_holds_before_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configuration = operator_fixture(root)
            configuration['minimum_release'] = '2.0.5'
            config_path = root / '.registry-state/retention-config.json'
            config_path.write_text(json.dumps(configuration))
            receipt = {'image': digest(9), 'version': '2.0.5', 'revision': 'a' * 40}
            (root / '.registry-state/deployed.json').write_text(json.dumps(receipt))
            container = {'Image': digest(9), 'State': {'Status': 'running', 'Health': {'Status': 'healthy'}},
                         'Config': {'Labels': {'org.opencontainers.image.version': '2.0.5',
                                             'org.opencontainers.image.revision': 'a' * 40}}}
            with patch.object(retention, 'recovery'), patch.object(retention, 'docker', side_effect=[
                    json.dumps([container, container]),
                    json.dumps([{'RepoDigests': ['brspoon/keep@' + digest(50)]}]), '']):
                self.assertEqual(retention.production(root)['minimum_release'], '2.0.5')
            configuration['minimum_release'] = '2.0.6'
            config_path.write_text(json.dumps(configuration))
            with patch.object(retention, 'docker') as docker, self.assertRaisesRegex(
                    retention.Hold, 'newer than production'):
                retention.production(root)
            docker.assert_not_called()

    def test_recovery_accepts_sqlite_pair_rollback_images_and_current_nas_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'app'; root.mkdir()
            backup = Path(directory) / 'nas'
            receipt, _ = recovery_fixture(root, backup)
            images = [digest(901), digest(902)]
            with patch.object(retention, 'docker', return_value=json.dumps([{'Id': value} for value in images])):
                self.assertIsNone(retention.recovery(root, receipt))

    def test_recovery_holds_for_missing_mismatched_or_corrupt_local_receipts(self):
        cases = ('missing_directory', 'mismatched_receipt', 'corrupt_database', 'corrupt_local_config_archive',
                 'missing_database', 'missing_paired_images')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'app'; root.mkdir()
                backup = Path(directory) / 'nas'
                receipt, _ = recovery_fixture(root, backup)
                record = Path(receipt['recovery'])
                if case == 'missing_directory':
                    shutil.rmtree(record)
                elif case == 'mismatched_receipt':
                    changed = dict(receipt, version='2.0.4')
                    (record / 'deployed.json').write_text(json.dumps(changed))
                elif case == 'corrupt_database':
                    (record / 'database.sqlite3').write_bytes(b'not a sqlite database')
                elif case == 'corrupt_local_config_archive':
                    (record / 'configuration.tgz').write_bytes(b'not a gzip archive')
                elif case == 'missing_database':
                    (record / 'database.sqlite3').unlink()
                with patch.object(retention, 'docker', return_value=json.dumps([{'Id': digest(901)}])):
                    with self.assertRaises(retention.Hold):
                        retention.recovery(root, receipt)

    def test_recovery_holds_for_missing_stale_or_mismatched_nas_config_backup(self):
        cases = ('missing', 'stale', 'mismatched_config')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'app'; root.mkdir()
                backup = Path(directory) / 'nas'
                receipt, archive = recovery_fixture(root, backup)
                if case == 'missing':
                    archive.unlink()
                elif case == 'stale':
                    old = (datetime.now(timezone.utc) - timedelta(hours=72)).timestamp()
                    os.utime(archive, (old, old))
                else:
                    (root / 'compose.yml').write_text('changed deployment config\n')
                with patch.object(retention, 'docker', return_value=json.dumps(
                            [{'Id': digest(901)}, {'Id': digest(902)}])):
                    with self.assertRaises(retention.Hold):
                        retention.recovery(root, receipt)

    def test_reviewed_artifact_file_accepts_only_exact_terminal_attempts(self):
        rows, _ = scenario()
        orphan = {'name': 'sha-' + format(999, '040x'), 'digest': digest(999),
                  'images': [{'os': 'linux', 'architecture': 'amd64', 'digest': digest(999)}]}
        transfer = {'name': 'transfer-12345-2-arm64', 'digest': digest(998),
                    'images': [{'os': 'linux', 'architecture': 'arm64', 'digest': digest(998)}]}
        rows.extend([orphan, transfer])
        artifacts = {
            orphan['name']: {'status': 'completed', 'conclusion': 'failure', 'run_id': '7788',
                             'run_attempt': 1, 'head_sha': orphan['name'][4:], 'digest': orphan['digest']},
            transfer['name']: {'status': 'completed', 'conclusion': 'success', 'run_id': '12345',
                               'run_attempt': 2, 'head_sha': 'b' * 40, 'digest': transfer['digest']},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); state = root / '.registry-state'; state.mkdir(); operator_fixture(root)
            review = {'schema': 'keep.registry-artifact-review.v1', 'repository': 'brspoon/keep',
                      'reviewed_at': datetime.now(timezone.utc).isoformat(), 'artifacts': artifacts}
            path = state / 'retention-artifacts.json'
            path.write_text(json.dumps(review)); path.chmod(0o600)
            self.assertEqual(retention.reviewed_artifacts(root, rows), {
                orphan['name']: orphan['digest'], transfer['name']: transfer['digest']})

    def test_reviewed_artifacts_hold_on_permissions_identity_state_or_digest_mismatch(self):
        rows, _ = scenario()
        name = 'transfer-12345-2-amd64'
        row = {'name': name, 'digest': digest(999),
               'images': [{'os': 'linux', 'architecture': 'amd64', 'digest': digest(999)}]}
        rows.append(row)
        valid = {'status': 'completed', 'conclusion': 'success', 'run_id': '12345',
                 'run_attempt': 2, 'head_sha': 'b' * 40, 'digest': row['digest']}
        bad_entries = [dict(valid, status='in_progress'), dict(valid, conclusion='queued'),
                       dict(valid, run_id='54321'), dict(valid, run_attempt=3),
                       dict(valid, digest=digest(998)), dict(valid, head_sha='invalid')]
        for entry in bad_entries:
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); state = root / '.registry-state'; state.mkdir(); operator_fixture(root)
                path = state / 'retention-artifacts.json'
                path.write_text(json.dumps({'schema': 'keep.registry-artifact-review.v1',
                    'repository': 'brspoon/keep', 'reviewed_at': datetime.now(timezone.utc).isoformat(),
                    'artifacts': {name: entry}})); path.chmod(0o600)
                with self.assertRaises(retention.Hold):
                    retention.reviewed_artifacts(root, rows)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); state = root / '.registry-state'; state.mkdir(); operator_fixture(root)
            path = state / 'retention-artifacts.json'
            path.write_text(json.dumps({'schema': 'keep.registry-artifact-review.v1',
                'repository': 'somewhere/else', 'reviewed_at': datetime.now(timezone.utc).isoformat(),
                'artifacts': {name: valid}})); path.chmod(0o600)
            with self.assertRaises(retention.Hold):
                retention.reviewed_artifacts(root, rows)
            path.write_text(json.dumps({'schema': 'keep.registry-artifact-review.v1',
                'repository': 'brspoon/keep', 'reviewed_at': datetime.now(timezone.utc).isoformat(),
                'artifacts': {name: valid}})); path.chmod(0o644)
            with self.assertRaises(retention.Hold):
                retention.reviewed_artifacts(root, rows)

        orphan = {'name': 'sha-' + format(998, '040x'), 'digest': digest(998),
                  'images': [{'os': 'linux', 'architecture': 'arm64', 'digest': digest(998)}]}
        rows.append(orphan)
        mismatch = {'status': 'completed', 'conclusion': 'failure', 'run_id': '54321',
                    'run_attempt': 1, 'head_sha': 'f' * 40, 'digest': orphan['digest']}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); state = root / '.registry-state'; state.mkdir(); operator_fixture(root)
            path = state / 'retention-artifacts.json'
            path.write_text(json.dumps({'schema': 'keep.registry-artifact-review.v1',
                'repository': 'brspoon/keep', 'reviewed_at': datetime.now(timezone.utc).isoformat(),
                'artifacts': {orphan['name']: mismatch}})); path.chmod(0o600)
            with self.assertRaises(retention.Hold):
                retention.reviewed_artifacts(root, rows)
            path.chmod(0o644)
            with self.assertRaises(retention.Hold):
                retention.reviewed_artifacts(root, rows)

    def test_dry_run_consumes_private_review_file_into_exact_plan(self):
        rows, live = scenario()
        orphan = {'name': 'sha-' + format(999, '040x'), 'digest': digest(999),
                  'images': [{'os': 'linux', 'architecture': 'amd64', 'digest': digest(999)}]}
        rows.append(orphan)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / '.git').mkdir()
            state = root / '.registry-state'; state.mkdir(); operator_fixture(root)
            token = state / 'retention-token'; token.write_text('synthetic'); token.chmod(0o600)
            entry = {'status': 'completed', 'conclusion': 'cancelled', 'run_id': '999',
                     'run_attempt': 1, 'head_sha': orphan['name'][4:], 'digest': orphan['digest']}
            path = state / 'retention-artifacts.json'
            path.write_text(json.dumps({'schema': 'keep.registry-artifact-review.v1',
                'repository': 'brspoon/keep', 'reviewed_at': datetime.now(timezone.utc).isoformat(),
                'artifacts': {orphan['name']: entry}})); path.chmod(0o600)
            with patch.object(retention, 'production', return_value=live), patch.object(
                    retention, 'Registry', return_value=FakeRegistry(rows)):
                result = retention.run(root, False)
            self.assertEqual(result['reviewed_artifacts'], {orphan['name']: orphan['digest']})
            self.assertEqual(result['tags'][orphan['name']], orphan['digest'])

    def test_same_version_legacy_pending_policy_requires_explicit_replacement(self):
        rows, live = scenario()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / '.git').mkdir()
            state = root / '.registry-state'; state.mkdir(); operator_fixture(root)
            token = state / 'retention-token'; token.write_text('synthetic'); token.chmod(0o600)
            old = retention.plan(rows, live); old['policy'] = 'legacy-three-release-policy'
            pending = state / 'retention-pending.json'; pending.write_text(json.dumps(old))
            registry = FakeRegistry(rows)
            with patch.object(retention, 'production', return_value=live), patch.object(
                    retention, 'Registry', return_value=registry):
                with self.assertRaises(retention.Hold):
                    retention.run(root, True)
                result = retention.run(root, True, replace_stale=True)
            self.assertEqual(result['policy'], retention.POLICY)
            self.assertFalse(pending.exists())
            self.assertEqual(len(list(state.glob('retention-pending.stale-*.json'))), 1)

    def test_changed_floor_requires_explicit_pending_replacement(self):
        rows, live = scenario()
        previous = retention.plan(rows, live)
        live['minimum_release'] = '2.0.5'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / '.git').mkdir()
            configuration = operator_fixture(root)
            state = root / '.registry-state'
            configuration['minimum_release'] = '2.0.5'
            (state / 'retention-config.json').write_text(json.dumps(configuration))
            token = state / 'retention-token'; token.write_text('synthetic'); token.chmod(0o600)
            pending = state / 'retention-pending.json'; pending.write_text(json.dumps(previous))
            registry = FakeRegistry(rows)
            with patch.object(retention, 'production', return_value=live), patch.object(
                    retention, 'Registry', return_value=registry):
                with self.assertRaises(retention.Hold):
                    retention.run(root, True)
                self.assertEqual(registry.deleted, [])
                result = retention.run(root, True, replace_stale=True)
            self.assertEqual(result['minimum_release'], '2.0.5')
            self.assertEqual(len(result['retained_tags']), 5)
            self.assertFalse(pending.exists())
            archives = list(state.glob('retention-pending.stale-*.json'))
            self.assertEqual(len(archives), 1)
            self.assertEqual(json.loads(archives[0].read_text()), previous)

    def test_dry_run_never_mutates_registry_or_creates_pending_plan(self):
        rows, live = scenario()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / '.git').mkdir(); state = root / '.registry-state'; state.mkdir(); operator_fixture(root)
            token = state / 'retention-token'; token.write_text('synthetic'); token.chmod(0o600)
            registry = FakeRegistry(rows)
            with patch.object(retention, 'production', return_value=live), patch.object(retention, 'Registry', return_value=registry):
                result = retention.run(root, False)
            self.assertEqual(result['mode'], 'dry-run')
            self.assertEqual(registry.deleted, [])
            self.assertFalse((state / 'retention-pending.json').exists())

    def test_execute_preserves_pending_plan_on_failure_and_resumes(self):
        rows, live = scenario()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / '.git').mkdir(); state = root / '.registry-state'; state.mkdir(); operator_fixture(root)
            token = state / 'retention-token'; token.write_text('synthetic'); token.chmod(0o600)
            registry = FakeRegistry(rows)
            with patch.object(retention, 'production', return_value=live), patch.object(retention, 'Registry', return_value=registry):
                original = registry.delete_tag
                calls = []
                def fail_second(name):
                    calls.append(name)
                    if len(calls) == 2: raise retention.Hold('temporary error')
                    original(name)
                with patch.object(registry, 'delete_tag', side_effect=fail_second), self.assertRaises(retention.Hold):
                    retention.run(root, True)
                self.assertTrue((state / 'retention-pending.json').exists())
                retention.run(root, True)
            self.assertFalse((state / 'retention-pending.json').exists())
            self.assertEqual(retention.plan(registry.rows, live)['tags'], {})

    def test_resume_passes_reviewed_targets_to_stale_count_checks(self):
        rows, live = scenario()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / '.git').mkdir(); state = root / '.registry-state'; state.mkdir(); operator_fixture(root)
            token = state / 'retention-token'; token.write_text('synthetic'); token.chmod(0o600)
            proposed = retention.plan(rows, live)
            (state / 'retention-pending.json').write_text(json.dumps(proposed))

            class ReviewedRegistry(FakeRegistry):
                def __init__(self, values):
                    super().__init__(values)
                    self.expected = []

                def tags(self, expected_absent=()):
                    self.expected.append(set(expected_absent))
                    return super().tags(expected_absent)

            registry = ReviewedRegistry(rows)
            with patch.object(retention, 'production', return_value=live), patch.object(retention, 'Registry', return_value=registry):
                retention.run(root, True)
            self.assertTrue(registry.expected)
            self.assertTrue(all(value == set(proposed['tags']) for value in registry.expected))

    def test_stale_pending_requires_explicit_replacement_and_carries_absent_tags(self):
        rows, live = scenario()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / '.git').mkdir(); state = root / '.registry-state'; state.mkdir(); operator_fixture(root)
            token = state / 'retention-token'; token.write_text('synthetic'); token.chmod(0o600)
            previous = retention.plan(rows, live)
            previous['production'] = '2.0.4'
            already_absent = next(iter(previous['tags']))
            (state / 'retention-pending.json').write_text(json.dumps(previous))
            registry = FakeRegistry([row for row in rows if row['name'] != already_absent])
            with patch.object(retention, 'production', return_value=live), patch.object(retention, 'Registry', return_value=registry):
                with self.assertRaises(retention.Hold):
                    retention.run(root, True)
                result = retention.run(root, True, replace_stale=True)
            self.assertFalse((state / 'retention-pending.json').exists())
            self.assertEqual(result['confirmed_absent'], [already_absent])
            self.assertEqual(len(list(state.glob('retention-pending.stale-*.json'))), 1)

    def test_replace_stale_requires_pending_proposal(self):
        rows, live = scenario()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / '.git').mkdir(); state = root / '.registry-state'; state.mkdir(); operator_fixture(root)
            token = state / 'retention-token'; token.write_text('synthetic'); token.chmod(0o600)
            with patch.object(retention, 'production', return_value=live), patch.object(retention, 'Registry', return_value=FakeRegistry(rows)):
                with self.assertRaises(retention.Hold):
                    retention.run(root, True, replace_stale=True)
