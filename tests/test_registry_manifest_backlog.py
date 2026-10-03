"""Offline tests for durable registry manifest graph retention."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
from email.message import Message
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import retain_registry as retention


def dg(char):
    return 'sha256:' + char * 64


def production_and_tags():
    revision = format(5, '040x')
    root, amd, arm = dg('1'), dg('2'), dg('3')
    images = [{'os': 'linux', 'architecture': 'amd64', 'digest': amd},
              {'os': 'linux', 'architecture': 'arm64', 'digest': arm}]
    rows = []
    for number in range(1, 6):
        version = f'2.0.{number}'
        index, child_a, child_b = dg(str(number + 3)), dg('b' if number != 5 else '2'), dg('c' if number != 5 else '3')
        index_images = [{'os': 'linux', 'architecture': 'amd64', 'digest': child_a},
                        {'os': 'linux', 'architecture': 'arm64', 'digest': child_b}]
        commit = 'sha-' + format(number, '040x')
        rows.extend([
            {'name': version, 'digest': index, 'images': copy.deepcopy(index_images)},
            {'name': commit, 'digest': index, 'images': copy.deepcopy(index_images)},
            {'name': commit + '-amd64', 'digest': child_a,
             'images': [{'os': 'linux', 'architecture': 'amd64', 'digest': child_a}]},
            {'name': commit + '-arm64', 'digest': child_b,
             'images': [{'os': 'linux', 'architecture': 'arm64', 'digest': child_b}]},
        ])
    stable = copy.deepcopy(next(row for row in rows if row['name'] == '2.0.5'))
    stable['name'] = 'stable'
    rows.append(stable)
    live = {'version': '2.0.5', 'revision': revision, 'registry_digests': [stable['digest']]}
    return rows, live


class MemoryRegistry:
    def __init__(self, rows, manifests):
        self.rows = copy.deepcopy(rows)
        self.manifests = copy.deepcopy(manifests)
        for row in rows:
            children = sorted({image['digest'] for image in row['images']} - {row['digest']})
            self.manifests.setdefault(row['digest'], {'children': children})
            for child in children:
                self.manifests.setdefault(child, {'children': []})
        self.events = []
        self.fail_delete = set()
        self.keep_after_delete = set()
        self.fail_after_delete = set()

    def tags(self, expected_absent=()):
        self.events.append(('tags', tuple(expected_absent)))
        return copy.deepcopy(self.rows)

    def manifest(self, value):
        self.events.append(('get', value))
        return copy.deepcopy(self.manifests.get(value))

    def delete_manifest(self, value):
        self.events.append(('delete', value))
        if value in self.fail_after_delete:
            self.manifests.pop(value, None)
            raise retention.Hold('synthetic response lost after deletion')
        if value in self.fail_delete:
            raise retention.Hold('synthetic registry delete refusal')
        if value not in self.keep_after_delete:
            self.manifests.pop(value, None)

    def delete_tag(self, value):
        self.events.append(('delete-tag', value))
        self.rows = [row for row in self.rows if row['name'] != value]


class ManifestBacklogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / '.registry-state'
        self.state.mkdir()
        self.rows, self.live = production_and_tags()

    def test_remembers_exact_graph_and_parent_first_order_across_empty_next_plan(self):
        parent, child, grandchild = dg('d'), dg('e'), dg('f')
        independent = dg('0')
        graph = {parent: {'children': [child]}, child: {'children': [grandchild]},
                 grandchild: {'children': []}, independent: {'children': []}}
        registry = MemoryRegistry(self.rows, graph)
        proposed = {'image': retention.IMAGE, 'production': self.live['version'],
                    'manifests': [parent, independent], 'tags': {}}
        retention.remember_manifest_targets(registry, proposed, self.state)
        self.assertEqual(proposed['manifests'], [independent, parent, child, grandchild])
        ledger_path = self.state / 'retention-manifests.json'
        ledger = json.loads(ledger_path.read_text())
        self.assertEqual(ledger['schema'], retention.MANIFEST_LEDGER)
        self.assertEqual(ledger['image'], retention.IMAGE)
        self.assertEqual(ledger['manifests'], graph)
        self.assertEqual(ledger_path.stat().st_mode & 0o777, 0o600)

        # Once tags no longer nominate the old indexes, prior exact graph targets
        # remain admitted and are refreshed from immutable registry objects.
        registry.manifests.pop(parent)
        registry.manifests.pop(child)
        next_plan = {'image': retention.IMAGE, 'production': self.live['version'], 'manifests': [], 'tags': {}}
        retention.remember_manifest_targets(registry, next_plan, self.state)
        self.assertEqual(next_plan['manifests'], [independent, parent, child, grandchild])
        self.assertIn(parent, next_plan['manifest_records'])
        self.assertEqual(next_plan['manifest_records'][parent], graph[parent])
        self.assertEqual(next_plan['manifest_records'][child], graph[child])

    def test_rejects_wrong_repository_or_non_private_backlog_file(self):
        path = self.state / 'retention-manifests.json'
        path.write_text(json.dumps({'schema': retention.MANIFEST_LEDGER, 'image': 'other/repository',
                                    'manifests': {}}))
        path.chmod(0o600)
        with self.assertRaisesRegex(retention.Hold, 'Unexpected manifest backlog'):
            retention.manifest_backlog(path)
        path.write_text(json.dumps({'schema': retention.MANIFEST_LEDGER, 'image': retention.IMAGE,
                                    'manifests': {}}))
        path.chmod(0o644)
        with self.assertRaisesRegex(retention.Hold, 'private owner-only'):
            retention.manifest_backlog(path)

        path.unlink()
        outside = self.root / 'ledger-target.json'
        outside.write_text(json.dumps({'schema': retention.MANIFEST_LEDGER, 'image': retention.IMAGE,
                                       'manifests': {}}))
        outside.chmod(0o600)
        path.symlink_to(outside)
        with self.assertRaisesRegex(retention.Hold, 'private owner-only'):
            retention.manifest_backlog(path)

    def test_backlog_rejects_incomplete_children_and_cycles(self):
        path = self.state / 'retention-manifests.json'
        parent, child = dg('d'), dg('e')
        for graph in (
                {parent: {'children': [child]}},
                {parent: {'children': [child]}, child: {'children': [parent]}}):
            path.write_text(json.dumps({'schema': retention.MANIFEST_LEDGER, 'image': retention.IMAGE,
                                        'manifests': graph}))
            path.chmod(0o600)
            with self.assertRaises(retention.Hold):
                retention.manifest_backlog(path)

    def make_apply_proposal(self, registry, manifests, records):
        stable = next(row for row in self.rows if row['name'] == 'stable')
        return {'image': retention.IMAGE, 'production': self.live['version'],
                'stable': stable['digest'], 'tags': {}, 'manifests': manifests,
                'manifest_records': records, 'reviewed_artifacts': {}}

    def test_parent_absence_is_read_back_before_its_child_can_be_deleted(self):
        parent, child = dg('d'), dg('e')
        registry = MemoryRegistry(self.rows, {parent: {'children': [child]}, child: {'children': []}})
        proposal = self.make_apply_proposal(registry, [parent, child],
                                            {parent: {'children': [child]}, child: {'children': []}})
        deleted = retention.apply(registry, proposal, lambda: self.live)
        self.assertEqual([event for event in registry.events if event[0] == 'delete'],
                         [('delete', parent), ('delete', child)])
        events = registry.events
        parent_deleted = events.index(('delete', parent))
        parent_absence = events.index(('get', parent), parent_deleted + 1)
        child_prefetch = events.index(('get', child), parent_absence + 1)
        self.assertLess(parent_absence, child_prefetch)
        self.assertIsNone(registry.manifests.get(parent))
        self.assertIsNone(registry.manifests.get(child))
        self.assertEqual(set(proposal['confirmed_absent_manifests']), {parent, child})

    def test_stalled_parent_blocks_child_while_independent_root_can_finish(self):
        independent, parent, child = dg('0'), dg('d'), dg('e')
        graph = {independent: {'children': []}, parent: {'children': [child]}, child: {'children': []}}
        registry = MemoryRegistry(self.rows, graph)
        registry.fail_delete.add(parent)
        proposal = self.make_apply_proposal(registry, [independent, parent, child], graph)
        with self.assertRaisesRegex(retention.Hold, 'not yet confirmed|synthetic registry delete refusal'):
            retention.apply(registry, proposal, lambda: self.live)
        self.assertNotIn(independent, registry.manifests)
        self.assertIn(parent, registry.manifests)
        self.assertIn(child, registry.manifests)
        self.assertIn(('delete', independent), registry.events)
        self.assertNotIn(('delete', child), registry.events)

    def test_new_custom_reference_protects_manifest_target(self):
        pinned = dg('d')
        rows = copy.deepcopy(self.rows)
        rows.append({'name': 'operator-pin', 'digest': pinned,
                     'images': [{'os': 'linux', 'architecture': 'amd64', 'digest': pinned}]})
        registry = MemoryRegistry(rows, {pinned: {'children': []}})
        proposal = self.make_apply_proposal(registry, [pinned], {pinned: {'children': []}})
        deleted = retention.apply(registry, proposal, lambda: self.live)
        self.assertNotIn(('delete', pinned), registry.events)
        self.assertIn(pinned, registry.manifests)
        self.assertEqual(deleted, [])

    def test_unselected_untagged_parent_protects_child(self):
        parent, child = dg('d'), dg('e')
        graph = {parent: {'children': [child]}, child: {'children': []}}
        registry = MemoryRegistry(self.rows, graph)
        proposal = self.make_apply_proposal(registry, [child], graph)
        retention.apply(registry, proposal, lambda: self.live)
        self.assertIn(parent, registry.manifests)
        self.assertIn(child, registry.manifests)
        self.assertNotIn(('delete', child), registry.events)

    def test_nested_custom_index_reference_protects_intermediate_old_index(self):
        custom_root, target, amd, arm = dg('0'), dg('d'), dg('2'), dg('3')
        custom_rows = copy.deepcopy(self.rows)
        custom_rows.append({'name': 'custom-pin', 'digest': custom_root,
                            'images': [{'os': 'linux', 'architecture': 'amd64', 'digest': amd},
                                       {'os': 'linux', 'architecture': 'arm64', 'digest': arm}]})
        graph = {custom_root: {'children': [target]}, target: {'children': [amd, arm]},
                 amd: {'children': []}, arm: {'children': []}}
        registry = MemoryRegistry(custom_rows, graph)
        proposal = self.make_apply_proposal(registry, [target], {target: {'children': [amd, arm]}})
        retention.apply(registry, proposal, lambda: self.live)
        self.assertIn(target, registry.manifests)
        self.assertNotIn(('delete', target), registry.events)

    def test_unknown_currently_tagged_manifest_holds_before_any_delete(self):
        target = dg('d')
        registry = MemoryRegistry(self.rows, {target: {'children': []}})
        stable_digest = next(row['digest'] for row in self.rows if row['name'] == 'stable')
        registry.manifests.pop(stable_digest)
        proposal = self.make_apply_proposal(registry, [target], {target: {'children': []}})
        with self.assertRaisesRegex(retention.Hold, 'currently tagged manifest is unavailable'):
            retention.apply(registry, proposal, lambda: self.live)
        self.assertNotIn(('delete', target), registry.events)

    def test_present_manifest_after_delete_blocks_child_but_absent_readback_resolves_error(self):
        parent, child = dg('d'), dg('e')
        graph = {parent: {'children': [child]}, child: {'children': []}}
        stalled = MemoryRegistry(self.rows, graph)
        stalled.keep_after_delete.add(parent)
        proposal = self.make_apply_proposal(stalled, [parent, child], graph)
        with self.assertRaisesRegex(retention.Hold, 'not yet confirmed'):
            retention.apply(stalled, proposal, lambda: self.live)
        self.assertNotIn(('delete', child), stalled.events)

        removed_then_error = MemoryRegistry(self.rows, graph)
        removed_then_error.fail_after_delete.add(parent)
        proposal = self.make_apply_proposal(removed_then_error, [parent, child], graph)
        retention.apply(removed_then_error, proposal, lambda: self.live)
        self.assertNotIn(parent, removed_then_error.manifests)
        self.assertNotIn(child, removed_then_error.manifests)
        self.assertEqual([event for event in removed_then_error.events if event[0] == 'delete'],
                         [('delete', parent), ('delete', child)])

    def test_confirmed_absent_result_targets_are_not_reintroduced(self):
        parent, child = dg('d'), dg('e')
        graph = {parent: {'children': [child]}, child: {'children': []}}
        registry = MemoryRegistry(self.rows, graph)
        result = {'image': retention.IMAGE, 'manifests': [parent, child],
                  'confirmed_absent_manifests': [parent, child]}
        (self.state / 'retention-result.json').write_text(json.dumps(result))
        proposed = {'image': retention.IMAGE, 'production': self.live['version'], 'manifests': [], 'tags': {}}
        retention.remember_manifest_targets(registry, proposed, self.state)
        self.assertEqual(proposed['manifests'], [])
        self.assertEqual(proposed['manifest_records'], {})

    def test_registry_manifest_fails_closed_on_bytes_media_type_subject_and_transport(self):
        class Response:
            def __init__(self, body): self.body = body
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, _limit): return self.body

        class Opener:
            def __init__(self, response=None, error=None): self.response, self.error = response, error
            def open(self, _request, timeout):
                self.timeout = timeout
                if self.error: raise self.error
                return self.response

        media = 'application/vnd.oci.image.index.v1+json'
        raw = json.dumps({'schemaVersion': 2, 'mediaType': media, 'manifests': []}).encode()
        valid = object.__new__(retention.Registry)
        valid.registry_token = 'synthetic'
        valid.opener = Opener(Response(raw))
        self.assertEqual(valid.manifest('sha256:' + hashlib.sha256(raw).hexdigest()), {'children': []})

        mismatch = object.__new__(retention.Registry)
        mismatch.registry_token = 'synthetic'
        mismatch.opener = Opener(Response(raw))
        with self.assertRaisesRegex(retention.Hold, 'bytes differ'):
            mismatch.manifest(dg('0'))

        for document in (
                {'schemaVersion': 2, 'mediaType': 'text/plain', 'manifests': []},
                {'schemaVersion': 2, 'mediaType': media, 'subject': {'digest': dg('f')}, 'manifests': []}):
            body = json.dumps(document).encode()
            invalid = object.__new__(retention.Registry)
            invalid.registry_token = 'synthetic'
            invalid.opener = Opener(Response(body))
            with self.assertRaises(retention.Hold):
                invalid.manifest('sha256:' + hashlib.sha256(body).hexdigest())

        for error in (urllib.error.HTTPError('https://registry.invalid', 403, 'forbidden', Message(), None),
                      urllib.error.URLError('offline')):
            unavailable = object.__new__(retention.Registry)
            unavailable.registry_token = 'synthetic'
            unavailable.opener = Opener(error=error)
            with self.assertRaises(retention.Hold):
                unavailable.manifest(dg('f'))


if __name__ == '__main__':
    unittest.main()
