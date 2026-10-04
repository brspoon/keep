import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import ci_changes as changes


class PathClassificationTests(unittest.TestCase):
    def test_only_explicit_prose_and_screenshot_paths_are_allowlisted(self):
        for path in (*changes.DOCUMENTS, 'docs/screenshots/leaving.png',
                     'docs/screenshots/mobile/screen one.webp'):
            with self.subTest(path=path):
                self.assertTrue(changes.harmless_path(path))
        for path in ('LICENSE', 'THIRD_PARTY.md', 'CONTRIBUTING.md', 'SECURITY.md',
                     'docs/licenses/README.md', 'docs/PYTHON_LICENSE.txt',
                     'docs/IMAGE_SECURITY.md', 'docs/RELEASE_POLICY.md',
                     'docs/SOURCE_DISTRIBUTION.md', 'docs/new-guide.md',
                     'docs/distribution-sources.json', 'docs/os-package-sources.json',
                     'docs/image-exceptions.json', 'docs/screenshots/executable.py',
                     'docs/screenshots/preview.svg', 'static/screen.png',
                     'README.md/', '../README.md', '/README.md',
                     'docs//FEATURES.md', 'docs/screenshots/../FEATURES.md',
                     'docs\\screenshots\\screen.png', 'docs/screenshots/a\nb.png', ''):
            with self.subTest(path=path):
                self.assertFalse(changes.harmless_path(path))

    def test_raw_diff_preserves_renames_spaces_and_modes(self):
        header = ':100644 100644 ' + 'a' * 40 + ' ' + 'b' * 40 + ' R100\0'
        rows = changes.parse_changes((header + 'README.md\0docs/screenshots/screen one.png\0').encode())
        self.assertEqual(rows, [changes.Change('R100', 'README.md',
            'docs/screenshots/screen one.png', '100644', '100644')])
        self.assertTrue(changes.harmless_change(rows[0]))

    def test_raw_diff_requires_bounded_complete_supported_records(self):
        valid = (':100644 100644 ' + 'a' * 40 + ' ' + 'b' * 40 + ' M\0README.md\0').encode()
        invalid = (valid[:-1], valid.split(b'\0')[0] + b'\0', valid.replace(b' M\0', b' U\0'),
                   valid.replace(b' M\0', b' R100\0'), valid.replace(b'README.md', b'\xff'))
        for raw in invalid:
            with self.subTest(raw=raw):
                with self.assertRaises((ValueError, UnicodeError)):
                    changes.parse_changes(raw)
        with patch.object(changes, 'DIFF_LIMIT', 1):
            with self.assertRaises(ValueError):
                changes.parse_changes(valid)

    def test_symlinks_submodules_executable_and_cross_boundary_renames_are_full(self):
        rows = [changes.Change('T', 'README.md', 'README.md', '100644', '120000'),
                changes.Change('M', 'README.md', 'README.md', '100644', '100755'),
                changes.Change('M', 'README.md', 'README.md', '160000', '160000'),
                changes.Change('R100', 'app.py', 'README.md', '100644', '100644'),
                changes.Change('R100', 'README.md', 'docs/licenses/README.md', '100644', '100644'),
                changes.Change('C100', 'README.md', 'docs/FEATURES.md', '100644', '100644')]
        for row in rows:
            with self.subTest(row=row):
                self.assertFalse(changes.harmless_change(row))


@unittest.skipUnless(shutil.which('git'), 'Git integration checks run in the contributor job, outside the minimal runtime image')
class GitClassificationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='keep-ci-changes-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.run_git('init', '--quiet', '--initial-branch=main')
        for name, body in {'VERSION': '2.21.3\n', 'README.md': 'Keep documentation\n',
                           'docs/FEATURES.md': 'Feature details\n', 'app.py': 'runtime = True\n',
                           'LICENSE': 'Keep license\n',
                           'docs/screenshots/old picture.png': 'image fixture\n'}.items():
            self.write(name, body)
        self.base = self.commit()
        self.lookups = []

    def run_git(self, *args):
        return subprocess.run(['git', '-c', 'user.name=Keep CI tests',
            '-c', 'user.email=ci-tests@example.invalid', *args], cwd=self.root,
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()

    def write(self, name, body):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)

    def commit(self):
        self.run_git('add', '--all')
        self.run_git('commit', '--quiet', '--message=Test change')
        return self.run_git('rev-parse', 'HEAD')

    def plan(self, *, published=True, event='push', base=None, head=None, repository=changes.REPOSITORY):
        def lookup(version):
            self.lookups.append(version)
            return published
        return changes.classify(self.root, event, base or self.base,
            head or self.run_git('rev-parse', 'HEAD'), repository, release_lookup=lookup)

    def test_published_documentation_skips_only_native_work(self):
        self.write('README.md', 'Improved introduction\n')
        self.commit()
        plan = self.plan()
        self.assertFalse(plan.native_required)
        self.assertTrue(plan.documentation_only)
        self.assertEqual(plan.version, '2.21.3')
        self.assertEqual(plan.files, 1)
        self.assertEqual(self.lookups, ['2.21.3'])

    def test_unpublished_documentation_always_gets_exact_commit_validation(self):
        self.write('docs/FEATURES.md', 'Improved guide\n')
        self.commit()
        plan = self.plan(published=False)
        self.assertTrue(plan.native_required)
        self.assertTrue(plan.documentation_only)
        self.assertIn('fresh exact-commit', plan.reason)

    def test_runtime_and_unknown_paths_never_query_a_public_release(self):
        for name in ('app.py', 'new-input.txt', 'docs/licenses/README.md',
                     'docs/os-package-sources.json', 'tests/test_new.py',
                     '.github/workflows/image.yml', 'install.sh', 'compose.yml'):
            with self.subTest(name=name):
                self.run_git('reset', '--hard', self.base)
                self.write(name, 'changed\n')
                self.commit()
                self.assertTrue(self.plan().native_required)
        self.assertEqual(self.lookups, [])

    def test_mixed_documentation_and_runtime_diff_is_full(self):
        self.write('README.md', 'Improved guide\n')
        self.write('app.py', 'runtime = False\n')
        self.commit()
        self.assertTrue(self.plan().native_required)
        self.assertEqual(self.lookups, [])

    def test_documentation_deletion_and_whitespace_screenshot_names_are_supported(self):
        (self.root / 'docs/FEATURES.md').unlink()
        self.write('docs/screenshots/new picture.png', 'another fixture\n')
        self.commit()
        self.assertFalse(self.plan().native_required)

    def test_sensitive_deletion_is_full(self):
        (self.root / 'LICENSE').unlink()
        self.commit()
        self.assertTrue(self.plan().native_required)
        self.assertEqual(self.lookups, [])

    def test_allowlisted_rename_requires_both_names(self):
        self.run_git('mv', 'docs/screenshots/old picture.png', 'docs/screenshots/new picture.png')
        self.commit()
        rows = changes.changed_files(self.root, 'push', self.base, self.run_git('rev-parse', 'HEAD'))
        self.assertEqual(rows[0].status, 'R100')
        self.assertFalse(self.plan().native_required)

    def test_sensitive_rename_into_documentation_is_full(self):
        self.run_git('mv', 'app.py', 'docs/screenshots/runtime.png')
        self.commit()
        self.assertTrue(self.plan().native_required)
        self.assertEqual(self.lookups, [])

    @unittest.skipUnless(hasattr(os, 'symlink'), 'Native symlinks unavailable')
    def test_real_symlink_change_is_full(self):
        (self.root / 'README.md').unlink()
        os.symlink('app.py', self.root / 'README.md')
        self.commit()
        self.assertTrue(self.plan().native_required)
        self.assertEqual(self.lookups, [])

    @unittest.skipIf(os.name == 'nt', 'Executable Git modes require Unix')
    def test_executable_mode_change_is_full(self):
        (self.root / 'README.md').chmod(0o755)
        self.commit()
        self.assertTrue(self.plan().native_required)

    def test_pull_request_diff_uses_merge_base(self):
        self.run_git('checkout', '--quiet', '-b', 'feature')
        self.write('README.md', 'Feature documentation\n')
        head = self.commit()
        self.run_git('checkout', '--quiet', 'main')
        self.write('app.py', 'runtime = False\n')
        base = self.commit()
        # A two-dot diff would include the target branch's unrelated runtime edit.
        plan = self.plan(event='pull_request', base=base, head=head)
        self.assertFalse(plan.native_required)
        self.assertEqual(plan.files, 1)

    def test_missing_endpoints_checkout_mismatch_and_repository_mismatch_are_full(self):
        self.write('README.md', 'Improved guide\n')
        head = self.commit()
        for options in ({'base': '0' * 40}, {'base': 'a' * 40}, {'base': 'bad'},
                        {'head': self.base}, {'repository': 'example/fork'},
                        {'event': 'workflow_dispatch'}):
            with self.subTest(options=options):
                self.assertTrue(self.plan(**options).native_required)
        self.assertEqual(self.lookups, [])
        self.assertEqual(self.run_git('rev-parse', 'HEAD'), head)

    def test_empty_diff_and_invalid_committed_version_are_full(self):
        self.assertTrue(self.plan().native_required)
        self.write('README.md', 'Improved guide\n')
        self.write('VERSION', 'not-a-version\n')
        invalid_version_commit = self.commit()
        # Even if a preceding malformed VERSION was already present, docs cannot skip.
        self.write('README.md', 'More documentation\n')
        self.commit()
        self.assertTrue(self.plan(base=invalid_version_commit).native_required)
        self.assertEqual(self.lookups, [])

    def test_release_lookup_uncertainty_is_full_not_a_false_green_skip(self):
        self.write('README.md', 'Improved guide\n')
        head = self.commit()
        for error in (urllib.error.URLError('unavailable'), TimeoutError(), ValueError('bad JSON')):
            with self.subTest(error=error), patch.object(changes, 'published_version', side_effect=error):
                def lookup(_version):
                    raise error
                plan = changes.classify(self.root, 'push', self.base, head,
                    changes.REPOSITORY, release_lookup=lookup)
                self.assertTrue(plan.native_required)
                self.assertTrue(plan.documentation_only)
        self.assertTrue(self.plan(published='yes').native_required)


class PublicReleaseTests(unittest.TestCase):
    def setUp(self):
        self.version = '2.21.3'
        self.url = changes.API + '/releases/tags/' + self.version
        self.release = {'id': 123, 'tag_name': self.version, 'draft': False,
            'prerelease': False, 'published_at': '2026-10-03T12:00:00Z',
            'url': changes.API + '/releases/123',
            'html_url': 'https://github.com/brspoon/keep/releases/tag/' + self.version}

    def lookup(self, metadata=None, *, returned_url=None):
        class Response(io.BytesIO):
            def geturl(response):
                return returned_url or self.url
        opener = unittest.mock.Mock()
        opener.open.return_value = Response(json.dumps(self.release if metadata is None else metadata).encode())
        with patch.object(changes.urllib.request, 'build_opener', return_value=opener) as builder:
            result = changes.published_version(self.version)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, self.url)
        self.assertNotIn('authorization', {name.lower() for name in request.headers})
        self.assertIsInstance(builder.call_args.args[0], changes.NoRedirect)
        self.assertEqual(opener.open.call_args.kwargs['timeout'], 10)
        return result

    def test_only_completed_public_exact_version_release_is_proof(self):
        self.assertTrue(self.lookup())
        mutations = ({'draft': True}, {'draft': 0}, {'prerelease': True},
            {'published_at': None}, {'published_at': ''}, {'tag_name': '2.21.2'},
            {'id': True}, {'id': -1}, {'url': 'https://example.invalid/releases/123'},
            {'html_url': 'https://github.com/example/fork/releases/tag/2.21.3'})
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertFalse(self.lookup({**self.release, **mutation}))

    def test_invalid_json_shape_redirect_and_size_limit_fail_closed(self):
        with self.assertRaises(ValueError):
            self.lookup([])
        with self.assertRaises(ValueError):
            self.lookup(returned_url='https://example.invalid/release')
        with patch.object(changes, 'METADATA_LIMIT', 1):
            with self.assertRaises(ValueError):
                self.lookup()
        self.assertIsNone(changes.NoRedirect().redirect_request(None, None, 302,
            'Found', {}, 'https://example.invalid/release'))

    def test_404_is_unpublished_and_other_http_errors_remain_uncertain(self):
        for code in (404, 403, 500, 302):
            with self.subTest(code=code):
                opener = unittest.mock.Mock()
                opener.open.side_effect = urllib.error.HTTPError(self.url, code, 'error', {}, None)
                with patch.object(changes.urllib.request, 'build_opener', return_value=opener):
                    if code == 404:
                        self.assertFalse(changes.published_version(self.version))
                    else:
                        with self.assertRaises(urllib.error.HTTPError):
                            changes.published_version(self.version)

    def test_invalid_versions_are_never_sent_to_an_address(self):
        with patch.object(changes.urllib.request, 'build_opener') as builder:
            for version in ('2.21.3/../../releases', '02.21.3', '', '2.21.3\n'):
                with self.subTest(version=version), self.assertRaises(ValueError):
                    changes.published_version(version)
            builder.assert_not_called()


class ReportingTests(unittest.TestCase):
    def test_outputs_and_summary_explain_docs_skip_without_reusing_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            output, summary = Path(directory) / 'outputs', Path(directory) / 'summary'
            plan = changes.Plan(False, True, 'Verified documentation.', '2.21.3', 1)
            with patch('sys.stdout', new_callable=io.StringIO) as stdout:
                changes.report(plan, 'push', output=output, summary=summary)
            self.assertIn('native_required=false\n', output.read_text())
            self.assertIn('documentation_only=true\n', output.read_text())
            self.assertIn('Python, JavaScript and Windows installer checks remain required.', summary.read_text())
            self.assertIn("No older commit's image or source evidence is reused.", stdout.getvalue())


if __name__ == '__main__':
    unittest.main()
