"""Matching source must be attached to the exact reviewed binary subject."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('collect_image_sources', ROOT / 'scripts/collect_image_sources.py')
sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sources)


class SourceStatementTests(unittest.TestCase):
    def statement(self, subject='a' * 64, predicate=sources.PREDICATE, materials=None):
        return json.dumps({'predicateType': predicate, 'subject': [{'digest': {'sha256': subject}}],
                           'predicate': materials if materials is not None else {'source': 'pinned'}})

    def test_rejects_source_for_another_binary(self):
        with self.assertRaisesRegex(ValueError, 'pinned native image'):
            sources.checked_statement(self.statement(), 'b' * 64)

    def test_rejects_other_kind_of_evidence(self):
        with self.assertRaisesRegex(ValueError, 'predicate'):
            sources.checked_statement(self.statement(predicate='https://slsa.dev/provenance/v1'), 'a' * 64)

    def test_empty_materials_cannot_satisfy_source_obligation(self):
        with self.assertRaisesRegex(ValueError, 'no corresponding-source'):
            sources.checked_statement(self.statement(materials={}), 'a' * 64)

    def test_matching_subject_and_materials_are_retained(self):
        self.assertEqual(sources.checked_statement(self.statement(), 'a' * 64)['predicate'], {'source': 'pinned'})

    def test_source_reference_requires_expected_repository_and_immutable_digest(self):
        good = {'predicate': {'source': {'name': 'dhi/python', 'digest': 'sha256:' + 'a' * 64}}}
        self.assertEqual(sources.source_reference(good), 'dhi.io/python@sha256:' + 'a' * 64)
        for bad in ({'name': 'other/private', 'digest': 'sha256:' + 'a' * 64},
                    {'name': 'dhi/python', 'digest': 'latest'}):
            with self.assertRaisesRegex(ValueError, 'un(?:expected|pinned)'):
                sources.source_reference({'predicate': {'source': bad}})
