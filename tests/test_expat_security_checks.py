import ctypes
import hashlib
import importlib.util
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "expat_security_checks", Path(__file__).parents[1] / "scripts/expat_security_checks.py"
)
checks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checks)


class FakeAPI:
    def __init__(self):
        self.created = []
        self.freed = []
        self.limits = mock.Mock()
        self.require_limits = mock.Mock()
        self.XML_ParserReset = mock.Mock(return_value=checks.XML_STATUS_OK)

    @contextmanager
    def parser(self):
        parser = object()
        self.created.append(parser)
        try:
            yield parser
        finally:
            self.freed.append(parser)


def captures():
    return [
        (bytearray(b"safe & sound"), object(), [False]),
        (bytearray(b"ordinary"), object(), [False]),
        (bytearray(), object(), [False]),
        *[(bytearray(expected), object(), [False])
          for _, expected in checks.LITERAL_MARKUP_CONTROLS],
        (bytearray(checks.DEFAULT_LITERAL_TEXT), object(), [False]),
    ]


def parse_results():
    ok = (checks.XML_STATUS_OK, checks.XML_ERROR_NONE)
    rejected = (
        checks.XML_STATUS_ERROR,
        checks.XML_ERROR_AMPLIFICATION_LIMIT_BREACH,
    )
    return [ok, ok, rejected, rejected, rejected, ok, ok, ok, ok, ok, ok, ok, ok]


class ExpatSecurityChecksTests(unittest.TestCase):
    def run_fake(self, *, results=None, capture_results=None, api=None):
        api = api or FakeAPI()
        with (
            mock.patch.object(checks, "_capture", side_effect=capture_results or captures()),
            mock.patch.object(checks, "_parse", side_effect=results or parse_results()) as parse,
        ):
            result = checks._exercise(api)
        return result, api, parse

    def test_complete_result_and_bounded_inputs(self):
        result, api, parse = self.run_fake()
        self.assertEqual(result, checks.expected_report())
        self.assertIsNone(checks.validate_report(result))
        self.assertEqual(api.created, api.freed)
        self.assertEqual(len(api.created), 9)
        self.assertEqual(api.XML_ParserReset.call_count, 4)
        self.assertEqual(parse.call_count, 13)
        documents = [call.args[2] for call in parse.call_args_list]
        self.assertEqual(max(map(len, documents)), 65_547)
        self.assertEqual(len(checks.ENTITY_DOCUMENT), 165)
        self.assertEqual(documents.count(checks.ALLOCATION_DOCUMENT), 2)
        self.assertEqual(documents.count(b"<hello/>"), 2)
        self.assertEqual(len(checks.DEFAULT_LITERAL_DOCUMENT), 19_536)
        self.assertEqual(hashlib.sha256(checks.DEFAULT_LITERAL_DOCUMENT).hexdigest(),
                         'c7e9ee64fa6e9994c96335666cb146cd258036c7277e0841faa5851bdd3ca26d')
        self.assertFalse(any(call.args[0] is api.created[-1]
                             for call in api.limits.call_args_list))

    def test_default_limit_rejection_of_literal_cdata_blocks(self):
        results = parse_results()
        results[-1] = (checks.XML_STATUS_ERROR, checks.XML_ERROR_AMPLIFICATION_LIMIT_BREACH)
        captured = captures()
        captured[-1][0].clear()
        with self.assertRaisesRegex(RuntimeError, 'default-limit literal XML compatibility'):
            self.run_fake(results=results, capture_results=captured)

    def test_loads_only_normal_soname(self):
        with (
            mock.patch.object(checks.ctypes, "CDLL") as load,
            mock.patch.object(checks, "_Expat") as api,
            mock.patch.object(checks, "_exercise", return_value={"result": 1}) as exercise,
        ):
            self.assertEqual(checks.exercise_expat_security(), {"result": 1})
        load.assert_called_once_with("libexpat.so.1")
        api.assert_called_once_with(load.return_value)
        exercise.assert_called_once_with(api.return_value)

    def test_literal_markup_keeps_entity_reference_text_literal(self):
        captured = captures()
        captured[3][0].extend(b'changed')
        api = FakeAPI()
        with self.assertRaisesRegex(RuntimeError, 'literal markup control'):
            self.run_fake(capture_results=captured, api=api)
        self.assertEqual(api.created, api.freed)

    def test_rejects_late_entity_expansion(self):
        captured = captures()
        captured[2][0].extend(b"x")
        api = FakeAPI()
        with self.assertRaisesRegex(RuntimeError, "before expansion"):
            self.run_fake(capture_results=captured, api=api)
        self.assertEqual(api.created, api.freed)

    def test_rejects_invalid_callback_length(self):
        captured = captures()
        captured[2][2][0] = True
        with self.assertRaisesRegex(RuntimeError, "before expansion"):
            self.run_fake(capture_results=captured)

    def test_every_native_failure_blocks(self):
        for index in range(len(parse_results())):
            results = parse_results()
            results[index] = (checks.XML_STATUS_ERROR, 1)
            api = FakeAPI()
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                self.run_fake(results=results, api=api)
            self.assertEqual(api.created, api.freed)

    def test_acceptance_of_amplifying_document_blocks(self):
        for index in (2, 3, 4):
            results = parse_results()
            results[index] = (checks.XML_STATUS_OK, checks.XML_ERROR_NONE)
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                self.run_fake(results=results)

    def test_reset_failure_blocks_and_frees_parser(self):
        api = FakeAPI()
        api.XML_ParserReset.return_value = 0
        with self.assertRaisesRegex(RuntimeError, "reset failed"):
            self.run_fake(api=api)
        self.assertEqual(api.created, api.freed)

    def test_reset_limit_change_blocks_and_frees_parser(self):
        api = FakeAPI()
        api.require_limits.side_effect = RuntimeError("changed configured limit")
        with self.assertRaisesRegex(RuntimeError, "changed configured limit"):
            self.run_fake(api=api)
        self.assertEqual(api.created, api.freed)

    def test_native_api_types_and_parser_cleanup(self):
        library = SimpleNamespace()
        names = (
            "XML_ParserCreate", "XML_ParserFree", "XML_ParserReset", "XML_Parse",
            "XML_GetErrorCode", "XML_SetCharacterDataHandler", "XML_SetPropertyDouble",
            "XML_SetPropertyUInt64", "XML_GetPropertyDouble", "XML_GetPropertyUInt64",
        )
        for name in names:
            setattr(library, name, mock.Mock())
        library.XML_ParserCreate.return_value = 123
        api = checks._Expat(library)
        self.assertIs(library.XML_ParserCreate.restype, ctypes.c_void_p)
        self.assertIs(library.XML_ParserReset.restype, ctypes.c_ubyte)
        self.assertEqual(
            library.XML_SetPropertyUInt64.argtypes,
            [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint64],
        )
        self.assertEqual(
            library.XML_GetPropertyDouble.argtypes,
            [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_double)],
        )
        with self.assertRaisesRegex(RuntimeError, "stop"):
            with api.parser() as parser:
                self.assertEqual(parser, 123)
                raise RuntimeError("stop")
        library.XML_ParserFree.assert_called_once_with(123)

    def test_missing_security_api_blocks(self):
        with self.assertRaisesRegex(RuntimeError, "missing XML_ParserCreate"):
            checks._Expat(SimpleNamespace())

    def test_all_report_fields_have_exact_types_and_values(self):
        expected = checks.expected_report()
        for field, value in expected.items():
            bad_values = [None, [], {}]
            if type(value) is bool:
                bad_values += [not value, int(value), str(value)]
            elif type(value) is int:
                bad_values += [value + 1, str(value), float(value), bool(value)]
            else:
                bad_values += [value + "-different"]
            for wrong in bad_values:
                changed = dict(expected, **{field: wrong})
                with self.subTest(field=field, wrong=wrong), self.assertRaises(RuntimeError):
                    checks.validate_report(changed)
            changed = dict(expected)
            del changed[field]
            with self.subTest(missing=field), self.assertRaises(RuntimeError):
                checks.validate_report(changed)
        with self.assertRaises(RuntimeError):
            checks.validate_report(dict(expected, unreviewed=True))
        for value in (None, [], "passed", True):
            with self.subTest(type=type(value)), self.assertRaises(RuntimeError):
                checks.validate_report(value)

    def test_report_template_is_not_shared(self):
        report = checks.expected_report()
        report["passed"] = False
        self.assertTrue(checks.expected_report()["passed"])

    def test_parse_enforces_size_and_elapsed_bounds(self):
        api = SimpleNamespace(XML_Parse=mock.Mock(return_value=1), XML_GetErrorCode=mock.Mock(return_value=0))
        with mock.patch.object(checks.time, "monotonic", return_value=11):
            with self.assertRaisesRegex(RuntimeError, "time bound"):
                checks._parse(api, 123, b"<r/>", 10)
        api.XML_Parse.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "fixed bound"):
            checks._parse(api, 123, b"x" * (checks.MAXIMUM_INPUT_BYTES + 1), 10)
        api.XML_Parse.assert_not_called()

    def test_callback_caps_total_output(self):
        api = SimpleNamespace(XML_SetCharacterDataHandler=mock.Mock())
        data, callback, invalid = checks._capture(api, 123)
        text = ctypes.create_string_buffer(b"test")
        callback(None, ctypes.addressof(text), 4)
        self.assertEqual(data, b"test")
        callback(None, ctypes.addressof(text), checks.MAXIMUM_INPUT_BYTES)
        self.assertEqual(data, b"test")
        self.assertTrue(invalid[0])


if __name__ == "__main__":
    unittest.main()
