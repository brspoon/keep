"""Bounded checks of the Expat API used by the normal runtime linker.

The caller must first verify the canonical loaded library and its reviewed build
record. These checks exercise behavior; they do not establish source provenance.
The reset checks adapt the upstream d8f31e6 regression tests to a 64 KiB input.
The entity check verifies c30145b's rejection before expanding an entity, using
an input whose complete expansion is only 512 characters even without the fix.
"""

from __future__ import annotations

import ctypes
import time
from contextlib import contextmanager


SONAME = "libexpat.so.1"
XML_STATUS_ERROR = 0
XML_STATUS_OK = 1
XML_ERROR_NONE = 0
XML_ERROR_AMPLIFICATION_LIMIT_BREACH = 43
XML_PROP_ERROR_NONE = 0
XML_PROP_ALLOC_TRACKER_ACTIVATION_THRESHOLD = 1
XML_PROP_ALLOC_TRACKER_MAXIMUM_AMPLIFICATION = 2
XML_PROP_BILLION_LAUGHS_ACTIVATION_THRESHOLD = 3
XML_PROP_BILLION_LAUGHS_MAXIMUM_AMPLIFICATION = 4

ALLOCATION_THRESHOLD = 32_768
ALLOCATION_CONTENT_BYTES = 65_536
ALLOCATION_DOCUMENT = b"<doc a='" + b"X" * ALLOCATION_CONTENT_BYTES + b"'/>"
ENTITY_DOCUMENT = (
    b'<!DOCTYPE r [<!ENTITY a "abcdefghijklmnop"><!ENTITY b "'
    + b"&a;" * 32
    + b'">]><r>&b;</r>'
)
RESET_DOCUMENT = b"<!DOCTYPE r [<!ENTITY e 'general entity'>]><r>&e;</r>"
MAXIMUM_INPUT_BYTES = len(ALLOCATION_DOCUMENT)
MAXIMUM_SECONDS = 10.0
ALLOCATION_RESET_CYCLES = 2
LITERAL_MARKUP_CONTROLS = (
    (b'<!DOCTYPE r [<!ENTITY word "ordinary"><!ENTITY literal "<![CDATA[&word;]]>">]><r>&literal;</r>', b'&word;'),
    (b'<!DOCTYPE r [<!ENTITY word "ordinary"><!ENTITY literal "<!-- &word; -->">]><r>&literal;</r>', b''),
    (b'<!DOCTYPE r [<!ENTITY word "ordinary"><!ENTITY literal "<?keep &word;?>">]><r>&literal;</r>', b''),
)
DEFAULT_LITERAL_TEXT = b'&word;' * 512
DEFAULT_LITERAL_DOCUMENT = (
    b'<!DOCTYPE r [<!ENTITY word "' + b'a' * 16_384
    + b'"><!ENTITY literal "<![CDATA[' + DEFAULT_LITERAL_TEXT
    + b']]>">]><r>&literal;</r>'
)
PARAMETER_ENTITY_DOCUMENT = (
    b'<!DOCTYPE r [<!ENTITY % declaration "<!ENTITY word \'safe\'>">'
    b'%declaration;]><r>&word;</r>'
)


def literal_context_controls():
    """Default-limit controls large enough to expose preflight overcounting."""
    controls = []
    for opening, closing, literal in (
        (b'<![CDATA[', b']]>', DEFAULT_LITERAL_TEXT),
        (b'<!-- ', b' -->', b''),
        (b'<?keep ', b'?>', b''),
    ):
        declaration = (b'<!DOCTYPE r [<!ENTITY outer "&head;&literal;&tail;">'
                       b'<!ENTITY head "begin"><!ENTITY literal "' + opening
                       + DEFAULT_LITERAL_TEXT + closing + b'">'
                       b'<!ENTITY word "' + b'a' * 16_384
                       + b'"><!ENTITY tail "end">]><r>&outer;</r>')
        expected = b'begin' + literal + b'end'
        for encoding in ('utf-8', 'utf-16'):
            document = declaration.decode().encode(encoding)
            controls.append((document, expected, len(document)))
            controls.append((document, expected, 7))
    # Numeric references are normalized before replacement text is scanned.
    controls.append((DEFAULT_LITERAL_DOCUMENT.replace(b'<![CDATA[', b'&#60;![CDATA['),
                     DEFAULT_LITERAL_TEXT, 11))
    controls.append((PARAMETER_ENTITY_DOCUMENT, b'safe', 1))
    controls.append((b'<!DOCTYPE r [<!ENTITY x "caf&#233;">]><r>&x;</r>',
                     'café'.encode(), 1))
    return tuple(controls)


LITERAL_CONTEXT_CONTROLS = literal_context_controls()
ACTIVE_REFERENCE_CONTROLS = tuple(
    b'<!DOCTYPE r [<!ENTITY a "abcdefghijklmnop"><!ENTITY attack "'
    + b'&a;' * 64 + b'"><!ENTITY body "' + prefix + b'&attack;' + suffix
    + b'">]><r>&body;</r>'
    for prefix, suffix in (
        (b'<![CDATA[&a;]]>', b''),
        (b'<!-- &a; -->', b''),
        (b'<?keep &a;?>', b''),
        (b"<n value='", b"'/>")
    )
)
MALFORMED_LITERAL_CONTROLS = tuple(
    b'<!DOCTYPE r [<!ENTITY body "' + prefix * 2_048 + b'">]><r>&body;</r>'
    for prefix in (b'<?keep ', b'<![CDATA[', b'<!-- ')
)

EXPECTED_RESULT = {
    "schema": "keep-expat-security-probes-v1",
    "soname": SONAME,
    "tests": 10,
    "passed": True,
    "ordinary_xml": True,
    "bounded_entity_control": True,
    "entity_preflight_rejection": True,
    "amplification_reset": True,
    "allocation_reset": True,
    "literal_markup_controls": True,
    "default_literal_xml": True,
    "literal_contexts": True,
    "active_reference_preflight": True,
    "malformed_literal_rejection": True,
    "preflight_emitted_characters": 0,
    "reset_rejections": 2,
    "allocation_reset_cycles": ALLOCATION_RESET_CYCLES,
    "maximum_input_bytes": MAXIMUM_INPUT_BYTES,
}

_CHARACTER_HANDLER = ctypes.CFUNCTYPE(
    None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


class _Expat:
    """The public Expat 2.9 property API, with every C signature specified."""

    def __init__(self, library):
        self.library = library
        pointer = ctypes.c_void_p
        signatures = {
            "XML_ParserCreate": ([ctypes.c_char_p], pointer),
            "XML_ParserFree": ([pointer], None),
            "XML_ParserReset": ([pointer, ctypes.c_char_p], ctypes.c_ubyte),
            "XML_SetParamEntityParsing": ([pointer, ctypes.c_int], ctypes.c_int),
            "XML_Parse": (
                [pointer, ctypes.c_char_p, ctypes.c_int, ctypes.c_int],
                ctypes.c_int,
            ),
            "XML_GetErrorCode": ([pointer], ctypes.c_int),
            "XML_SetCharacterDataHandler": ([pointer, _CHARACTER_HANDLER], None),
            "XML_SetPropertyDouble": (
                [pointer, ctypes.c_int, ctypes.c_double],
                ctypes.c_int,
            ),
            "XML_SetPropertyUInt64": (
                [pointer, ctypes.c_int, ctypes.c_uint64],
                ctypes.c_int,
            ),
            "XML_GetPropertyDouble": (
                [pointer, ctypes.c_int, ctypes.POINTER(ctypes.c_double)],
                ctypes.c_int,
            ),
            "XML_GetPropertyUInt64": (
                [pointer, ctypes.c_int, ctypes.POINTER(ctypes.c_uint64)],
                ctypes.c_int,
            ),
        }
        for name, (arguments, result) in signatures.items():
            try:
                function = getattr(library, name)
            except AttributeError as exc:
                raise RuntimeError(f"Expat security API is missing {name}") from exc
            function.argtypes = arguments
            function.restype = result
            setattr(self, name, function)

    @contextmanager
    def parser(self):
        parser = self.XML_ParserCreate(None)
        _require(bool(parser), "Expat could not create a security-probe parser")
        try:
            yield parser
        finally:
            self.XML_ParserFree(parser)

    def limits(self, parser, *, allocation: bool, factor: float, threshold: int):
        factor_property = (
            XML_PROP_ALLOC_TRACKER_MAXIMUM_AMPLIFICATION
            if allocation
            else XML_PROP_BILLION_LAUGHS_MAXIMUM_AMPLIFICATION
        )
        threshold_property = (
            XML_PROP_ALLOC_TRACKER_ACTIVATION_THRESHOLD
            if allocation
            else XML_PROP_BILLION_LAUGHS_ACTIVATION_THRESHOLD
        )
        _require(
            self.XML_SetPropertyDouble(parser, factor_property, factor)
            == XML_PROP_ERROR_NONE,
            "Expat rejected the security-probe amplification limit",
        )
        _require(
            self.XML_SetPropertyUInt64(parser, threshold_property, threshold)
            == XML_PROP_ERROR_NONE,
            "Expat rejected the security-probe activation threshold",
        )
        self.require_limits(
            parser, allocation=allocation, factor=factor, threshold=threshold
        )

    def require_limits(
        self, parser, *, allocation: bool, factor: float, threshold: int
    ):
        factor_property = (
            XML_PROP_ALLOC_TRACKER_MAXIMUM_AMPLIFICATION
            if allocation
            else XML_PROP_BILLION_LAUGHS_MAXIMUM_AMPLIFICATION
        )
        threshold_property = (
            XML_PROP_ALLOC_TRACKER_ACTIVATION_THRESHOLD
            if allocation
            else XML_PROP_BILLION_LAUGHS_ACTIVATION_THRESHOLD
        )
        actual_factor = ctypes.c_double()
        actual_threshold = ctypes.c_uint64()
        _require(
            self.XML_GetPropertyDouble(
                parser, factor_property, ctypes.byref(actual_factor)
            )
            == XML_PROP_ERROR_NONE
            and actual_factor.value == factor,
            "Expat changed the configured amplification limit",
        )
        _require(
            self.XML_GetPropertyUInt64(
                parser, threshold_property, ctypes.byref(actual_threshold)
            )
            == XML_PROP_ERROR_NONE
            and actual_threshold.value == threshold,
            "Expat changed the configured activation threshold",
        )


def _check_deadline(deadline: float) -> None:
    _require(time.monotonic() <= deadline, "Expat security probes exceeded their time bound")


def _parse(api, parser, document: bytes, deadline: float, *, chunk_size: int = 64):
    _require(
        0 < len(document) <= MAXIMUM_INPUT_BYTES and chunk_size > 0,
        "Expat security-probe input exceeds its fixed bound",
    )
    for offset in range(0, len(document), chunk_size):
        _check_deadline(deadline)
        chunk = document[offset : offset + chunk_size]
        status = api.XML_Parse(
            parser, chunk, len(chunk), int(offset + len(chunk) == len(document))
        )
        _check_deadline(deadline)
        if status != XML_STATUS_OK:
            return status, api.XML_GetErrorCode(parser)
    return status, api.XML_GetErrorCode(parser)


def _capture(api, parser):
    # Hold the returned callback until parsing has finished: C keeps its pointer.
    data = bytearray()
    invalid = [False]

    def receive(_context, text, length):
        if not 0 <= length <= MAXIMUM_INPUT_BYTES - len(data):
            invalid[0] = True
            return
        data.extend(ctypes.string_at(text, length))

    callback = _CHARACTER_HANDLER(receive)
    api.XML_SetCharacterDataHandler(parser, callback)
    return data, callback, invalid


def _exercise_literal_contexts(api, deadline):
    for document, expected, chunk_size in LITERAL_CONTEXT_CONTROLS:
        with api.parser() as parser:
            if document == PARAMETER_ENTITY_DOCUMENT:
                _require(api.XML_SetParamEntityParsing(parser, 2) == 1,
                         'Expat parameter-entity control is unavailable')
            data, callback, invalid = _capture(api, parser)
            status, error = _parse(api, parser, document, deadline, chunk_size=chunk_size)
            _require((status, error, bytes(data))
                     == (XML_STATUS_OK, XML_ERROR_NONE, expected) and not invalid[0],
                     'Expat default-limit XML context compatibility failed')
    for document in ACTIVE_REFERENCE_CONTROLS:
        with api.parser() as parser:
            api.limits(parser, allocation=False, factor=2.0, threshold=0)
            data, callback, invalid = _capture(api, parser)
            status, error = _parse(api, parser, document, deadline, chunk_size=len(document))
            _require((status, error) == (XML_STATUS_ERROR, XML_ERROR_AMPLIFICATION_LIMIT_BREACH)
                     and not data and not invalid[0],
                     'Expat literal markup hid an active reference from preflight')
    for document in MALFORMED_LITERAL_CONTROLS:
        with api.parser() as parser:
            status, error = _parse(api, parser, document, deadline, chunk_size=len(document))
            _require(status == XML_STATUS_ERROR and error != XML_ERROR_NONE,
                     'Expat accepted malformed literal markup')


def _exercise(api) -> dict:
    deadline = time.monotonic() + MAXIMUM_SECONDS
    with api.parser() as parser:
        data, callback, invalid = _capture(api, parser)
        status, error = _parse(
            api, parser, b"<root><item>safe &amp; sound</item></root>", deadline
        )
        _require(
            (status, error, bytes(data))
            == (XML_STATUS_OK, XML_ERROR_NONE, b"safe & sound")
            and not invalid[0],
            "Expat ordinary XML control failed",
        )

    with api.parser() as parser:
        api.limits(parser, allocation=False, factor=2.0, threshold=0)
        data, callback, invalid = _capture(api, parser)
        status, error = _parse(
            api,
            parser,
            b'<!DOCTYPE r [<!ENTITY e "ordinary">]><r>&e;</r>',
            deadline,
        )
        _require(
            (status, error, bytes(data))
            == (XML_STATUS_OK, XML_ERROR_NONE, b"ordinary")
            and not invalid[0],
            "Expat bounded entity control failed",
        )

    with api.parser() as parser:
        api.limits(parser, allocation=False, factor=2.0, threshold=0)
        data, callback, invalid = _capture(api, parser)
        # A single feed makes the available direct-byte budget unambiguous.
        status, error = _parse(
            api, parser, ENTITY_DOCUMENT, deadline, chunk_size=len(ENTITY_DOCUMENT)
        )
        _require(
            (status, error)
            == (XML_STATUS_ERROR, XML_ERROR_AMPLIFICATION_LIMIT_BREACH)
            and not data
            and not invalid[0],
            "Expat did not reject the entity before expansion",
        )

    with api.parser() as parser:
        api.limits(parser, allocation=False, factor=1.0, threshold=0)
        for attempt in range(2):
            if attempt:
                _require(
                    api.XML_ParserReset(parser, None) == XML_STATUS_OK,
                    "Expat amplification-probe reset failed",
                )
                api.require_limits(
                    parser, allocation=False, factor=1.0, threshold=0
                )
            _require(
                _parse(api, parser, RESET_DOCUMENT, deadline, chunk_size=1)
                == (XML_STATUS_ERROR, XML_ERROR_AMPLIFICATION_LIMIT_BREACH),
                "Expat reset discarded the configured amplification protection",
            )

    with api.parser() as parser:
        api.limits(
            parser, allocation=True, factor=100.0, threshold=ALLOCATION_THRESHOLD
        )
        for cycle in range(ALLOCATION_RESET_CYCLES):
            if cycle:
                _require(
                    api.XML_ParserReset(parser, None) == XML_STATUS_OK,
                    "Expat allocation-probe cycle reset failed",
                )
            _require(
                _parse(api, parser, ALLOCATION_DOCUMENT, deadline)
                == (XML_STATUS_OK, XML_ERROR_NONE),
                "Expat bounded allocation control failed",
            )
            _require(
                api.XML_ParserReset(parser, None) == XML_STATUS_OK,
                "Expat allocation-probe reset failed",
            )
            api.require_limits(
                parser, allocation=True, factor=100.0, threshold=ALLOCATION_THRESHOLD
            )
            _require(
                _parse(api, parser, b"<hello/>", deadline, chunk_size=1)
                == (XML_STATUS_OK, XML_ERROR_NONE),
                "Expat reset retained allocation accounting from the previous document",
            )
    for document, expected in LITERAL_MARKUP_CONTROLS:
        with api.parser() as parser:
            data, callback, invalid = _capture(api, parser)
            status, error = _parse(api, parser, document, deadline)
            _require(
                (status, error, bytes(data)) == (XML_STATUS_OK, XML_ERROR_NONE, expected)
                and not invalid[0],
                "Expat literal markup control failed",
            )
    with api.parser() as parser:
        # Keep untouched defaults: the reference-looking text is literal CDATA.
        data, callback, invalid = _capture(api, parser)
        status, error = _parse(
            api, parser, DEFAULT_LITERAL_DOCUMENT, deadline,
            chunk_size=len(DEFAULT_LITERAL_DOCUMENT),
        )
        _require(
            (status, error, bytes(data))
            == (XML_STATUS_OK, XML_ERROR_NONE, DEFAULT_LITERAL_TEXT)
            and not invalid[0],
            "Expat default-limit literal XML compatibility failed "
            f"(status={status}, error={error}, output_bytes={len(data)})",
        )
    _exercise_literal_contexts(api, deadline)
    _check_deadline(deadline)
    return expected_report()


def exercise_expat_security() -> dict:
    """Run all checks using the same SONAME resolved by ordinary consumers."""
    return _exercise(_Expat(ctypes.CDLL(SONAME)))


def expected_report() -> dict:
    """Return the fixed successful shape for strict evidence fixtures."""
    return dict(EXPECTED_RESULT)


def validate_report(probes) -> None:
    """Revalidate the complete successful result without loading native code."""
    _require(
        type(probes) is dict and set(probes) == set(EXPECTED_RESULT),
        "Expat security-probe report fields are incomplete or unexpected",
    )
    for field, expected in EXPECTED_RESULT.items():
        actual = probes[field]
        _require(
            type(actual) is type(expected) and actual == expected,
            f"Expat security-probe report has invalid {field}",
        )
