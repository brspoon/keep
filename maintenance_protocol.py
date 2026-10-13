"""Fixed-operation signed protocol.

The host creates enrollment locally. Browser requests cannot choose the owner,
context, daemon, paths, or key.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import secrets
import time
import uuid

MAX_ENVELOPE = 16384
MAX_LIFETIME = 900
MAX_SKEW = 30
HASH = re.compile(r"[a-f0-9]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}\Z")
REVISION = re.compile(r"[a-f0-9]{40}\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\Z")
OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
PHASES = frozenset(("accepted", "resolving", "pulling", "draining", "stopping",
                   "backing-up", "prepared", "activating", "verifying", "committed", "success",
                   "failed", "recovery-needed", "recovering", "recovery-committed", "recovered", "held"))
TERMINAL = frozenset(("success", "failed", "recovered"))


class ProtocolError(RuntimeError):
    """Fixed error messages are suitable for sanitized status responses."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("Duplicate JSON field")
        result[key] = value
    return result


def parse_json(data: bytes, limit=MAX_ENVELOPE):
    if not isinstance(data, bytes) or not data or len(data) > limit:
        raise ProtocolError("Message size is invalid")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ProtocolError("Invalid JSON number")))
    except (UnicodeError, ValueError, TypeError) as error:
        raise ProtocolError("Message is not valid JSON") from error


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError) as error:
        raise ProtocolError("Message cannot be canonicalized") from error


def exact_fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ProtocolError("Unexpected message fields")


def canonical_uuid(value):
    if not isinstance(value, str):
        raise ProtocolError("Invalid request identity")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise ProtocolError("Invalid request identity") from error
    if parsed.version != 4 or str(parsed) != value:
        raise ProtocolError("Invalid request identity")
    return value


@dataclass(frozen=True)
class ImageIdentity:
    index_digest: str
    native_digest: str
    image_id: str
    version: str
    revision: str
    architecture: str

    @classmethod
    def from_dict(cls, value):
        exact_fields(value, cls.__dataclass_fields__)
        for field in ("index_digest", "native_digest", "image_id"):
            if not isinstance(value[field], str) or not IMAGE_ID.fullmatch(value[field]):
                raise ProtocolError("Invalid image identity")
        if (not isinstance(value["version"], str) or not VERSION.fullmatch(value["version"])
                or not isinstance(value["revision"], str) or not REVISION.fullmatch(value["revision"])
                or value["architecture"] not in ("amd64", "arm64")):
            raise ProtocolError("Invalid image metadata")
        return cls(**value)

    def as_dict(self):
        return {field: getattr(self, field) for field in self.__dataclass_fields__}

    @property
    def reference(self):
        return "brspoon/keep@" + self.index_digest


@dataclass(frozen=True)
class Enrollment:
    install_id: str
    owner_id: str
    epoch: int
    key: bytes

    @classmethod
    def create(cls, owner_id):
        if not isinstance(owner_id, str) or not OWNER.fullmatch(owner_id):
            raise ProtocolError("Invalid enrolled owner")
        return cls(str(uuid.uuid4()), owner_id, 1, secrets.token_bytes(32))

    def __post_init__(self):
        canonical_uuid(self.install_id)
        if (not isinstance(self.owner_id, str) or not OWNER.fullmatch(self.owner_id)
                or type(self.epoch) is not int or not 1 <= self.epoch <= 2**31 - 1
                or not isinstance(self.key, bytes) or len(self.key) != 32):
            raise ProtocolError("Invalid enrollment")


def signed(enrollment: Enrollment, payload):
    encoded = canonical(payload)
    result = canonical({"payload": payload,
                        "mac": hmac.new(enrollment.key, encoded, hashlib.sha256).hexdigest()})
    if len(result) > MAX_ENVELOPE:
        raise ProtocolError("Message size is invalid")
    return result


def verify(enrollment: Enrollment, data: bytes):
    envelope = parse_json(data)
    exact_fields(envelope, ("payload", "mac"))
    signature = envelope["mac"]
    if not isinstance(signature, str) or not HASH.fullmatch(signature):
        raise ProtocolError("Invalid message authentication")
    expected = hmac.new(enrollment.key, canonical(envelope["payload"]), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ProtocolError("Invalid message authentication")
    return envelope["payload"]


@dataclass(frozen=True)
class Request:
    request_id: str
    operation: str
    credential_version: int
    issued_at: int
    expires_at: int
    nonce: str
    expected: ImageIdentity
    target: ImageIdentity | None
    payload_sha256: str


def verify_request(enrollment: Enrollment, data: bytes, *, now=None):
    value = verify(enrollment, data)
    exact_fields(value, ("protocol", "install_id", "owner_id", "epoch", "request_id",
                         "operation", "credential_version", "issued_at", "expires_at",
                         "nonce", "expected", "target"))
    if (value["protocol"] != "keep.maintenance.v1" or value["install_id"] != enrollment.install_id
            or value["owner_id"] != enrollment.owner_id or type(value["epoch"]) is not int
            or value["epoch"] != enrollment.epoch):
        raise ProtocolError("Enrollment does not match")
    canonical_uuid(value["request_id"])
    if value["operation"] not in ("install", "restart"):
        raise ProtocolError("Operation is not allowed")
    for field in ("credential_version", "issued_at", "expires_at"):
        if type(value[field]) is not int or not 0 <= value[field] < 2**53:
            raise ProtocolError("Invalid request time or credential version")
    now = time.time() if now is None else now
    if (value["issued_at"] > now + MAX_SKEW or value["expires_at"] <= now
            or not 1 <= value["expires_at"] - value["issued_at"] <= MAX_LIFETIME):
        raise ProtocolError("Request has expired or is not yet valid")
    nonce = value["nonce"]
    if not isinstance(nonce, str) or not HASH.fullmatch(nonce):
        raise ProtocolError("Invalid request nonce")
    expected = ImageIdentity.from_dict(value["expected"])
    target = None if value["target"] is None else ImageIdentity.from_dict(value["target"])
    if (value["operation"] == "install" and (target is None or target == expected)
            or value["operation"] == "restart" and target is not None):
        raise ProtocolError("Target does not match operation")
    if target is not None and target.architecture != expected.architecture:
        raise ProtocolError("Target architecture does not match the installation")
    return Request(value["request_id"], value["operation"], value["credential_version"],
                   value["issued_at"], value["expires_at"], nonce, expected, target,
                   hashlib.sha256(canonical(value)).hexdigest())


def public_status(enrollment, request, *, sequence, phase, result_code=None):
    """Deliberately excludes host paths, stdout/stderr, config, tokens and key."""
    if phase not in PHASES or type(sequence) is not int or not 0 <= sequence <= 128:
        raise ProtocolError("Invalid operation progress")
    if result_code not in (None, "complete", "unavailable", "authority-changed", "recovered", "manual-review"):
        raise ProtocolError("Invalid operation result")
    return signed(enrollment, {"protocol": "keep.maintenance.status.v1",
        "install_id": enrollment.install_id, "request_id": request.request_id,
        "sequence": sequence, "phase": phase, "result_code": result_code})
