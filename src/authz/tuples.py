import re
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any, Mapping

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]*$")


def _check_name(kind: str, value: str, raw: str) -> None:
    if not value:
        raise ValueError(f"empty {kind} in {raw!r}")
    if not _NAME.fullmatch(value):
        raise ValueError(
            f"invalid {kind} {value!r} in {raw!r}; expected letters, digits, '_' or '-', "
            "starting with a letter or '_'"
        )


def _check_object_id(value: str, raw: str) -> None:
    if not value:
        raise ValueError(f"empty object id in {raw!r}")
    if "#" in value:
        raise ValueError(f"object id must not contain '#' in {raw!r}")


def _check_chars(raw: str) -> None:
    if any(c.isspace() or c < " " or c == "\x7f" for c in raw):
        raise ValueError(f"whitespace or control characters are not allowed in {raw!r}")


@dataclass(frozen=True)
class ObjectRef:
    namespace: str
    object_id: str

    def __str__(self) -> str:
        return f"{self.namespace}:{self.object_id}"

    @classmethod
    def parse(cls, raw: str) -> "ObjectRef":
        namespace, colon, object_id = raw.partition(":")
        if not colon:
            raise ValueError(
                f"invalid object reference {raw!r}; expected 'namespace:object_id'"
            )
        _check_chars(raw)
        _check_name("namespace", namespace, raw)
        _check_object_id(object_id, raw)
        return cls(namespace, object_id)


@dataclass(frozen=True)
class SubjectRef:
    namespace: str
    object_id: str
    relation: str | None = None

    @property
    def is_userset(self) -> bool:
        return self.relation is not None

    def __str__(self) -> str:
        base = f"{self.namespace}:{self.object_id}"
        return f"{base}#{self.relation}" if self.relation else base

    @classmethod
    def parse(cls, raw: str) -> "SubjectRef":
        obj_part, sep, relation = raw.partition("#")
        namespace, colon, object_id = obj_part.partition(":")
        if not colon:
            raise ValueError(
                f"invalid subject reference {raw!r}; expected 'namespace:object_id' "
                "or 'namespace:object_id#relation'"
            )
        _check_chars(raw)
        _check_name("namespace", namespace, raw)
        _check_object_id(object_id, raw)
        if sep:
            _check_name("relation", relation, raw)
        return cls(namespace, object_id, relation if sep else None)


@dataclass(frozen=True)
class Condition:
    name: str
    context: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RelationTuple:
    namespace: str
    object_id: str
    relation: str
    subject: str
    condition: Condition | None = None

    def __post_init__(self) -> None:
        raw = f"{self.namespace}:{self.object_id}#{self.relation}"
        _check_chars(raw)
        _check_name("namespace", self.namespace, raw)
        _check_object_id(self.object_id, raw)
        _check_name("relation", self.relation, raw)
        SubjectRef.parse(self.subject)

    @property
    def object(self) -> ObjectRef:
        return ObjectRef(self.namespace, self.object_id)

    @cached_property
    def subject_ref(self) -> SubjectRef:
        return SubjectRef.parse(self.subject)

    def __str__(self) -> str:
        return (
            f"({self.namespace}, {self.object_id!r}, "
            f"{self.relation!r}, {self.subject!r})"
        )
