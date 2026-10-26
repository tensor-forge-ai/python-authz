import pytest

from authz.tuples import Condition, ObjectRef, RelationTuple, SubjectRef


def test_object_ref_parse_and_str():
    ref = ObjectRef.parse("document:doc42")
    assert ref == ObjectRef("document", "doc42")
    assert str(ref) == "document:doc42"


def test_object_ref_parse_rejects_missing_colon():
    with pytest.raises(ValueError):
        ObjectRef.parse("document")


def test_subject_ref_parse_plain_object():
    ref = SubjectRef.parse("user:alice")
    assert ref == SubjectRef("user", "alice", None)
    assert ref.is_userset is False
    assert str(ref) == "user:alice"


def test_subject_ref_parse_userset():
    ref = SubjectRef.parse("group:eng#member")
    assert ref == SubjectRef("group", "eng", "member")
    assert ref.is_userset is True
    assert str(ref) == "group:eng#member"


def test_subject_ref_parse_rejects_missing_colon():
    with pytest.raises(ValueError):
        SubjectRef.parse("alice")


def test_relation_tuple_object_and_subject_ref():
    t = RelationTuple("document", "doc42", "owner", "user:alice")
    assert t.object == ObjectRef("document", "doc42")
    assert t.subject_ref == SubjectRef("user", "alice", None)
    assert t.condition is None


def test_relation_tuple_with_condition():
    cond = Condition("business_hours", {"tz": "UTC"})
    t = RelationTuple("document", "doc42", "owner", "user:alice", condition=cond)
    assert t.condition.name == "business_hours"
    assert t.condition.context == {"tz": "UTC"}


def test_relation_tuple_str_is_readable():
    t = RelationTuple("document", "doc42", "owner", "user:alice")
    text = str(t)
    assert "document" in text and "doc42" in text and "owner" in text and "alice" in text


@pytest.mark.parametrize(
    "raw",
    [
        ":alice",
        "user:",
        "user: alice",
        "user:ali ce",
        "user:alice\n",
        "user:ali\tce",
        "user:ali\x00ce",
        "user:ali\x7fce",
        "user:ali ce",
        "1user:alice",
        "us er:alice",
        "us.er:alice",
        "user:alice#",
        "user:alice#mem ber",
        "user:alice#1member",
        "user:alice#member#x",
        "#:alice",
    ],
)
def test_subject_ref_parse_rejects_bad_identifiers(raw):
    with pytest.raises(ValueError):
        SubjectRef.parse(raw)


@pytest.mark.parametrize(
    "raw",
    ["document:", ":doc42", "document:do c", "document:doc#42", "document:doc\n", "d c:doc", "document:a\x1bb"],
)
def test_object_ref_parse_rejects_bad_identifiers(raw):
    with pytest.raises(ValueError):
        ObjectRef.parse(raw)


@pytest.mark.parametrize(
    "raw", ["document:a:b:c", "document:a/b.c@d", "document:ünï", "doc-ument:x", "_d:1"]
)
def test_parse_accepts_printable_ids_and_colons_after_the_first(raw):
    assert str(ObjectRef.parse(raw)) == raw
    assert str(SubjectRef.parse(raw)) == raw


def test_object_ref_parse_keeps_partition_semantics():
    ref = ObjectRef.parse("document:a:b")
    assert ref == ObjectRef("document", "a:b")


def test_parse_error_messages_keep_their_shape():
    with pytest.raises(ValueError, match="invalid object reference 'document'; expected"):
        ObjectRef.parse("document")
    with pytest.raises(ValueError, match="invalid subject reference 'alice'; expected"):
        SubjectRef.parse("alice")


@pytest.mark.parametrize(
    "args",
    [
        ("", "doc42", "owner", "user:alice"),
        ("document", "", "owner", "user:alice"),
        ("document", "doc42", "", "user:alice"),
        ("document", "doc42", "owner", ""),
        ("document", "doc42", "owner", "alice"),
        ("document", "doc42", "owner", "user:alice#"),
        ("document", "doc 42", "owner", "user:alice"),
        ("document", "doc#42", "owner", "user:alice"),
        ("document", "doc42", "own er", "user:alice"),
        ("document", "doc42", "owner", "user:al ice"),
        ("docu:ment", "doc42", "owner", "user:alice"),
        ("document", "doc42", "owner#x", "user:alice"),
        ("document", "doc42\n", "owner", "user:alice"),
    ],
)
def test_relation_tuple_rejects_bad_fields(args):
    with pytest.raises(ValueError):
        RelationTuple(*args)


def test_relation_tuple_accepts_userset_subject_and_colon_ids():
    t = RelationTuple("document", "a:b", "viewer", "group:eng#member")
    assert t.subject_ref == SubjectRef("group", "eng", "member")
