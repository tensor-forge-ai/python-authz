import pytest

from authz import (
    Direct,
    From,
    Namespace,
    NamespaceNotFound,
    RelationNotFound,
    RelationTuple,
    TupleToUserset,
)
from authz import Union as UnionRule


@pytest.fixture
def schema(client):
    client.register_schema(
        Namespace("group", {"member": Direct()}),
        Namespace("folder", {"viewer": Direct()}),
        Namespace(
            "document",
            {
                "parent": Direct(),
                "owner": Direct(),
                "viewer": UnionRule(Direct(), TupleToUserset("parent", "viewer")),
                "editor": UnionRule(Direct(), From("owner")),
            },
        ),
    )
    return client


async def test_userset_subject_must_name_a_registered_namespace(schema):
    with pytest.raises(NamespaceNotFound):
        await schema.write([RelationTuple("document", "1", "viewer", "team:eng#member")])


async def test_userset_subject_must_name_an_existing_relation(schema):
    with pytest.raises(RelationNotFound):
        await schema.write([RelationTuple("document", "1", "viewer", "group:eng#boss")])


async def test_valid_userset_subject_is_accepted(schema):
    await schema.write([RelationTuple("document", "1", "viewer", "group:eng#member")])


async def test_plain_subject_of_unregistered_namespace_is_allowed(schema):
    await schema.write([RelationTuple("document", "1", "viewer", "user:alice")])


async def test_tupleset_relation_rejects_userset_subject(schema):
    with pytest.raises(ValueError, match="tupleset"):
        await schema.write([RelationTuple("document", "1", "parent", "folder:f#viewer")])


async def test_tupleset_subject_namespace_must_be_registered(schema):
    with pytest.raises(NamespaceNotFound):
        await schema.write([RelationTuple("document", "1", "parent", "user:alice")])


async def test_tupleset_subject_namespace_must_define_computed_relation(schema):
    with pytest.raises(RelationNotFound):
        await schema.write([RelationTuple("document", "1", "parent", "group:eng")])


async def test_valid_tupleset_subject_is_accepted(schema):
    await schema.write([RelationTuple("document", "1", "parent", "folder:f")])


async def test_every_tuple_to_userset_rule_on_the_relation_is_checked(client):
    client.register_schema(
        Namespace("folder", {"viewer": Direct()}),
        Namespace(
            "document",
            {
                "parent": Direct(),
                "viewer": TupleToUserset("parent", "viewer"),
                "editor": TupleToUserset("parent", "editor"),
            },
        ),
    )
    with pytest.raises(RelationNotFound):
        await client.write([RelationTuple("document", "1", "parent", "folder:f")])


async def test_failed_validation_writes_nothing(schema):
    with pytest.raises(NamespaceNotFound):
        await schema.write(
            [
                RelationTuple("document", "1", "viewer", "user:alice"),
                RelationTuple("document", "1", "parent", "user:alice"),
            ]
        )
    assert await schema.read("document", object_id="1") == []


async def test_poisoned_parent_tuple_cannot_break_later_checks(schema):
    with pytest.raises(NamespaceNotFound):
        await schema.write([RelationTuple("document", "1", "parent", "ghost:g")])
    assert await schema.check("user:alice", "viewer", "document:1") is False
