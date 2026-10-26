import pytest

from authz import Condition, Direct, Namespace, RelationTuple


@pytest.fixture
def schema(client):
    client.register_schema(
        Namespace("group", {"member": Direct()}),
        Namespace("document", {"viewer": Direct()}),
    )
    return client


async def test_plain_tuple_subject_does_not_match_a_userset_subject(schema):
    await schema.write([RelationTuple("document", "1", "viewer", "group:eng")])
    assert await schema.check("group:eng", "viewer", "document:1") is True
    assert await schema.check("group:eng#member", "viewer", "document:1") is False


async def test_crafted_subject_relation_does_not_match_plain_tuple(schema):
    await schema.write([RelationTuple("document", "1", "viewer", "user:bob")])
    assert await schema.check("user:bob", "viewer", "document:1") is True
    assert await schema.check("user:bob#x", "viewer", "document:1") is False


async def test_userset_subject_matches_an_identical_userset_tuple(schema):
    await schema.write([RelationTuple("document", "1", "viewer", "group:eng#member")])
    assert await schema.check("group:eng#member", "viewer", "document:1") is True
    assert await schema.check("group:eng#other", "viewer", "document:1") is False
    assert await schema.check("group:ops#member", "viewer", "document:1") is False


async def test_userset_subject_matches_through_nested_usersets(schema):
    await schema.write(
        [
            RelationTuple("group", "all", "member", "group:eng#member"),
            RelationTuple("document", "1", "viewer", "group:all#member"),
        ]
    )
    assert await schema.check("group:eng#member", "viewer", "document:1") is True
    assert await schema.check("group:ops#member", "viewer", "document:1") is False


async def test_userset_subject_does_not_gain_its_members_access(schema):
    await schema.write(
        [
            RelationTuple("group", "eng", "member", "user:alice"),
            RelationTuple("document", "1", "viewer", "user:alice"),
        ]
    )
    assert await schema.check("group:eng#member", "viewer", "document:1") is False


async def test_exact_userset_match_still_honours_its_condition(schema):
    schema.register_condition("never", lambda **_: False)
    await schema.write(
        [
            RelationTuple(
                "document", "1", "viewer", "group:eng#member", condition=Condition("never")
            )
        ]
    )
    assert await schema.check("group:eng#member", "viewer", "document:1") is False


async def test_conditions_are_not_evaluated_for_tuples_that_cannot_match(schema):
    calls = []

    def recorder(*, subject, resource, **_):
        calls.append(subject)
        return True

    schema.register_condition("recorder", recorder)
    await schema.write(
        [
            RelationTuple(
                "document", "1", "viewer", "user:alice", condition=Condition("recorder")
            )
        ]
    )
    decision = await schema.explain("user:bob", "viewer", "document:1")
    assert decision.allowed is False
    assert decision.condition_results == ()
    assert calls == []

    decision = await schema.explain("user:alice", "viewer", "document:1")
    assert decision.allowed is True
    assert decision.condition_results == (("recorder", True),)
    assert calls == ["user:alice"]
