from decimal import Decimal

import pytest

from authz import (
    Client,
    Condition,
    Direct,
    Exclusion,
    From,
    Intersection,
    Namespace,
    PythonCallableEvaluator,
    RelationTuple,
    SqliteStorage,
    TupleToUserset,
    builtin_conditions,
)
from authz import Union as UnionRule

BUILTINS = builtin_conditions()


def call(name, **ctx):
    return BUILTINS[name](subject="user:alice", resource="document:1", **ctx)


@pytest.mark.parametrize("name", ["max_amount", "min_amount"])
@pytest.mark.parametrize(
    "ctx",
    [
        {},
        {"amount": 5},
        {"max_amount": 10, "min_amount": 1},
        {"amount": None, "max_amount": 10, "min_amount": 1},
        {"amount": "abc", "max_amount": 10, "min_amount": 1},
        {"amount": True, "max_amount": 10, "min_amount": 1},
        {"amount": float("nan"), "max_amount": 10, "min_amount": 1},
        {"amount": float("inf"), "max_amount": 10, "min_amount": 1},
        {"amount": "-inf", "max_amount": 10, "min_amount": 1},
        {"amount": [5], "max_amount": 10, "min_amount": 1},
        {"amount": 5, "max_amount": True, "min_amount": True},
        {"amount": 5, "max_amount": float("nan"), "min_amount": float("nan")},
        {"amount": 5, "max_amount": "x", "min_amount": "x"},
        {"amount": 10**400, "max_amount": 10, "min_amount": 1},
    ],
)
def test_amount_conditions_are_indeterminate_on_missing_or_invalid_input(name, ctx):
    assert call(name, **ctx) is None


def test_amount_conditions_decide_when_inputs_are_valid():
    assert call("max_amount", amount=5, max_amount=10) is True
    assert call("max_amount", amount=10, max_amount=10) is True
    assert call("max_amount", amount="11", max_amount=10) is False
    assert call("max_amount", amount=Decimal("9.5"), max_amount=10) is True
    assert call("min_amount", amount=5, min_amount=5) is True
    assert call("min_amount", amount=4, min_amount=5) is False
    assert call("max_amount", amount=0, max_amount=0) is True


@pytest.mark.parametrize(
    "ctx",
    [
        {},
        {"attribute": "tier"},
        {"attribute": "tier", "tier": "gold"},
        {"attribute": "tier", "expected": "gold"},
        {"tier": "gold", "expected": "gold"},
        {"attribute": "", "expected": "gold", "": "gold"},
        {"attribute": 5, "expected": "gold"},
        {"attribute": "tier", "tier": None, "expected": None},
        {"attribute": "tier", "tier": "gold", "expected": None},
    ],
)
def test_equals_attr_is_indeterminate_when_anything_is_absent(ctx):
    assert call("equals_attr", **ctx) is None


def test_equals_attr_decides_when_present():
    assert call("equals_attr", attribute="tier", tier="gold", expected="gold") is True
    assert call("equals_attr", attribute="tier", tier="tin", expected="gold") is False
    assert call("equals_attr", attribute="flag", flag=False, expected=False) is True


@pytest.mark.parametrize(
    "allowed",
    ["admin", b"admin", None, 5, {"admin": 1}, iter(["admin"]), (x for x in ["admin"])],
)
def test_in_set_requires_a_real_collection(allowed):
    assert call("in_set", attribute="role", role="admin", allowed_values=allowed) is None


def test_in_set_rejects_substring_membership():
    assert call("in_set", attribute="role", role="adm", allowed_values="admin") is None
    assert call("in_set", attribute="role", role="adm", allowed_values=["admin"]) is False


@pytest.mark.parametrize("allowed", [["a", "b"], ("a", "b"), {"a", "b"}, frozenset("ab")])
def test_in_set_accepts_list_tuple_set_frozenset(allowed):
    assert call("in_set", attribute="k", k="a", allowed_values=allowed) is True
    assert call("in_set", attribute="k", k="z", allowed_values=allowed) is False


@pytest.mark.parametrize(
    "ctx",
    [
        {"attribute": "k", "allowed_values": ["a"]},
        {"allowed_values": ["a"]},
        {"attribute": "k", "k": None, "allowed_values": ["a"]},
        {"attribute": "k", "k": ["unhashable"], "allowed_values": {"a"}},
    ],
)
def test_in_set_is_indeterminate_without_attribute_value(ctx):
    assert call("in_set", **ctx) is None


@pytest.mark.parametrize(
    "ctx",
    [
        {},
        {"jurisdiction": "US"},
        {"allowed_jurisdictions": ["US"]},
        {"required_jurisdiction": "US"},
        {"jurisdiction": None, "required_jurisdiction": "US"},
        {"jurisdiction": "US", "allowed_jurisdictions": "US"},
    ],
)
def test_jurisdiction_match_is_indeterminate_without_required_inputs(ctx):
    assert call("jurisdiction_match", **ctx) is None


def test_jurisdiction_match_requires_every_given_constraint():
    assert call("jurisdiction_match", jurisdiction="US", allowed_jurisdictions=["US"]) is True
    assert call("jurisdiction_match", jurisdiction="US", required_jurisdiction="US") is True
    assert call(
        "jurisdiction_match", jurisdiction="US",
        allowed_jurisdictions=["US", "CA"], required_jurisdiction="CA",
    ) is False
    assert call(
        "jurisdiction_match", jurisdiction="US",
        allowed_jurisdictions="US", required_jurisdiction="CA",
    ) is False


@pytest.mark.parametrize("excluded", [None, "", 5])
def test_not_same_subject_is_indeterminate_without_excluded_subject(excluded):
    assert call("not_same_subject", excluded_subject=excluded) is None
    assert call("not_same_subject") is None


def test_not_same_subject_decides_when_given():
    assert call("not_same_subject", excluded_subject="user:alice") is False
    assert call("not_same_subject", excluded_subject="user:bob") is True


@pytest.fixture
async def make_client():
    storages = []

    async def make(**kwargs):
        storage = SqliteStorage(":memory:")
        await storage.connect()
        storages.append(storage)
        evaluator = PythonCallableEvaluator.with_builtins()
        client = Client(storage, evaluator, **kwargs)
        evaluator.register("unknown", lambda **_: None)
        evaluator.register("yes", lambda **_: True)
        evaluator.register("no", lambda **_: False)
        return client

    yield make
    for s in storages:
        await s.close()


def cond(name):
    return Condition(name)


async def test_missing_context_does_not_grant_access(make_client):
    client = await make_client()
    client.register_schema(Namespace("claim", {"approve": Direct()}))
    await client.write(
        [
            RelationTuple(
                "claim", "1", "approve", "user:alice",
                condition=Condition("max_amount", {"max_amount": 100}),
            )
        ]
    )
    assert await client.check("user:alice", "approve", "claim:1") is False
    assert await client.check("user:alice", "approve", "claim:1", context={"amount": 50}) is True
    decision = await client.explain("user:alice", "approve", "claim:1")
    assert decision.allowed is False
    assert decision.indeterminate is True
    assert decision.condition_results == (("max_amount", None),)
    assert decision.reason == (
        "Denied: indeterminate, missing or invalid condition context "
        "for user:alice on claim:1#approve"
    )


async def test_definite_denial_is_not_indeterminate(make_client):
    client = await make_client()
    client.register_schema(Namespace("claim", {"approve": Direct()}))
    await client.write(
        [RelationTuple("claim", "1", "approve", "user:alice", condition=cond("no"))]
    )
    decision = await client.explain("user:alice", "approve", "claim:1")
    assert (decision.allowed, decision.indeterminate) == (False, False)
    assert decision.reason.startswith("Denied: no matching relation")


async def test_allowed_decision_is_not_indeterminate(make_client):
    client = await make_client()
    client.register_schema(Namespace("claim", {"approve": Direct()}))
    await client.write([RelationTuple("claim", "1", "approve", "user:alice")])
    decision = await client.explain("user:alice", "approve", "claim:1")
    assert (decision.allowed, decision.indeterminate) == (True, False)


async def test_failed_subtract_condition_must_not_grant_under_exclusion(make_client):
    client = await make_client()
    client.register_schema(
        Namespace(
            "document",
            {
                "banned": Direct(),
                "viewer": Exclusion(Direct(), From("banned")),
            },
        )
    )
    await client.write(
        [
            RelationTuple("document", "1", "viewer", "user:alice"),
            RelationTuple(
                "document", "1", "banned", "user:alice",
                condition=Condition("max_amount", {"max_amount": 100}),
            ),
        ]
    )
    # The ban's condition cannot be evaluated without an amount: no access.
    assert await client.check("user:alice", "viewer", "document:1") is False
    decision = await client.explain("user:alice", "viewer", "document:1")
    assert decision.indeterminate is True
    # Ban definitely does not apply -> access.
    assert await client.check("user:alice", "viewer", "document:1", context={"amount": 500}) is True
    # Ban definitely applies -> no access.
    assert await client.check("user:alice", "viewer", "document:1", context={"amount": 5}) is False


async def test_exclusion_with_definitely_false_base_is_definite_even_if_subtract_unknown(make_client):
    client = await make_client()
    client.register_schema(
        Namespace(
            "document",
            {"banned": Direct(), "viewer": Exclusion(Direct(), From("banned"))},
        )
    )
    await client.write(
        [RelationTuple("document", "1", "banned", "user:alice", condition=cond("unknown"))]
    )
    decision = await client.explain("user:alice", "viewer", "document:1")
    assert (decision.allowed, decision.indeterminate) == (False, False)


async def test_exclusion_with_unknown_base_and_true_subtract_is_definite(make_client):
    client = await make_client()
    client.register_schema(
        Namespace(
            "document",
            {"banned": Direct(), "viewer": Exclusion(Direct(), From("banned"))},
        )
    )
    await client.write(
        [
            RelationTuple("document", "1", "viewer", "user:alice", condition=cond("unknown")),
            RelationTuple("document", "1", "banned", "user:alice"),
        ]
    )
    decision = await client.explain("user:alice", "viewer", "document:1")
    assert (decision.allowed, decision.indeterminate) == (False, False)


async def test_exclusion_with_unknown_base_and_false_subtract_is_indeterminate(make_client):
    client = await make_client()
    client.register_schema(
        Namespace(
            "document",
            {"banned": Direct(), "viewer": Exclusion(Direct(), From("banned"))},
        )
    )
    await client.write(
        [RelationTuple("document", "1", "viewer", "user:alice", condition=cond("unknown"))]
    )
    decision = await client.explain("user:alice", "viewer", "document:1")
    assert (decision.allowed, decision.indeterminate) == (False, True)


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        ("yes", "unknown", True),
        ("unknown", "yes", True),
        ("no", "unknown", None),
        ("unknown", "no", None),
        ("no", "no", False),
        ("unknown", "unknown", None),
    ],
)
async def test_union_is_kleene_or(make_client, first, second, expected):
    client = await make_client()
    client.register_schema(
        Namespace(
            "document",
            {
                "a": Direct(),
                "b": Direct(),
                "either": UnionRule(From("a"), From("b")),
            },
        )
    )
    await client.write(
        [
            RelationTuple("document", "1", "a", "user:alice", condition=cond(first)),
            RelationTuple("document", "1", "b", "user:alice", condition=cond(second)),
        ]
    )
    decision = await client.explain("user:alice", "either", "document:1")
    assert decision.allowed is (expected is True)
    assert decision.indeterminate is (expected is None)


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        ("yes", "yes", True),
        ("yes", "unknown", None),
        ("unknown", "yes", None),
        ("no", "unknown", False),
        ("unknown", "no", False),
        ("no", "yes", False),
        ("unknown", "unknown", None),
    ],
)
async def test_intersection_is_kleene_and(make_client, first, second, expected):
    client = await make_client()
    client.register_schema(
        Namespace(
            "document",
            {
                "a": Direct(),
                "b": Direct(),
                "both": Intersection(From("a"), From("b")),
            },
        )
    )
    await client.write(
        [
            RelationTuple("document", "1", "a", "user:alice", condition=cond(first)),
            RelationTuple("document", "1", "b", "user:alice", condition=cond(second)),
        ]
    )
    decision = await client.explain("user:alice", "both", "document:1")
    assert decision.allowed is (expected is True)
    assert decision.indeterminate is (expected is None)
    assert (decision.matched_tuples != ()) is (expected is True)


async def test_unknown_tuple_does_not_hide_a_later_true_tuple(make_client):
    client = await make_client()
    client.register_schema(Namespace("document", {"viewer": Direct()}))
    group = Namespace("group", {"member": Direct()})
    client.register_schema(group)
    await client.write(
        [
            RelationTuple("document", "1", "viewer", "user:alice", condition=cond("unknown")),
            RelationTuple("document", "1", "viewer", "group:g#member"),
            RelationTuple("group", "g", "member", "user:alice"),
        ]
    )
    decision = await client.explain("user:alice", "viewer", "document:1")
    assert decision.allowed is True
    assert decision.indeterminate is False
    assert decision.condition_results == (("unknown", None),)
    assert decision.matched_tuples == (
        RelationTuple("group", "g", "member", "user:alice"),
        RelationTuple("document", "1", "viewer", "group:g#member"),
    )


async def test_unknown_userset_tuple_condition_is_indeterminate(make_client):
    client = await make_client()
    client.register_schema(
        Namespace("group", {"member": Direct()}), Namespace("document", {"viewer": Direct()})
    )
    await client.write(
        [
            RelationTuple("group", "g", "member", "user:alice"),
            RelationTuple("document", "1", "viewer", "group:g#member", condition=cond("unknown")),
        ]
    )
    decision = await client.explain("user:alice", "viewer", "document:1")
    assert (decision.allowed, decision.indeterminate) == (False, True)


async def test_unknown_inside_tuple_to_userset_parent_is_indeterminate(make_client):
    client = await make_client()
    client.register_schema(
        Namespace("folder", {"viewer": Direct()}),
        Namespace(
            "document",
            {"parent": Direct(), "viewer": UnionRule(Direct(), TupleToUserset("parent", "viewer"))},
        ),
    )
    await client.write(
        [
            RelationTuple("folder", "f", "viewer", "user:alice", condition=cond("unknown")),
            RelationTuple("document", "1", "parent", "folder:f"),
        ]
    )
    decision = await client.explain("user:alice", "viewer", "document:1")
    assert (decision.allowed, decision.indeterminate) == (False, True)


async def test_condition_on_a_tupleset_tuple_is_honoured(make_client):
    client = await make_client()
    client.register_schema(
        Namespace("folder", {"viewer": Direct()}),
        Namespace(
            "document",
            {"parent": Direct(), "viewer": UnionRule(Direct(), TupleToUserset("parent", "viewer"))},
        ),
    )
    await client.write(
        [
            RelationTuple("folder", "f", "viewer", "user:alice"),
            RelationTuple("document", "1", "parent", "folder:f", condition=cond("no")),
            RelationTuple("document", "2", "parent", "folder:f", condition=cond("unknown")),
            RelationTuple("document", "3", "parent", "folder:f", condition=cond("yes")),
        ]
    )
    assert await client.check("user:alice", "viewer", "document:1") is False
    assert await client.check("user:alice", "viewer", "document:2") is False
    assert (await client.explain("user:alice", "viewer", "document:2")).indeterminate is True
    assert await client.check("user:alice", "viewer", "document:3") is True


async def test_union_short_circuits_on_true(make_client):
    client = await make_client()
    seen = []
    client.register_condition("spy", lambda **_: seen.append(1) or True)
    client.register_schema(
        Namespace(
            "document",
            {"a": Direct(), "b": Direct(), "either": UnionRule(From("a"), From("b"))},
        )
    )
    await client.write(
        [
            RelationTuple("document", "1", "a", "user:alice"),
            RelationTuple("document", "1", "b", "user:alice", condition=cond("spy")),
        ]
    )
    assert await client.check("user:alice", "either", "document:1") is True
    assert seen == []


async def test_intersection_short_circuits_on_false(make_client):
    client = await make_client()
    seen = []
    client.register_condition("spy", lambda **_: seen.append(1) or True)
    client.register_schema(
        Namespace(
            "document",
            {"a": Direct(), "b": Direct(), "both": Intersection(From("a"), From("b"))},
        )
    )
    await client.write(
        [RelationTuple("document", "1", "b", "user:alice", condition=cond("spy"))]
    )
    assert await client.check("user:alice", "both", "document:1") is False
    assert seen == []


async def test_engine_rejects_non_bool_evaluator_results(make_client):
    class Sloppy:
        def is_registered(self, name):
            return True

        async def evaluate(self, name, subject, resource, context):
            return 1

    storage = SqliteStorage(":memory:")
    await storage.connect()
    client = Client(storage, Sloppy())
    client.register_schema(Namespace("document", {"viewer": Direct()}))
    await client.write(
        [RelationTuple("document", "1", "viewer", "user:alice", condition=cond("x"))]
    )
    with pytest.raises(TypeError, match="x"):
        await client.check("user:alice", "viewer", "document:1")
    await storage.close()


async def test_check_returns_a_plain_bool(make_client):
    client = await make_client()
    client.register_schema(Namespace("document", {"viewer": Direct()}))
    await client.write(
        [RelationTuple("document", "1", "viewer", "user:alice", condition=cond("unknown"))]
    )
    assert await client.check("user:alice", "viewer", "document:1") is False


async def test_list_objects_and_permissions_exclude_indeterminate_results(make_client):
    client = await make_client()
    client.register_schema(Namespace("document", {"viewer": Direct()}))
    await client.write(
        [
            RelationTuple("document", "1", "viewer", "user:alice", condition=cond("unknown")),
            RelationTuple("document", "2", "viewer", "user:alice"),
        ]
    )
    assert await client.list_objects("user:alice", "viewer", "document") == ["2"]
    assert await client.list_permissions("user:alice", "document:1") == []
