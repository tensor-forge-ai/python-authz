import pytest

from authz import (
    CheckItem,
    Client,
    CycleDetected,
    DepthLimitExceeded,
    Direct,
    EvaluationBudgetExceeded,
    From,
    Namespace,
    PythonCallableEvaluator,
    RelationTuple,
    TupleToUserset,
)
from authz import Union as UnionRule


def lattice(depth: int) -> list[RelationTuple]:
    # Two nodes per level, each pointing at both nodes of the next level:
    # 2**depth distinct paths, only 2 * depth distinct nodes.
    return [
        RelationTuple("g", f"n{i}_{j}", "member", f"g:n{i + 1}_{k}#member")
        for i in range(depth)
        for j in (0, 1)
        for k in (0, 1)
    ]


@pytest.fixture
def counted(storage):
    reads = []
    original = storage.read_tuples

    async def counting(*args, **kwargs):
        reads.append((args, kwargs))
        return await original(*args, **kwargs)

    storage.read_tuples = counting
    return reads


@pytest.fixture
def group_client(client):
    client.register_schema(Namespace("g", {"member": Direct()}))
    return client


async def test_diamond_lattice_check_is_linear_in_nodes(storage, group_client, counted):
    await storage.write_tuples(lattice(20) + [RelationTuple("g", "n20_1", "member", "user:alice")])
    counted.clear()
    assert await group_client.check("user:mallory", "member", "g:n0_0") is False
    assert len(counted) <= 2 * 21 + 1
    counted.clear()
    assert await group_client.check("user:alice", "member", "g:n0_0") is True


async def test_diamond_lattice_deeper_than_default_depth_still_hits_depth_limit(
    storage, group_client
):
    await storage.write_tuples(lattice(30))
    with pytest.raises(DepthLimitExceeded):
        await group_client.check("user:mallory", "member", "g:n0_0")


async def test_memoization_does_not_hide_cycles(storage, group_client):
    await storage.write_tuples(
        [
            RelationTuple("g", "root", "member", "g:shared#member"),
            RelationTuple("g", "root", "member", "g:loop_a#member"),
            RelationTuple("g", "loop_a", "member", "g:shared#member"),
            RelationTuple("g", "loop_a", "member", "g:loop_b#member"),
            RelationTuple("g", "loop_b", "member", "g:loop_a#member"),
        ]
    )
    with pytest.raises(CycleDetected):
        await group_client.check("user:mallory", "member", "g:root")


async def test_pathological_graph_exceeds_the_evaluation_budget(storage, client):
    client = Client(client._storage, client._conditions, max_evaluations=100)
    client.register_schema(Namespace("g", {"member": Direct()}))
    tuples = [
        RelationTuple("g", "root", "member", f"g:a{i}#member") for i in range(20)
    ] + [
        RelationTuple("g", f"a{i}", "member", f"g:b{i}_{j}#member")
        for i in range(20)
        for j in range(20)
    ]
    await storage.write_tuples(tuples)
    with pytest.raises(EvaluationBudgetExceeded) as exc_info:
        await client.check("user:mallory", "member", "g:root")
    assert exc_info.value.max_evaluations == 100


async def test_default_budget_bounds_unmemoized_explain_on_a_diamond(storage, group_client):
    await storage.write_tuples(lattice(20))
    with pytest.raises(EvaluationBudgetExceeded):
        await group_client.explain("user:mallory", "member", "g:n0_0")


async def test_explain_still_works_on_small_graphs_with_the_budget(storage, group_client):
    await storage.write_tuples(lattice(3) + [RelationTuple("g", "n3_0", "member", "user:alice")])
    decision = await group_client.explain("user:alice", "member", "g:n0_0")
    assert decision.allowed is True


async def test_budget_applies_per_check_not_per_batch(storage, client):
    client = Client(client._storage, client._conditions, max_evaluations=5)
    client.register_schema(Namespace("g", {"member": Direct()}))
    await storage.write_tuples(
        [RelationTuple("g", f"x{i}", "member", "user:alice") for i in range(10)]
    )
    results = await client.check_batch(
        [CheckItem("user:alice", "member", f"g:x{i}") for i in range(10)]
    )
    assert results == [True] * 10


async def test_memo_is_per_check_so_subjects_do_not_leak(storage, group_client):
    await storage.write_tuples(
        [
            RelationTuple("g", "root", "member", "g:inner#member"),
            RelationTuple("g", "inner", "member", "user:alice"),
        ]
    )
    results = await group_client.check_batch(
        [
            CheckItem("user:alice", "member", "g:root"),
            CheckItem("user:bob", "member", "g:root"),
            CheckItem("user:alice", "member", "g:root"),
        ]
    )
    assert results == [True, False, True]


async def test_check_uses_a_per_check_read_cache(storage, client, counted):
    client.register_schema(
        Namespace("folder", {"viewer": Direct()}),
        Namespace(
            "document",
            {
                "parent": Direct(),
                "viewer": UnionRule(Direct(), TupleToUserset("parent", "viewer"), From("parent")),
            },
        ),
    )
    await storage.write_tuples([RelationTuple("document", "d", "parent", "folder:f")])
    counted.clear()
    await client.check("user:alice", "viewer", "document:d")
    keys = [(a, tuple(sorted(k.items()))) for a, k in counted]
    assert len(keys) == len(set(keys))


@pytest.mark.parametrize("value", [0, -1])
def test_max_evaluations_must_be_positive(storage, value):
    with pytest.raises(ValueError):
        Client(storage, PythonCallableEvaluator(), max_evaluations=value)


def test_context_precedence_is_validated(storage):
    with pytest.raises(ValueError, match="context_precedence"):
        Client(storage, PythonCallableEvaluator(), context_precedence="both")
    for value in ("stored", "request"):
        Client(storage, PythonCallableEvaluator(), context_precedence=value)


@pytest.fixture
def folder_schema(client):
    client.register_schema(
        Namespace(
            "folder",
            {
                "parent": Direct(),
                "viewer": UnionRule(Direct(), TupleToUserset("parent", "viewer")),
            },
        )
    )
    return client


async def test_expand_raises_on_cyclic_data(storage, folder_schema):
    await storage.write_tuples(
        [
            RelationTuple("folder", "A", "parent", "folder:B"),
            RelationTuple("folder", "B", "parent", "folder:A"),
        ]
    )
    with pytest.raises(CycleDetected):
        await folder_schema.expand("viewer", "folder:A")


async def test_expand_raises_on_self_loop(storage, folder_schema):
    await storage.write_tuples([RelationTuple("folder", "A", "parent", "folder:A")])
    with pytest.raises(CycleDetected):
        await folder_schema.expand("viewer", "folder:A")


async def test_expand_respects_max_depth(storage, client):
    client = Client(client._storage, client._conditions, max_depth=3)
    client.register_schema(
        Namespace(
            "folder",
            {
                "parent": Direct(),
                "viewer": UnionRule(Direct(), TupleToUserset("parent", "viewer")),
            },
        )
    )
    await storage.write_tuples(
        [RelationTuple("folder", f"f{i}", "parent", f"folder:f{i + 1}") for i in range(6)]
    )
    with pytest.raises(DepthLimitExceeded):
        await client.expand("viewer", "folder:f0")


async def test_expand_counts_against_max_evaluations(storage, client):
    client = Client(client._storage, client._conditions, max_evaluations=10)
    client.register_schema(
        Namespace(
            "folder",
            {
                "parent": Direct(),
                "viewer": UnionRule(Direct(), TupleToUserset("parent", "viewer")),
            },
        )
    )
    await storage.write_tuples(
        [RelationTuple("folder", "root", "parent", f"folder:c{i}") for i in range(30)]
    )
    with pytest.raises(EvaluationBudgetExceeded):
        await client.expand("viewer", "folder:root")


async def test_expand_diamond_shared_child_is_not_a_cycle(storage, folder_schema):
    await storage.write_tuples(
        [
            RelationTuple("folder", "top", "parent", "folder:left"),
            RelationTuple("folder", "top", "parent", "folder:right"),
            RelationTuple("folder", "left", "parent", "folder:base"),
            RelationTuple("folder", "right", "parent", "folder:base"),
            RelationTuple("folder", "base", "viewer", "user:alice"),
        ]
    )
    tree = await folder_schema.expand("viewer", "folder:top")
    assert [c.object.object_id for c in tree.children] == ["left", "right"]
