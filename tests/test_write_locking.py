import pytest

from authz import (
    CardinalityViolationError,
    Client,
    Direct,
    Namespace,
    PythonCallableEvaluator,
    RelationTuple,
    SqliteStorage,
    TupleToUserset,
)
from authz import Union as UnionRule


class RecordingStorage(SqliteStorage):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.locks: list[tuple[str, bool]] = []

    async def lock(self, key: str) -> None:
        self.locks.append((key, self._owns_tx.get()))
        await super().lock(key)


class StorageWithoutLock(SqliteStorage):
    lock = None


SCHEMA = (
    Namespace("org", {"admin": Direct(), "member": Direct()}, max_subjects={"admin": 1, "member": 3}),
    Namespace(
        "folder",
        {
            "parent": Direct(),
            "viewer": UnionRule(Direct(), TupleToUserset("parent", "viewer")),
        },
    ),
)


@pytest.fixture
async def recording():
    s = RecordingStorage(":memory:")
    await s.connect()
    c = Client(s, PythonCallableEvaluator())
    c.register_schema(*SCHEMA)
    yield s, c
    await s.close()


async def test_lock_is_taken_once_per_limited_relation_in_sorted_order(recording):
    storage, client = recording
    await client.write(
        [
            RelationTuple("org", "b", "member", "user:1"),
            RelationTuple("org", "a", "member", "user:1"),
            RelationTuple("org", "b", "member", "user:2"),
            RelationTuple("org", "a", "admin", "user:1"),
        ]
    )
    assert [k for k, _ in storage.locks] == [
        "authz:cardinality:org:a#admin",
        "authz:cardinality:org:a#member",
        "authz:cardinality:org:b#member",
    ]


async def test_lock_is_always_called_inside_the_transaction(recording):
    storage, client = recording
    await client.write(
        [
            RelationTuple("org", "a", "admin", "user:1"),
            RelationTuple("folder", "x", "parent", "folder:y"),
        ]
    )
    assert storage.locks and all(inside for _, inside in storage.locks)


async def test_graph_lock_follows_cardinality_locks_when_an_edge_is_written(recording):
    storage, client = recording
    await client.write(
        [
            RelationTuple("folder", "x", "parent", "folder:y"),
            RelationTuple("org", "a", "admin", "user:1"),
        ]
    )
    assert [k for k, _ in storage.locks] == ["authz:cardinality:org:a#admin", "authz:graph"]


@pytest.mark.parametrize(
    "t",
    [
        RelationTuple("org", "a", "admin", "group:g#member"),
        RelationTuple("folder", "x", "parent", "folder:y"),
    ],
)
async def test_graph_lock_is_taken_for_userset_and_tupleset_edges(recording, t):
    storage, client = recording
    client.register_schema(Namespace("group", {"member": Direct()}))
    await client.write([t])
    assert "authz:graph" in [k for k, _ in storage.locks]


async def test_no_lock_when_no_limit_and_no_edge(recording):
    storage, client = recording
    await client.write(
        [
            RelationTuple("folder", "x", "viewer", "user:1"),
            RelationTuple("folder", "x", "viewer", "user:2"),
        ]
    )
    assert storage.locks == []


async def test_graph_lock_is_taken_once_for_a_batch_of_edges(recording):
    storage, client = recording
    await client.write(
        [
            RelationTuple("folder", "x", "parent", "folder:y"),
            RelationTuple("folder", "y", "parent", "folder:z"),
        ]
    )
    assert [k for k, _ in storage.locks] == ["authz:graph"]


async def test_storage_without_lock_still_enforces_cardinality():
    storage = StorageWithoutLock(":memory:")
    await storage.connect()
    client = Client(storage, PythonCallableEvaluator())
    client.register_schema(*SCHEMA)
    await client.write([RelationTuple("org", "a", "admin", "user:1")])
    with pytest.raises(CardinalityViolationError):
        await client.write([RelationTuple("org", "a", "admin", "user:2")])
    await storage.close()

