"""Backend-agnostic behavioral contract for the Storage protocol.

Each backend's test file imports this module with `import *` and supplies
its own `storage` fixture. No fixtures are defined here.
"""
import asyncio

import pytest

from authz import (
    CardinalityViolationError,
    Client,
    Direct,
    Namespace,
    PythonCallableEvaluator,
    TupleToUserset,
    WouldCreateCycle,
)
from authz import Union as UnionRule
from authz.tuples import Condition, RelationTuple


async def test_write_then_read_round_trips(storage):
    await storage.write_tuples(
        [RelationTuple("document", "doc42", "owner", "user:alice")]
    )
    rows = await storage.read_tuples("document", object_id="doc42", relation="owner")
    assert rows == [RelationTuple("document", "doc42", "owner", "user:alice")]


async def test_read_filters_by_namespace_object_relation_subject(storage):
    await storage.write_tuples(
        [
            RelationTuple("document", "doc42", "owner", "user:alice"),
            RelationTuple("document", "doc42", "editor", "user:bob"),
            RelationTuple("document", "doc7", "owner", "user:carol"),
        ]
    )
    rows = await storage.read_tuples("document", object_id="doc42")
    assert {r.relation for r in rows} == {"owner", "editor"}

    rows = await storage.read_tuples("document", subject="user:bob")
    assert len(rows) == 1
    assert rows[0].object_id == "doc42"


async def test_write_preserves_condition(storage):
    cond = Condition("business_hours", {"tz": "UTC"})
    await storage.write_tuples(
        [RelationTuple("document", "doc42", "owner", "user:alice", condition=cond)]
    )
    rows = await storage.read_tuples("document", object_id="doc42", relation="owner")
    assert rows[0].condition == cond


async def test_delete_removes_tuple(storage):
    t = RelationTuple("document", "doc42", "owner", "user:alice")
    await storage.write_tuples([t])
    await storage.delete_tuples([t])
    rows = await storage.read_tuples("document", object_id="doc42", relation="owner")
    assert rows == []


async def test_current_token_increases_after_write(storage):
    before = await storage.current_token()
    await storage.write_tuples(
        [RelationTuple("document", "doc42", "owner", "user:alice")]
    )
    after = await storage.current_token()
    assert int(after) > int(before)


async def test_current_token_survives_delete_emptying_the_table(storage):
    t = RelationTuple("document", "doc42", "owner", "user:alice")
    write_token = await storage.write_tuples([t])
    await storage.delete_tuples([t])
    token_after_delete = await storage.current_token()
    assert int(token_after_delete) >= int(write_token)


async def test_write_tuples_returns_token(storage):
    token = await storage.write_tuples(
        [RelationTuple("document", "doc42", "owner", "user:alice")]
    )
    current = await storage.current_token()
    assert token == current


async def test_wait_for_token_returns_for_current_or_past_token(storage):
    token = await storage.write_tuples(
        [RelationTuple("document", "doc42", "owner", "user:alice")]
    )
    await storage.wait_for_token(token)  # must not raise


async def test_transaction_commits_on_success(storage):
    async with storage.transaction():
        await storage.write_tuples(
            [RelationTuple("document", "doc42", "owner", "user:alice")]
        )
    rows = await storage.read_tuples("document", object_id="doc42", relation="owner")
    assert len(rows) == 1


async def test_transaction_rolls_back_on_error(storage):
    with pytest.raises(RuntimeError):
        async with storage.transaction():
            await storage.write_tuples(
                [RelationTuple("document", "doc42", "owner", "user:alice")]
            )
            raise RuntimeError("boom")
    rows = await storage.read_tuples("document", object_id="doc42", relation="owner")
    assert rows == []


async def test_delete_advances_token_past_every_earlier_token(storage):
    t = RelationTuple("document", "doc42", "owner", "user:alice")
    write_token = await storage.write_tuples([t])
    delete_token = await storage.delete_tuples([t])
    assert int(delete_token) > int(write_token)
    assert await storage.current_token() == delete_token


async def test_delete_that_removes_nothing_does_not_advance_token(storage):
    t = RelationTuple("document", "doc42", "owner", "user:alice")
    token = await storage.write_tuples([t])
    missing = RelationTuple("document", "doc42", "owner", "user:nobody")
    assert await storage.delete_tuples([missing]) == token


async def test_write_after_delete_gets_a_newer_token_than_the_delete(storage):
    t = RelationTuple("document", "doc42", "owner", "user:alice")
    await storage.write_tuples([t])
    delete_token = await storage.delete_tuples([t])
    write_token = await storage.write_tuples([t])
    assert int(write_token) > int(delete_token)


@pytest.mark.parametrize("token", ["abc", "", "1.5", None])
async def test_wait_for_token_rejects_non_integer_token(storage, token):
    with pytest.raises(ValueError, match="token"):
        await storage.wait_for_token(token)


async def test_wait_for_token_raises_when_storage_is_behind(storage):
    with pytest.raises(RuntimeError):
        await storage.wait_for_token("999999")


async def test_nested_transaction_joins_outer_transaction(storage):
    with pytest.raises(RuntimeError):
        async with storage.transaction():
            async with storage.transaction():
                await storage.write_tuples(
                    [RelationTuple("document", "doc42", "owner", "user:alice")]
                )
            raise RuntimeError("boom")
    assert await storage.read_tuples("document", object_id="doc42") == []


async def test_rolled_back_transaction_does_not_discard_a_concurrent_write(storage):
    inside = asyncio.Event()
    doomed = RelationTuple("document", "doc42", "owner", "user:alice")
    survivor = RelationTuple("document", "doc43", "owner", "user:bob")

    async def failing_transaction():
        with pytest.raises(RuntimeError):
            async with storage.transaction():
                await storage.write_tuples([doomed])
                inside.set()
                await asyncio.sleep(0.1)
                raise RuntimeError("boom")

    async def concurrent_write():
        await inside.wait()
        await storage.write_tuples([survivor])

    await asyncio.gather(failing_transaction(), concurrent_write())
    assert await storage.read_tuples("document", object_id="doc42") == []
    assert await storage.read_tuples("document", object_id="doc43") == [survivor]


async def test_other_tasks_do_not_read_uncommitted_writes(storage):
    inside = asyncio.Event()
    seen = []

    async def writer():
        with pytest.raises(RuntimeError):
            async with storage.transaction():
                await storage.write_tuples(
                    [RelationTuple("document", "doc42", "owner", "user:alice")]
                )
                inside.set()
                await asyncio.sleep(0.1)
                raise RuntimeError("boom")

    async def reader():
        await inside.wait()
        seen.append(await storage.read_tuples("document", object_id="doc42"))

    await asyncio.gather(writer(), reader())
    assert seen == [[]]


async def test_concurrent_singleton_writes_cannot_exceed_limit(storage):
    client = Client(storage, PythonCallableEvaluator())
    client.register_schema(
        Namespace("org", {"admin": Direct()}, singleton_relations={"admin"})
    )
    results = await asyncio.gather(
        *(
            client.write([RelationTuple("org", "acme", "admin", f"user:u{i}")])
            for i in range(8)
        ),
        return_exceptions=True,
    )
    failures = [r for r in results if isinstance(r, Exception)]
    assert len(failures) == 7
    assert all(isinstance(f, CardinalityViolationError) for f in failures)
    assert len(await client.read("org", object_id="acme", relation="admin")) == 1


async def test_concurrent_edge_writes_cannot_form_a_cycle(storage, monkeypatch):
    read_tuples = storage.read_tuples

    async def slow_read_tuples(*args, **kwargs):
        await asyncio.sleep(0.05)  # widen the window between guard and insert
        return await read_tuples(*args, **kwargs)

    monkeypatch.setattr(storage, "read_tuples", slow_read_tuples)
    client = Client(storage, PythonCallableEvaluator())
    client.register_schema(
        Namespace(
            "folder",
            {
                "parent": Direct(),
                "viewer": UnionRule(Direct(), TupleToUserset("parent", "viewer")),
            },
        )
    )
    results = await asyncio.gather(
        client.write([RelationTuple("folder", "A", "parent", "folder:B")]),
        client.write([RelationTuple("folder", "B", "parent", "folder:A")]),
        return_exceptions=True,
    )
    failures = [r for r in results if isinstance(r, Exception)]
    assert len(failures) == 1
    assert isinstance(failures[0], WouldCreateCycle)
    assert len(await storage.read_tuples("folder", relation="parent")) == 1
