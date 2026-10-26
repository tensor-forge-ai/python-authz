import asyncio
import sqlite3

import pytest

from authz import (
    CardinalityViolationError,
    Client,
    Direct,
    Namespace,
    PythonCallableEvaluator,
)
from authz.storage.sqlite import SqliteStorage
from authz.tuples import RelationTuple
from tests.storage_conformance import *  # noqa: F401,F403


@pytest.fixture
async def storage():
    s = SqliteStorage(":memory:")
    await s.connect()
    yield s
    await s.close()


async def test_context_manager_connects_and_closes():
    async with SqliteStorage(":memory:") as s:
        rows = await s.read_tuples("document", object_id="doc42")
        assert rows == []


async def test_lock_is_a_noop(storage):
    async with storage.transaction():
        await storage.lock("anything")


async def test_transaction_holds_the_database_write_lock(tmp_path):
    path = str(tmp_path / "authz.db")
    async with SqliteStorage(path) as first, SqliteStorage(path) as second:
        async with first.transaction():
            await first.write_tuples([RelationTuple("document", "doc42", "owner", "user:alice")])
            assert first._conn.in_transaction
            # BEGIN IMMEDIATE: a second connection cannot start writing meanwhile.
            await second._conn.execute("PRAGMA busy_timeout = 0")
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                async with second.transaction():
                    pass
        assert not first._conn.in_transaction


async def test_concurrent_singleton_writes_across_connections_cannot_exceed_limit(tmp_path):
    path = str(tmp_path / "authz.db")
    async with SqliteStorage(path) as first, SqliteStorage(path) as second:
        clients = [
            Client(s, PythonCallableEvaluator()) for s in (first, second)
        ]
        for c in clients:
            c.register_schema(
                Namespace("org", {"admin": Direct()}, singleton_relations={"admin"})
            )
        results = await asyncio.gather(
            *(
                clients[i % 2].write([RelationTuple("org", "acme", "admin", f"user:u{i}")])
                for i in range(6)
            ),
            return_exceptions=True,
        )
        failures = [r for r in results if isinstance(r, Exception)]
        assert len(failures) == 5
        assert all(isinstance(f, CardinalityViolationError) for f in failures)
        assert len(await first.read_tuples("org", object_id="acme")) == 1


@pytest.mark.parametrize("table", ["bad name", "t;drop table x", "1abc", "a.b", "x" * 64, ""])
def test_invalid_table_names_are_rejected(table):
    with pytest.raises(ValueError):
        SqliteStorage(":memory:", table=table)


async def test_custom_table_name_is_used_for_all_sql():
    t = RelationTuple("document", "doc42", "owner", "user:alice")
    async with SqliteStorage(":memory:", table="authz_custom") as s:
        before = await s.current_token()
        await s.write_tuples([t])
        assert await s.read_tuples("document") == [t]
        assert int(await s.current_token()) > int(before)
        delete_token = await s.delete_tuples([t])
        assert int(delete_token) > int(before) + 1
        async with s._conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'index') "
            "AND name LIKE '%tuples%'"
        ) as cursor:
            assert await cursor.fetchall() == []
        async with s._conn.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'idx_authz_custom%' ORDER BY name"
        ) as cursor:
            assert [r[0] for r in await cursor.fetchall()] == [
                "idx_authz_custom_forward",
                "idx_authz_custom_reverse",
            ]


async def test_create_schema_false_leaves_the_database_untouched(tmp_path):
    path = str(tmp_path / "authz.db")
    async with SqliteStorage(path, create_schema=False) as s:
        async with s._conn.execute("SELECT count(*) FROM sqlite_master") as cursor:
            assert (await cursor.fetchone())[0] == 0
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            await s.read_tuples("document")


async def test_create_schema_false_works_with_precreated_table(tmp_path):
    path = str(tmp_path / "authz.db")
    async with SqliteStorage(path, table="authz_pre"):
        pass
    t = RelationTuple("document", "doc42", "owner", "user:alice")
    async with SqliteStorage(path, table="authz_pre", create_schema=False) as s:
        await s.write_tuples([t])
        assert await s.read_tuples("document") == [t]
