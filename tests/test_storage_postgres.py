import asyncio
import os
import shutil
import uuid
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest

from authz.storage.postgres import PostgresStorage
from authz.tuples import RelationTuple
from tests.storage_conformance import *  # noqa: F401,F403


def _with_database(dsn: str, database: str) -> str:
    return urlunsplit(urlsplit(dsn)._replace(path=f"/{database}"))


async def _admin(dsn: str, statement: str) -> None:
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute(statement)
    finally:
        await conn.close()


@pytest.fixture(scope="session")
def postgres_dsn():
    admin_dsn = os.environ.get("AUTHZ_TEST_POSTGRES_DSN")
    if admin_dsn:
        database = f"authz_test_{uuid.uuid4().hex[:12]}"
        asyncio.run(_admin(admin_dsn, f"CREATE DATABASE {database}"))
        try:
            yield _with_database(admin_dsn, database)
        finally:
            asyncio.run(_admin(admin_dsn, f"DROP DATABASE IF EXISTS {database} WITH (FORCE)"))
        return

    if shutil.which("docker") is None:
        pytest.skip("set AUTHZ_TEST_POSTGRES_DSN or make docker available")
    try:
        import docker
        from testcontainers.community.postgres import PostgresContainer

        docker.from_env().ping()
    except Exception:
        pytest.skip("set AUTHZ_TEST_POSTGRES_DSN or make docker available")
    with PostgresContainer("postgres:16") as pg:
        # testcontainers returns a SQLAlchemy-style URL; asyncpg has no "+driver" suffix.
        url = pg.get_connection_url(driver="asyncpg")
        yield url.replace("postgresql+asyncpg://", "postgresql://")


@pytest.fixture
async def storage(postgres_dsn):
    async with PostgresStorage(postgres_dsn) as s:
        yield s
        async with s._pool.acquire() as conn:
            await conn.execute("TRUNCATE TABLE tuples RESTART IDENTITY")


async def test_context_manager_connects_and_closes(postgres_dsn):
    async with PostgresStorage(postgres_dsn) as s:
        rows = await s.read_tuples("document", object_id="doc42")
        assert rows == []


async def test_transaction_nested_calls_share_one_connection(storage):
    seen_connections = []

    async with storage.transaction():
        conn1, must_release1 = await storage._connection()
        conn2, must_release2 = await storage._connection()
        seen_connections.extend([conn1, conn2])
        assert must_release1 is False
        assert must_release2 is False

    assert seen_connections[0] is seen_connections[1]


async def test_connection_outside_transaction_must_be_released(storage):
    conn, must_release = await storage._connection()
    assert must_release is True
    await storage._pool.release(conn)


async def test_concurrent_transactions_do_not_share_connections(storage):
    results = {}

    async def run(name):
        async with storage.transaction():
            conn, _ = await storage._connection()
            await asyncio.sleep(0.05)  # widen the window for a real race
            results[name] = conn

    await asyncio.gather(run("a"), run("b"))
    assert results["a"] is not results["b"]


async def test_lock_outside_transaction_is_rejected(storage):
    with pytest.raises(RuntimeError):
        await storage.lock("k")


async def test_lock_blocks_other_transactions_until_commit(storage):
    order = []
    holding = asyncio.Event()

    async def first():
        async with storage.transaction():
            await storage.lock("k")
            holding.set()
            await asyncio.sleep(0.15)
            order.append("first-done")

    async def second():
        await holding.wait()
        async with storage.transaction():
            await storage.lock("k")
            order.append("second-locked")

    await asyncio.gather(first(), second())
    assert order == ["first-done", "second-locked"]


async def test_lock_with_different_keys_does_not_block(storage):
    holding = asyncio.Event()
    release = asyncio.Event()

    async def first():
        async with storage.transaction():
            await storage.lock("a")
            holding.set()
            await release.wait()

    async def second():
        await holding.wait()
        async with storage.transaction():
            await asyncio.wait_for(storage.lock("b"), timeout=2)
        release.set()

    await asyncio.gather(first(), second())


@pytest.mark.parametrize("table", ["bad name", "t;drop", "1abc", "a.b.c", "x" * 64, ".t", "s."])
def test_invalid_table_names_are_rejected(table):
    with pytest.raises(ValueError):
        PostgresStorage("postgresql://unused", table=table)


@pytest.mark.parametrize("table", ["authz_custom", "authz_schema_test.rel_tuples"])
async def test_custom_table_name_is_used_for_all_sql(postgres_dsn, table):
    if "." in table:
        await _admin(postgres_dsn, f"CREATE SCHEMA IF NOT EXISTS {table.split('.')[0]}")
    t = RelationTuple("document", "doc42", "owner", "user:alice")
    async with PostgresStorage(postgres_dsn, table=table) as s:
        before = await s.current_token()
        await s.write_tuples([t])
        assert await s.read_tuples("document") == [t]
        assert int(await s.current_token()) > int(before)
        delete_token = await s.delete_tuples([t])
        assert int(delete_token) > int(before) + 1
        assert await s.read_tuples("document") == []
        async with s._pool.acquire() as conn:
            await conn.execute(f"DROP TABLE {table}")


async def test_create_schema_false_works_with_precreated_table(postgres_dsn):
    ddl_dsn = postgres_dsn
    async with PostgresStorage(ddl_dsn, table="authz_precreated") as creator:
        pass
    t = RelationTuple("document", "doc42", "owner", "user:alice")
    async with PostgresStorage(ddl_dsn, table="authz_precreated", create_schema=False) as s:
        await s.write_tuples([t])
        assert await s.read_tuples("document") == [t]
        async with s._pool.acquire() as conn:
            await conn.execute("DROP TABLE authz_precreated")


async def test_create_schema_false_does_not_run_ddl(postgres_dsn):
    with pytest.raises(asyncpg.UndefinedTableError):
        await PostgresStorage(
            postgres_dsn, table="authz_never_created", create_schema=False
        ).connect()
    async with PostgresStorage(postgres_dsn) as s:
        async with s._pool.acquire() as conn:
            exists = await conn.fetchval("SELECT to_regclass('authz_never_created')")
    assert exists is None


async def test_least_privilege_role_without_ddl_rights_can_connect(postgres_dsn):
    role = f"authz_app_{uuid.uuid4().hex[:8]}"
    table = "authz_lp_tuples"
    async with PostgresStorage(postgres_dsn, table=table):
        pass
    await _admin(postgres_dsn, f"CREATE ROLE {role} LOGIN PASSWORD 'pw'")
    try:
        await _admin(postgres_dsn, f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {role}")
        # Exactly the privileges docs/security.md (A16) documents: USAGE, not SELECT.
        await _admin(postgres_dsn, f"GRANT USAGE ON SEQUENCE {table}_change_id_seq TO {role}")
        parts = urlsplit(postgres_dsn)
        netloc = f"{role}:pw@{parts.hostname}" + (f":{parts.port}" if parts.port else "")
        dsn = urlunsplit(parts._replace(netloc=netloc))
        async with PostgresStorage(dsn, table=table, create_schema=False) as s:
            t = RelationTuple("document", "doc42", "owner", "user:alice")
            written = await s.write_tuples([t])
            assert int(written) > 0
            assert await s.read_tuples("document", object_id="doc42") == [t]
            deleted = await s.delete_tuples([t])
            assert int(deleted) > int(written)
            await s.wait_for_token(deleted)
    finally:
        await _admin(postgres_dsn, f"DROP OWNED BY {role}")
        await _admin(postgres_dsn, f"DROP ROLE {role}")
