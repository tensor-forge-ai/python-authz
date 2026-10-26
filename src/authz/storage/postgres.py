import json
import re
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Sequence

import asyncpg

from authz.storage.base import Token
from authz.tuples import Condition, RelationTuple

_IDENT = r"[A-Za-z_][A-Za-z0-9_]{0,62}"
_TABLE = re.compile(rf"^(?:{_IDENT}\.)?({_IDENT})$")


def _schema_sql(table: str, bare: str) -> str:
    index = bare[:40]
    return f"""
CREATE TABLE IF NOT EXISTS {table} (
    change_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    subject TEXT NOT NULL,
    condition_name TEXT,
    condition_context JSONB,
    UNIQUE(namespace, object_id, relation, subject)
);
CREATE INDEX IF NOT EXISTS idx_{index}_forward
    ON {table}(namespace, object_id, relation);
CREATE INDEX IF NOT EXISTS idx_{index}_reverse
    ON {table}(namespace, subject);
"""


def _row_to_tuple(row) -> RelationTuple:
    condition = None
    if row["condition_name"] is not None:
        context = json.loads(row["condition_context"]) if row["condition_context"] else {}
        condition = Condition(row["condition_name"], context)
    return RelationTuple(
        row["namespace"], row["object_id"], row["relation"], row["subject"],
        condition=condition,
    )


class PostgresStorage:
    def __init__(
        self,
        dsn: str,
        *,
        min_size: int = 1,
        max_size: int = 10,
        table: str = "tuples",
        create_schema: bool = True,
    ):
        match = _TABLE.fullmatch(table)
        if match is None:
            raise ValueError(f"invalid table name {table!r}")
        self._dsn = dsn
        self._min_size = min_size
        self._max_size = max_size
        self._table = table
        self._bare_table = match.group(1)
        self._create_schema = create_schema
        self._pool: asyncpg.Pool | None = None
        self._sequence: str | None = None
        self._active_conn: ContextVar[asyncpg.Connection | None] = ContextVar(
            "authz_postgres_conn", default=None
        )
        t = table
        self._upsert_sql = (
            f"INSERT INTO {t} (namespace, object_id, relation, subject, condition_name, "
            "condition_context) VALUES ($1, $2, $3, $4, $5, $6) "
            "ON CONFLICT (namespace, object_id, relation, subject) DO UPDATE SET "
            "condition_name = excluded.condition_name, "
            "condition_context = excluded.condition_context"
        )
        self._delete_sql = (
            f"DELETE FROM {t} WHERE namespace = $1 AND object_id = $2 "
            "AND relation = $3 AND subject = $4"
        )

    async def connect(self) -> None:
        self._pool = await asyncpg.create_pool(
            self._dsn, min_size=self._min_size, max_size=self._max_size
        )
        try:
            async with self._pool.acquire() as conn:
                if self._create_schema:
                    await conn.execute(_schema_sql(self._table, self._bare_table))
                self._sequence = await conn.fetchval(
                    "SELECT pg_get_serial_sequence($1, 'change_id')", self._table
                )
            if self._sequence is None:
                raise RuntimeError(f"table {self._table!r} has no change_id sequence")
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def __aenter__(self) -> "PostgresStorage":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    async def _connection(self) -> tuple[asyncpg.Connection, bool]:
        conn = self._active_conn.get()
        if conn is not None:
            return conn, False
        return await self._pool.acquire(), True

    @asynccontextmanager
    async def transaction(self):
        if self._active_conn.get() is not None:
            yield
            return
        async with self._pool.acquire() as conn:
            token = self._active_conn.set(conn)
            try:
                async with conn.transaction():
                    yield
            finally:
                self._active_conn.reset(token)

    async def lock(self, key: str) -> None:
        conn = self._active_conn.get()
        if conn is None:
            raise RuntimeError("lock() must be called inside transaction()")
        await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", key)

    async def write_tuples(self, tuples: Sequence[RelationTuple]) -> Token:
        async with self.transaction():
            conn, must_release = await self._connection()
            try:
                for t in tuples:
                    condition_name = t.condition.name if t.condition else None
                    condition_context = (
                        json.dumps(dict(t.condition.context)) if t.condition else None
                    )
                    await conn.execute(
                        self._upsert_sql,
                        t.namespace, t.object_id, t.relation, t.subject,
                        condition_name, condition_context,
                    )
            finally:
                if must_release:
                    await self._pool.release(conn)
        return await self.current_token()

    async def delete_tuples(self, tuples: Sequence[RelationTuple]) -> Token:
        async with self.transaction():
            conn, must_release = await self._connection()
            try:
                deleted = 0
                for t in tuples:
                    status = await conn.execute(
                        self._delete_sql, t.namespace, t.object_id, t.relation, t.subject
                    )
                    deleted += int(status.rpartition(" ")[2])
                if deleted:
                    # A delete is a change: advance the sequence so its token is
                    # newer than any token issued before it.
                    await conn.fetchval("SELECT nextval($1::regclass)", self._sequence)
            finally:
                if must_release:
                    await self._pool.release(conn)
        return await self.current_token()

    async def read_tuples(
        self,
        namespace: str,
        object_id: str | None = None,
        relation: str | None = None,
        subject: str | None = None,
    ) -> list[RelationTuple]:
        conn, must_release = await self._connection()
        try:
            query = (
                "SELECT namespace, object_id, relation, subject, condition_name, "
                f"condition_context FROM {self._table} WHERE namespace = $1"
            )
            params: list[str] = [namespace]
            if object_id is not None:
                params.append(object_id)
                query += f" AND object_id = ${len(params)}"
            if relation is not None:
                params.append(relation)
                query += f" AND relation = ${len(params)}"
            if subject is not None:
                params.append(subject)
                query += f" AND subject = ${len(params)}"
            rows = await conn.fetch(query, *params)
            return [_row_to_tuple(row) for row in rows]
        finally:
            if must_release:
                await self._pool.release(conn)

    async def current_token(self) -> Token:
        conn, must_release = await self._connection()
        try:
            # last_value alone is misleading: Postgres pre-seeds a freshly
            # created (or RESTART IDENTITY-reset) sequence's last_value to
            # its start value even before anything has actually consumed
            # it. is_called distinguishes "really advanced" from "just
            # initialized" -- only count it once nextval() has actually run.
            value = await conn.fetchval(
                f"SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM {self._sequence}"
            )
            return str(value)
        finally:
            if must_release:
                await self._pool.release(conn)

    async def wait_for_token(self, token: Token) -> None:
        try:
            wanted = int(token)
        except (TypeError, ValueError):
            raise ValueError(f"invalid consistency token {token!r}") from None
        current = await self.current_token()
        if int(current) < wanted:
            raise RuntimeError(
                f"storage is behind token {token!r} (current: {current!r})"
            )
