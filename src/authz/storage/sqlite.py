import asyncio
import json
import re
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Sequence

import aiosqlite

from authz.storage.base import Token
from authz.tuples import Condition, RelationTuple

_TABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def _schema_sql(table: str) -> str:
    return f"""
CREATE TABLE IF NOT EXISTS {table} (
    change_id INTEGER PRIMARY KEY AUTOINCREMENT,
    namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    subject TEXT NOT NULL,
    condition_name TEXT,
    condition_context TEXT,
    UNIQUE(namespace, object_id, relation, subject)
);
CREATE INDEX IF NOT EXISTS idx_{table}_forward
    ON {table}(namespace, object_id, relation);
CREATE INDEX IF NOT EXISTS idx_{table}_reverse
    ON {table}(namespace, subject);
"""


def _row_to_tuple(row: tuple) -> RelationTuple:
    namespace, object_id, relation, subject, condition_name, condition_context = row
    condition = None
    if condition_name is not None:
        condition = Condition(condition_name, json.loads(condition_context or "{}"))
    return RelationTuple(namespace, object_id, relation, subject, condition=condition)


class SqliteStorage:
    def __init__(self, path: str, *, table: str = "tuples", create_schema: bool = True):
        if not _TABLE.fullmatch(table):
            raise ValueError(f"invalid table name {table!r}")
        self._path = path
        self._table = table
        self._create_schema = create_schema
        self._conn: aiosqlite.Connection | None = None
        self._tx_lock = asyncio.Lock()
        self._owns_tx: ContextVar[bool] = ContextVar("authz_sqlite_tx", default=False)
        t = table
        self._upsert_sql = (
            f"INSERT INTO {t} (namespace, object_id, relation, subject, condition_name, "
            "condition_context) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(namespace, object_id, relation, subject) DO UPDATE SET "
            "condition_name = excluded.condition_name, "
            "condition_context = excluded.condition_context"
        )
        self._delete_sql = (
            f"DELETE FROM {t} WHERE namespace = ? AND object_id = ? "
            "AND relation = ? AND subject = ?"
        )

    async def connect(self) -> None:
        # Autocommit mode: transaction() issues BEGIN IMMEDIATE/COMMIT itself.
        self._conn = await aiosqlite.connect(self._path, isolation_level=None)
        if self._create_schema:
            await self._conn.executescript(_schema_sql(self._table))

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def __aenter__(self) -> "SqliteStorage":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    @asynccontextmanager
    async def transaction(self):
        if self._owns_tx.get():
            yield
            return
        async with self._tx_lock:
            await self._conn.execute("BEGIN IMMEDIATE")
            flag = self._owns_tx.set(True)
            try:
                yield
                await self._conn.execute("COMMIT")
            except BaseException:
                if self._conn.in_transaction:
                    await self._conn.rollback()
                raise
            finally:
                self._owns_tx.reset(flag)

    @asynccontextmanager
    async def _committed_reads(self):
        # One shared connection would show other tasks' uncommitted writes.
        if self._owns_tx.get():
            yield
            return
        async with self._tx_lock:
            yield

    async def lock(self, key: str) -> None:
        # No-op: BEGIN IMMEDIATE already holds SQLite's single write lock.
        pass

    async def write_tuples(self, tuples: Sequence[RelationTuple]) -> Token:
        async with self.transaction():
            for t in tuples:
                condition_name = t.condition.name if t.condition else None
                condition_context = (
                    json.dumps(dict(t.condition.context)) if t.condition else None
                )
                await self._conn.execute(
                    self._upsert_sql,
                    (
                        t.namespace,
                        t.object_id,
                        t.relation,
                        t.subject,
                        condition_name,
                        condition_context,
                    ),
                )
        return await self.current_token()

    async def delete_tuples(self, tuples: Sequence[RelationTuple]) -> Token:
        async with self.transaction():
            deleted = 0
            for t in tuples:
                cursor = await self._conn.execute(
                    self._delete_sql, (t.namespace, t.object_id, t.relation, t.subject)
                )
                deleted += cursor.rowcount
            if deleted:
                # A delete is a change: advance the AUTOINCREMENT high-water mark
                # so its token is newer than any token issued before it.
                await self._conn.execute(
                    "UPDATE sqlite_sequence SET seq = seq + 1 WHERE name = ?",
                    (self._table,),
                )
        return await self.current_token()

    async def read_tuples(
        self,
        namespace: str,
        object_id: str | None = None,
        relation: str | None = None,
        subject: str | None = None,
    ) -> list[RelationTuple]:
        query = (
            "SELECT namespace, object_id, relation, subject, condition_name, "
            f"condition_context FROM {self._table} WHERE namespace = ?"
        )
        params: list[str] = [namespace]
        if object_id is not None:
            query += " AND object_id = ?"
            params.append(object_id)
        if relation is not None:
            query += " AND relation = ?"
            params.append(relation)
        if subject is not None:
            query += " AND subject = ?"
            params.append(subject)
        async with self._committed_reads():
            async with self._conn.execute(query, params) as cursor:
                rows = await cursor.fetchall()
        return [_row_to_tuple(row) for row in rows]

    async def current_token(self) -> Token:
        # MAX(change_id) over the live table would go backwards after a
        # delete empties it; sqlite_sequence tracks the AUTOINCREMENT
        # high-water mark, which only ever increases.
        async with self._committed_reads():
            async with self._conn.execute(
                "SELECT seq FROM sqlite_sequence WHERE name = ?", (self._table,)
            ) as cursor:
                row = await cursor.fetchone()
        return str(row[0] if row else 0)

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
