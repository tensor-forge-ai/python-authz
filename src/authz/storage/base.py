from contextlib import AbstractAsyncContextManager
from typing import Protocol, Sequence

from authz.tuples import RelationTuple

Token = str


class Storage(Protocol):
    # Optional: `async def lock(self, key: str) -> None`. Called inside transaction();
    # must block until the caller holds an exclusive lock on `key` until the
    # transaction ends. Client.write uses it, when present, to serialize
    # cardinality checks and cycle guards across concurrent writers.

    async def write_tuples(self, tuples: Sequence[RelationTuple]) -> Token: ...

    async def delete_tuples(self, tuples: Sequence[RelationTuple]) -> Token: ...

    async def read_tuples(
        self,
        namespace: str,
        object_id: str | None = None,
        relation: str | None = None,
        subject: str | None = None,
    ) -> list[RelationTuple]: ...

    async def current_token(self) -> Token: ...

    async def wait_for_token(self, token: Token) -> None: ...

    def transaction(self) -> AbstractAsyncContextManager[None]: ...
