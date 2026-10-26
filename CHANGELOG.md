# Changelog

## 0.8.1

### Fixed

- `PostgresStorage.current_token()` reads the change sequence with `pg_sequence_last_value()`, which needs only `USAGE` on the sequence. 0.8.0 selected from the sequence directly, which needs `SELECT`, so a role holding exactly the privileges that `docs/security.md` (A16) documents failed every write and every delete with `permission denied for sequence`. The least-privilege test now grants only those privileges.

Upgrade from 0.8.0 with no other changes. A deployment that granted `SELECT` on the sequence as a workaround can revoke it.

## 0.8.0

A security release. Each change below refers to a finding in [`docs/security.md`](docs/security.md), which explains the mechanism and the attack it closes. Several changes alter behaviour that 0.7.0 users may depend on; read the Upgrade Notes before upgrading.

### Security

- Stored condition context takes precedence over request context (A1). `Client(..., context_precedence="request")` restores the 0.7.0 order.
- Conditions are three-valued. A condition returns `True`, `False`, or `None` for indeterminate. Rewrite rules combine the three values with Kleene logic, and `check()` allows only on `True`, so missing context denies, also under `Exclusion` (A2, A3). `EvaluationDecision.indeterminate` reports the case.
- Built-in conditions return `None` for missing or invalid parameters instead of substituting permissive defaults (A2).
- A condition result that is not `True`, `False`, or `None` raises `TypeError`. Context keys `subject` and `resource`, and non-string keys, raise `ValueError` (A4).
- A plain tuple subject matches only a plain request subject. A userset tuple subject matches an identical userset subject directly (A5).
- Identifiers are validated in `ObjectRef.parse`, `SubjectRef.parse`, and `RelationTuple` (A6).
- `write()` validates what a tuple's subject refers to (A7).
- `write()` takes storage locks around the cardinality and cycle checks; `PostgresStorage` implements them with advisory locks (A8).
- `SqliteStorage` owns transactions per task and uses `BEGIN IMMEDIATE`, so concurrent tasks cannot join or lose each other's writes (A9).
- Deletes advance the consistency token (A10).
- Node results are memoized within a check, and `max_evaluations` bounds the work of one check; beyond it, `EvaluationBudgetExceeded` is raised (A11).
- `expand()` enforces `max_depth`, detects cycles, and spends from the same budget (A12).
- FastAPI: resource placeholders resolve from path parameters only, unless `resource_sources` enables query parameters or headers. Ambiguous and missing values are rejected with 400, and templates may contain only bare `{name}` fields (A13).
- FastAPI: whether `get_context` takes the request is read from its signature, and its exceptions propagate (A14).
- `Namespace.relations` and `Namespace.max_subjects` are read-only (A15).
- Conditions on tupleset tuples are evaluated (A19).

### Added

- `Client` keyword arguments `context_precedence` and `max_evaluations`.
- `EvaluationBudgetExceeded`.
- `EvaluationDecision.indeterminate`.
- Optional storage method `lock(key)`.
- `table=` and `create_schema=` on `SqliteStorage` and `PostgresStorage` (A16).
- `resource_sources=` on `requires()` and `explain_access()`.
- Extra `postgres`; `py.typed`.
- A test workflow covering Python 3.11 to 3.13 and PostgreSQL 16.

### Removed

- The unused `duckdb` dependency, the `authz` console script, and `authz.main` (A17).

### Packaging and Release

- `asyncpg` moved to the extra `python-authz[postgres]`. `PostgresStorage` loads lazily and is no longer listed in `authz.__all__`.
- The `fastapi` extra depends on `fastapi` instead of `fastapi[all]`.
- Project URLs point at `github.com/tensor-forge-ai/python-authz`.
- The publishing workflow pins actions to commit SHAs, runs the tests first, checks the tag against the package version, and publishes with attestations (A18).

### Upgrade Notes

1. **Stored context wins.** A tuple's stored context now overrides request context. If you passed request context to override stored values on purpose, construct the client with `context_precedence="request"`, or move those values out of the tuple.
2. **Missing context denies.** A built-in condition with a missing parameter denies, where it used to allow. Make sure every conditional tuple carries its parameters, and every check that reaches one passes the request side.
   - **Numbers.** Numeric parameters must be finite numbers; `True`, `NaN`, and infinities are rejected.
   - **Sets.** `in_set` and `jurisdiction_match` require a list, tuple, set, or frozenset for their allowed values; a string is rejected.
   - **Both jurisdiction parameters.** When `jurisdiction_match` receives both `allowed_jurisdictions` and `required_jurisdiction`, both must hold.
3. **Custom conditions must return a boolean or `None`.** Returning `0`, `1`, or another truthy value raises `TypeError`.
4. **Userset subjects.** A check whose subject is a userset (`group:eng#member`) no longer matches tuples granted to the object `group:eng`.
5. **Identifiers.** Tuples with empty ids, ids containing `#`, whitespace, or control characters, or invalid namespace or relation names can no longer be constructed. Rows of that kind already in storage raise when read; find and rewrite them before upgrading.
6. **Write validation.** `write()` rejects a userset subject whose namespace or relation is not registered, and a userset subject on a tupleset relation.
7. **Conditional parent tuples now apply.** A conditional tuple on a tupleset relation used to be followed unconditionally.
8. **Tokens.** `delete()` returns a newer token than the write before it. A PostgreSQL role that deletes tuples needs `USAGE` on the change sequence.
9. **SQLite.** Transactions are explicit `BEGIN IMMEDIATE` transactions on an autocommit connection, and concurrent tasks wait for each other.
10. **FastAPI.** Templates resolve from path parameters by default. Pass `resource_sources=("path", "query")` or include `"header"` to restore the old lookup, and write header placeholders in the underscore form (`{x_tenant_id}` for `X-Tenant-Id`). Templates with attribute access, indexing, or format specifications raise `ValueError` when the route is declared.
11. **Explain.** `explain()` is not memoized and can raise `EvaluationBudgetExceeded` on a wide graph that `check()` evaluates within budget; raise `max_evaluations` if that happens on legitimate data.
12. **Installation.** Install `python-authz[postgres]` to use `PostgresStorage`. `from authz import PostgresStorage` keeps working when `asyncpg` is installed.
13. **API.** The new `Client` arguments are keyword-only.

## 0.7.0

- Singleton and cardinality constraints: `singleton_relations` and `max_subjects` on `Namespace`, enforced by `write()` with `CardinalityViolationError`.
- `build_role_hierarchy()` for ordered role tiers with downward inheritance and `override_<role>` relations.

## 0.6.0

- Request context for conditions, `explain()` with `EvaluationDecision`, `check_batch()`, `list_permissions()`, `list_objects()`, built-in conditions, and FastAPI `get_context` and `explain_access()`.

## 0.5.0

- First release: Zanzibar-style rewrite rules, conditions, SQLite and PostgreSQL storage, consistency tokens, and the FastAPI integration.
