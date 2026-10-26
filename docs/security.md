# Security Analysis

This document is an end-to-end security analysis of `authz` as of version 0.7.0, and a record of what version 0.8.0 changes in response. It states the threat model first, then each finding with the mechanism that causes it, a concrete failure, and the fix. A final section lists the properties 0.8.0 guarantees and the responsibilities that remain with the application.

## Threat Model

`authz` is a library. It runs inside an application process, and its security depends on which of its inputs an attacker can influence. The inputs fall into four groups.

| Input | Who controls it | Trust |
|---|---|---|
| Schema (`Namespace`, rewrite rules), registered conditions, `Client` options | The application developer | Trusted |
| Storage contents (tuples) | The application, often on behalf of users ("share this folder with bob") | Trusted in structure, user-influenced in content |
| `check()` arguments: subject | The application's authentication layer | Trusted after authentication, but frequently built by string formatting from token claims |
| `check()` arguments: resource and context | Often derived from the HTTP request | Untrusted |

An attacker succeeds by doing any of the following:

- obtaining an allow that the policy does not grant (escalation);
- making checks raise or run long, so that legitimate requests fail (denial of service);
- breaking an invariant the schema declares, such as a singleton relation or an acyclic graph;
- making a revocation invisible to a later check.

Leaking which tuples exist through error messages is a smaller concern and is covered under Residual Responsibilities.

Severity below follows the usual reading. **High** means an escalation or a broken invariant reachable through ordinary use. **Medium** means a denial of service, or an escalation that needs an unusual but plausible configuration. **Low** means hardening.

## Findings

| ID | Severity | Component | Finding |
|---|---|---|---|
| A1 | High | engine | Request context overrides policy context stored on a tuple |
| A2 | High | conditions | Built-in conditions allow when their parameters are missing |
| A3 | High | engine | A failed condition under `Exclusion` grants access |
| A4 | Medium | conditions | Any truthy return value counts as an allow |
| A5 | High | engine | Direct matching ignores the relation of the request subject |
| A6 | Medium | tuples | Identifiers are not validated |
| A7 | Medium | engine | Tuples that reference undefined relations make later checks raise |
| A8 | High | engine, storage | Cardinality and cycle checks race with concurrent writers |
| A9 | High | SQLite storage | Concurrent tasks share one transaction, and acknowledged writes can be lost |
| A10 | Medium | storage | Deletes do not advance the consistency token |
| A11 | Medium | engine | Evaluation time is exponential in graph depth |
| A12 | Medium | engine | `expand()` has no depth or cycle bound |
| A13 | High | FastAPI | Resource placeholders resolve from headers and query parameters |
| A14 | Medium | FastAPI | `get_context` errors are retried with a different call |
| A15 | Low | schema | A namespace can be mutated after registration |
| A16 | Low | storage | Fixed table name, and DDL on every connect |
| A17 | Low | packaging | Unused native dependency, mandatory database driver, stray console script |
| A18 | Medium | release | The publishing workflow is not pinned, gated, or attested |
| A19 | Low | conditions, engine | Conditions on tupleset tuples are ignored |

### A1. Request Context Overrides Policy

A condition is attached to a tuple together with a context written at the same time, for example

```python
RelationTuple("claim", "10", "approver", "user:alice",
              condition=Condition("max_amount", {"max_amount": 1000}))
```

which says that alice may approve claims up to 1000. At check time 0.7.0 merged contexts as `{**stored, **request}`, so a key present in both took the request's value. A FastAPI route that builds its context from the request body or the query string therefore let the caller send `max_amount=10**12` and approve any amount. The stored context is the policy, and the request context is a claim about the current operation; the merge order made the claim override the policy.

**Fix.** The stored context takes precedence: the merge is `{**request, **stored}`. The order matches the caveat semantics of SpiceDB, where values written on the relationship win. `Client(..., context_precedence="request")` restores the 0.7.0 order for applications that knowingly rely on it.

### A2. Fail-Open Built-in Conditions

Each built-in condition substituted a permissive default when a parameter was absent or unparseable:

- `max_amount` read a missing `amount` as 0 and a missing `max_amount` as infinity, so a tuple written without a limit allowed everything;
- `min_amount` read a missing `amount` as 0, which fails open for a negative minimum;
- `equals_attr` compared `ctx.get(attribute) == ctx.get("expected")`, which is `None == None`, hence true, when both are missing;
- `in_set` accepted a string as `allowed_values`, so membership became substring search: `"adm" in "admin"` is true;
- `jurisdiction_match` returned true when neither `allowed_jurisdictions` nor `required_jurisdiction` was given;
- `not_same_subject` allowed every subject when `excluded_subject` was missing, which defeats a separation-of-duties rule exactly when it is misconfigured.

In every case a programming or configuration error turned into an allow.

**Fix.** A built-in returns a result only when its inputs are present and well-typed: numbers must be finite and must not be booleans (`True` is not 1), and set-valued parameters must be a list, tuple, set, or frozenset. Otherwise the built-in returns `None`, which A3 defines as indeterminate and which denies.

### A3. Negation under Missing Context

Replacing the defaults of A2 with `False` would not have been sound, because rewrite rules can negate. Consider

```python
"viewer": Exclusion(Direct(), From("blocked"))
```

with a conditional `blocked` tuple that needs a context key the caller omitted. If the condition evaluates to `False`, the subject is not blocked, and the exclusion grants access. A condition that cannot be evaluated must not be read as either answer.

**Fix.** Evaluation is three-valued: every rule produces `True`, `False`, or `None` (indeterminate), combined by Kleene's strong logic:

| Rule | Result |
|---|---|
| `Union(a, b, ...)` | `True` if any child is `True`; else `None` if any child is `None`; else `False` |
| `Intersection(a, b, ...)` | `False` if any child is `False`; else `None` if any child is `None`; else `True` |
| `Exclusion(base, subtract)` | `Intersection(base, not subtract)`, with `not None = None` |
| `Direct()` | `Union` over the tuples of the relation |
| `TupleToUserset(t, r)` | `Union` over the tuples of `t`, each `Intersection(condition, r on the parent)` |

A condition may return `None` to say its inputs were missing or invalid. `check()` returns `True` only when the result is `True`, so indeterminate denies, and it denies through `Exclusion` as well: `Exclusion(True, None) = None`. The evaluator still short-circuits on a decisive value (`True` in a union, `False` in an intersection), so the change costs nothing on graphs without indeterminate conditions. `explain()` reports the case with `indeterminate=True` and a reason that names it.

### A4. Truthy Condition Results

`PythonCallableEvaluator` returned `bool(result)`, so a condition that returned the string `"False"`, a non-empty list, or an object allowed access. **Fix.** A condition must return `True`, `False`, or `None`. Anything else raises `TypeError` naming the condition, and the engine applies the same rule to custom `ConditionEvaluator` implementations. The evaluator also rejects context keys `subject` and `resource`, which collide with the keyword arguments every condition receives, and non-string keys, with a `ValueError` that names the condition instead of an opaque `TypeError` from the call.

### A5. Subject Relation Ignored in Direct Matching

For a tuple with a plain subject, `_eval_direct` compared only the namespace and the object id of the request subject. A check with the subject `group:eng#member` therefore matched a tuple whose subject was the object `group:eng`, although a userset and an object are different principals. The same comparison matters when the application builds the subject by formatting a token claim, for example `f"user:{claims['sub']}"`. A `sub` of `bob#admin` produced the userset `user:bob#admin`, which matched every tuple granted to `user:bob`.

**Fix.** A plain tuple subject matches only a plain request subject with the same namespace and id. A userset tuple subject that equals the request subject matches directly, before any recursion, so that "does `group:eng#member` have `viewer`" is answered by a tuple naming `group:eng#member`, as in Zanzibar. The subject comparison now runs before the condition, so a condition is never evaluated, or reported by `explain()`, for a tuple that cannot match.

### A6. Identifier Validation

`ObjectRef.parse` and `SubjectRef.parse` split on the first `:` and `#` and accepted any remainder. Empty namespaces and ids, ids containing `#`, and ids with whitespace or control characters were all stored. A `#` inside an object id breaks the round trip between a tuple and its string form, and it is the mechanism behind the subject confusion in A5. **Fix.** Namespace and relation names must match `[A-Za-z_][A-Za-z0-9_-]*`. Object ids must be non-empty and must not contain `#`, whitespace, or control characters; a `:` after the first is allowed, so `book:urn:isbn:0451450523` is the object `urn:isbn:0451450523` of namespace `book`. The rules apply in `parse` and in `RelationTuple` construction, so an invalid tuple cannot reach storage.

### A7. Poisoned Tuples

`write()` checked the tuple's own namespace and relation, but not what its subject refers to. The tuple `document:1#viewer@group:eng#nonexistent` was stored. Every later check of `viewer` on `document:1` then raised `RelationNotFound` while following it, which denied that permission to every user of the document, including users with an unrelated direct grant. **Fix.** `write()` validates references:

- a userset subject must name a registered namespace and one of its relations;
- a tuple on a tupleset relation (one that a `TupleToUserset` follows) must have a plain subject, and the subject's namespace must define the `computed_relation` of every rule that follows it.

Plain subjects of unregistered namespaces, such as `user:alice`, remain allowed.

### A8. Write Races on Cardinality and Cycles

`write()` enforced `max_subjects` by reading the current subjects and then inserting, inside a transaction at the default isolation level. Two concurrent writers for the same singleton relation both read an empty set, both passed, and both inserted, leaving two holders of a relation declared to have one. The data-cycle guard had the same shape: two edges written concurrently can close a cycle that neither write sees alone. Check-time cycle detection then raises `CycleDetected` on every check that reaches the cycle.

**Fix.** Storage may implement an optional `lock(key)` that holds an exclusive lock on `key` until the transaction ends. `write()` locks each `(namespace, object_id, relation)` with a cardinality limit, in sorted order, and then one global graph key when the batch contains an edge. The fixed order makes deadlock impossible. `PostgresStorage.lock` takes `pg_advisory_xact_lock(hashtextextended(key, 0))`. A storage without `lock` still works, without the guarantee, so third-party backends written against 0.7.0 keep running.

### A9. Shared SQLite Transactions

`SqliteStorage` has one connection, and 0.7.0 marked an open transaction with an instance attribute. A second task that wrote while the first task's transaction was open saw the flag, skipped its own `BEGIN`, and wrote into the first task's transaction. If the first task then rolled back (for example on `CardinalityViolationError`), the second task's write disappeared, although the second task had already received a token for it. Reads on the shared connection could also see another task's uncommitted rows.

**Fix.** Transactions are owned per task through a `ContextVar`, serialized with an `asyncio.Lock`, and run with explicit `BEGIN IMMEDIATE`, which also takes SQLite's write lock against other processes on the same file. A nested `transaction()` in the owning task still joins the outer one. Reads from tasks that do not own the open transaction wait for it to finish, so they see only committed rows. Because `BEGIN IMMEDIATE` already excludes every other writer, `SqliteStorage.lock` is a no-op.

### A10. Revocations and Consistency Tokens

A token is the storage's change counter, and `check(..., at_least_as_fresh_as=token)` refuses to evaluate against a state older than the token. Inserts advanced the counter, deletes did not: `delete()` returned the counter value from before the delete, so the token of a revocation was no newer than tokens issued earlier, and a check against a lagging state would accept it. This is the "new enemy" problem of the Zanzibar paper. **Fix.** A delete that removes at least one row advances the counter in the same transaction (`nextval` on the change sequence in PostgreSQL, a bump of `sqlite_sequence` in SQLite). A non-integer token now raises `ValueError` instead of an unhandled conversion error.

### A11. Exponential Evaluation

`max_depth` bounds the length of a resolution chain, not the number of nodes visited. Let each folder `f_i` have two parents `a_{i+1}` and `b_{i+1}`, each of whose single parent is `f_{i+1}`, and let the subject hold no grant anywhere. A check on `f_0` then visits `f_1` twice, `f_2` four times, and `f_d` `2^d` times, because every path is explored separately. At depth 20 that is about a million node evaluations from 60 tuples, and any user who can create folders and set parents can build it.

**Fix.** Within one top-level check the subject and context are fixed, so the result of a node `(namespace, object_id, relation)` does not depend on how it was reached. The engine memoizes each completed node per check; the diamond lattice above costs `O(d)` evaluations, and in the test suite a 20-deep lattice takes at most 43 storage reads. A node still in progress is never served from the memo, so cycle detection is unchanged. A budget, `Client(..., max_evaluations=10_000)`, counts node evaluations per check and raises `EvaluationBudgetExceeded` beyond it. `explain()` records the traversal and is not memoized, so on very wide graphs it can hit the budget where `check()` does not. Every `check()` and `explain()` also uses a per-call read cache, which in 0.7.0 only `check_batch()` had.

### A12. Unbounded `expand()`

`expand()` recursed through `From` and `TupleToUserset` without a depth limit or a visited set. Cyclic data, which A8 shows can exist, made it recurse until Python's recursion limit. **Fix.** `expand()` applies `max_depth`, detects cycles on its path, and spends from the same budget as `check()`.

### A13. FastAPI Resource Resolution

`requires("viewer", "document:{document_id}", ...)` filled the template from headers, query parameters, and path parameters merged into one dictionary, with path parameters last. Two attacks followed.

- A placeholder that the route does not define as a path parameter was taken from the query string or a header, which the caller controls. A route `/reports` with the template `report:{report_id}` authorized whatever `report_id` the caller sent, while the handler could read a different value from elsewhere.
- When the same name appeared in several sources, authorization used one value and the handler, reading a specific source, could use another (parameter pollution).

In addition, a missing placeholder raised `KeyError`, which FastAPI turns into a 500.

**Fix.** `requires()` and `explain_access()` take `resource_sources`, defaulting to `("path",)`. Query parameters and headers are used only when listed. A name with more than one distinct value, across the enabled sources or within one of them, is rejected with 400, and so is a missing placeholder. Templates may contain only bare `{name}` fields; attribute access, indexing, conversions, and format specifications raise `ValueError` when the route is declared. A header placeholder uses the lowercase header name with dashes replaced by underscores (`X-Report-Id` becomes `{x_report_id}`). A resolved resource that fails A6 validation is rejected with 400, also when it comes from a resource function.

### A14. Context Function Retry

`_resolve_context` called `get_context(request)` and, on any `TypeError`, called `get_context()`. A `TypeError` raised inside a function that does take the request was therefore swallowed, and the function was called again without the request, possibly returning a different context. **Fix.** Whether `get_context` takes the request is decided once, from its signature, when the route is declared. Exceptions propagate.

### A15. Mutable Namespaces

`Namespace` kept a reference to the caller's relations dictionary. `register_schema` checks for `From` cycles and caches tupleset relations at registration, so a later mutation of that dictionary bypassed both. **Fix.** `Namespace.relations` and `Namespace.max_subjects` are read-only copies (`MappingProxyType`).

### A16. Storage Configuration

Both storages used the fixed table name `tuples` and ran `CREATE TABLE IF NOT EXISTS` on every connect, which requires DDL privileges for the application's database role. **Fix.** `table=` names the table (validated as an identifier, and `schema.table` for PostgreSQL, because the name is interpolated into SQL), and `create_schema=False` connects without DDL, so a least-privilege role with `SELECT`, `INSERT`, `UPDATE`, and `DELETE` on the table and `USAGE` on its sequence suffices. All other SQL was already parameterized; the analysis found no injection.

### A17. Packaging

The package depended on `duckdb`, which no module imports, and on `asyncpg` for every installation, and it installed a console script `authz` that printed a greeting. Each unnecessary dependency is a native binary that a user must trust and patch. **Fix.** `duckdb` is removed, `asyncpg` moved to the extra `python-authz[postgres]` with `PostgresStorage` loaded lazily, the FastAPI extra no longer pulls `fastapi[all]`, the console script is removed, the project URLs point at the repository that publishes the package, and the package ships `py.typed`.

### A18. Release Pipeline

`publish.yml` built and published on every published GitHub release, using actions referenced by mutable tags, with no test run and no check that the tag matched the package version. A compromised or retagged action could have altered the wheel, and a release created from the wrong commit would have shipped. **Fix.** Every action is pinned to a full commit SHA. The workflow runs the test matrix (including PostgreSQL) before building, verifies that the release tag equals the version in `pyproject.toml`, and checks out without persisted credentials. It publishes through PyPI trusted publishing with build attestations. Default token permissions are `contents: read`, and only the publishing job receives `id-token: write`. A separate `test.yml` runs the suite on every push and pull request.

### A19. Conditions on Tupleset Tuples

`TupleToUserset` followed the tuples of the tupleset relation without evaluating their conditions, so a conditional `parent` tuple behaved as unconditional. **Fix.** The condition of a tupleset tuple is evaluated and combined with the result on the parent, as in the table of A3.

## Guarantees in 0.8.0

1. `check()` returns `True` only when the rewrite rules evaluate to `True` with every condition on the deciding tuples evaluating to `True`. Missing or invalid condition context never contributes an allow, including under negation.
2. Policy written on a tuple cannot be overridden by request context, unless the client is constructed with `context_precedence="request"`.
3. Every stored tuple has valid identifiers and refers only to defined relations, provided all writes go through `Client.write`.
4. With a storage that implements `lock` (both bundled ones do), concurrent writes cannot exceed `max_subjects` or jointly create a data cycle.
5. Tokens increase on every insert and every effective delete.
6. One `check()` performs at most `max_evaluations` node evaluations and follows chains of at most `max_depth` relations, and `expand()` obeys the same bounds.

## Residual Responsibilities

Some properties depend on how the application uses the library, and no change to the library can provide them.

- **Request context is a claim.** A condition can only be as trustworthy as its inputs. If a route passes `amount` from the request body, the handler must act on that same amount; otherwise the caller can authorize a small amount and execute a large one. Values such as the current time should come from the server.
- **Subjects come from authentication.** Build subject strings from verified identities. A6 rejects malformed identifiers, but it cannot tell whether a well-formed subject belongs to the caller.
- **Error messages name tuples.** `CardinalityViolationError` lists the existing subjects, and `CycleDetected` and `explain()` name objects on the evaluation path. Log them; do not return them to untrusted clients.
- **`expand()` reports candidates.** It lists the subjects reachable through the rules without evaluating conditions, and it lists both operands of `Intersection` and the base of `Exclusion`. Use it for display and debugging, and use `check()` for decisions.
- **`list_objects()` without candidates reads the namespace.** The per-check budget bounds each check, but the initial read of every object in the namespace is unbounded. Pass `candidate_ids` on large namespaces.
- **Exceptions deny by aborting.** A condition that raises, a cycle, the depth limit, and the budget all abort the whole check with an exception, even when another branch would have allowed. This is fail-closed behaviour, and the application should map these errors to a refusal and log them.
- **Writes outside the client bypass validation.** Tuples inserted into the table by other means are not validated, and A3 treats a userset subject on a tupleset relation found in storage as indeterminate.
