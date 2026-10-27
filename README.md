# authz

A framework-agnostic ReBAC/RBAC/ABAC authorization engine.

## About

Most systems end up with three separate authorization mechanisms: roles
for admin/editor/viewer distinctions (RBAC), attribute rules for things
like "only during business hours" (ABAC), and some hand-rolled traversal
for hierarchies like folders or nested groups (ReBAC). `authz` implements
all three on one data structure instead: a graph of relationship facts,
each one a `(namespace, object, relation, subject)` tuple, in the style
of Google's Zanzibar paper.

A role is just a relation on an object, so "alice is an editor of
document:roadmap" is a tuple like any other. A folder hierarchy is a
traversal between tuples: "you can view a document if you can view its
parent folder" is one rule, applied uniformly no matter how deep the
folder tree goes. An attribute check is a condition attached to a
specific tuple, evaluated against the current subject and context at
check time. Because all three live in the same graph, a single `check()`
call can walk through a role, into a group, and across a parent/child
boundary in one pass, all using the same traversal logic, instead of
three separate mechanisms that would each need to be kept correct and
kept in agreement with each other.

## Status

Release, version 0.9.0, for Python 3.11 and later, including the free-threaded builds of 3.14 and 3.15. Version 0.8.0 was a security release: [`docs/security.md`](docs/security.md) analyses the library end to end and records what changed, and [`CHANGELOG.md`](CHANGELOG.md) lists the upgrade notes. The library provides:

- **Unified ReBAC + RBAC + ABAC**: Zanzibar-style relationship graphs with conditions evaluated against stored policy and request context. Stored context takes precedence.
- **Three-Valued Conditions**: a condition may return `None` when its context is missing or invalid; rewrite rules combine `True`, `False`, and `None` with Kleene logic, and a check allows only on `True`, so missing context never grants access, even under `Exclusion`.
- **Bounded Evaluation**: per-check memoization, `max_depth`, and an evaluation budget (`max_evaluations`) for `check()` and `expand()`.
- **Singleton and Cardinality Constraints**: `singleton_relations` and `max_subjects` on `Namespace`, enforced under storage locks so concurrent writers cannot exceed them.
- **Declarative Role Hierarchies**: `build_role_hierarchy(roles_high_to_low, extra_relations=...)` with transitive downward inheritance and `override_<role>` relations.
- **Audit and Explanation**: `Client.explain()` returns an `EvaluationDecision` with the visited relations, matched tuples, condition results, and a reason.
- **Batch Evaluation and Introspection**: `check_batch()`, `list_permissions()`, and `list_objects()`.
- **Built-in Conditions**: `max_amount`, `min_amount`, `equals_attr`, `in_set`, `jurisdiction_match`, `not_same_subject`, all fail-closed.
- **FastAPI Integration**: `requires()` and `explain_access()`, with resource placeholders resolved from path parameters unless `resource_sources` enables query parameters or headers.
- **Storage**: async SQLite and PostgreSQL backends with configurable table names and an option to connect without DDL privileges.

## Roadmap

- DuckDB and MongoDB storage backends
- a standalone HTTP service mode beyond the sample app's admin routes
- a SAML auth integration recipe (OAuth2 and JWT are already covered)
- JSON-Logic and CEL `ConditionEvaluator` implementations, alongside the
  existing Python-callable one
- Java, Kotlin, Rust, and C++ SDKs

## Install

```bash
uv add python-authz                # core, with SQLite storage
uv add "python-authz[postgres]"    # adds PostgresStorage (asyncpg)
uv add "python-authz[fastapi]"     # adds authz.integrations.fastapi
```

## Quickstart

A schema declares, per namespace, how each relation is computed: `Direct()`
means "true when a matching tuple exists," `Union` combines several rules
with OR, and `TupleToUserset` re-checks a relation on a related object (the
mechanism behind "viewer of the parent folder implies viewer of the
document"). Once the schema is registered, `write()` adds facts to the
graph and `check()` answers a yes/no access question against it:

```python
from authz import (
    Client, Direct, From, Namespace, PythonCallableEvaluator,
    RelationTuple, SqliteStorage, TupleToUserset, Union,
)

async with SqliteStorage(":memory:") as storage:
    client = Client(storage=storage, condition_evaluator=PythonCallableEvaluator())

    folder = Namespace("folder", {
        "owner": Direct(),
        "viewer": Union(Direct(), From("owner")),
    })
    document = Namespace("document", {
        "parent": Direct(),
        "viewer": Union(Direct(), TupleToUserset("parent", "viewer")),
    })

    client.register_schema(folder, document)

    await client.write([
        RelationTuple("folder", "workspace", "owner", "user:alice"),
        RelationTuple("document", "roadmap", "parent", "folder:workspace"),
    ])

    await client.check("user:alice", "viewer", "document:roadmap")  # True
```

See [`docs/quickstart.md`](docs/quickstart.md) for the full walkthrough
(groups, ABAC conditions, consistency tokens, `expand()`), and
[`examples/seed_data.py`](examples/seed_data.py) for a runnable version of
it: `python -m examples.seed_data`.

Before designing your own schema, read [`docs/pitfalls.md`](docs/pitfalls.md).
It covers schema vs. data cycles, which rewrite rule (`Union`,
`Intersection`, `Exclusion`, `From`, `TupleToUserset`) fits which
situation, and when a depth-limit error means your data is legitimately
deep versus something bypassed the guards.

## Role Hierarchies & Cardinality Constraints

Version 0.7.0 added first-class support for ordered role tiers with upward override relations and singleton limits:

```python
from authz import Namespace, build_role_hierarchy, RelationTuple, CardinalityViolationError

# Build 5-tier role relations with downward inheritance and override_<role> relations
roles = build_role_hierarchy([
    "org_admin",
    "org_manager",
    "tpa_coordinator",
    "org_user",
    "diagnostic_billing_staff",
])

# Enforce singleton constraint: an organization can have at most ONE org_admin
org_ns = Namespace("org", roles, singleton_relations={"org_admin"})
client.register_schema(org_ns)

# Alice is assigned org_admin -> inherits org_manager, tpa_coordinator, etc.
await client.write([RelationTuple("org", "acme", "org_admin", "user:alice")])
assert await client.check("user:alice", "org_user", "org:acme") is True

# Bob cannot also be assigned org_admin on the same org
try:
    await client.write([RelationTuple("org", "acme", "org_admin", "user:bob")])
except CardinalityViolationError as e:
    print(f"Singleton violation: {e}")
```

## FastAPI Integration Example

A route needs one thing from an authorization library: block the request
before the handler runs if the caller lacks permission. `authz.integrations.fastapi`
does that as a single `Depends()`, so the check happens the same way
FastAPI already resolves any other dependency. It's an optional adapter
built as a proof of concept; a Django, Flask, or plain-script consumer
should call the same `Client` directly instead.

```python
from fastapi import Depends
from authz.integrations.fastapi import requires


@app.get("/documents/{document_id}")
async def read_document(
    document_id: str,
    _: None = Depends(requires(
        "viewer", "document:{document_id}",
        get_client=get_authz_client, get_subject=get_current_user,
    )),
):
    ...
```

`requires()` makes the route depend on a `check()` call: when that call
returns `False`, the request never reaches the handler body, and the
caller receives a 403 automatically. See
[`docs/fastapi_integration.md`](docs/fastapi_integration.md) for the full
example, including how `get_client`/`get_subject` compose with your app's
own database and auth setup.

## Security

Read [`docs/security.md`](docs/security.md) for the threat model, the findings fixed in 0.8.0, and the responsibilities that stay with the application. Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## Development

```bash
uv sync --all-extras
uv run pytest
```

The PostgreSQL tests use the server at `AUTHZ_TEST_POSTGRES_DSN` (a superuser DSN; the tests create and drop their own database), or start one with testcontainers when Docker is available, and are skipped otherwise.
