# Quickstart

This walkthrough uses plain `Client` calls throughout. (See
[`fastapi_integration.md`](fastapi_integration.md) for an optional FastAPI
adapter.)

## The core idea

Instead of separate systems for roles, group hierarchies, and attribute
rules, everything here is a fact in one graph: a `(namespace, object,
relation, subject)` tuple. "alice owns folder:workspace" is a tuple.
"eng-team can view folder:workspace" is a tuple. A **schema** declares,
per namespace, how each relation is computed from the tuples that exist:
whether it's a plain fact, an OR of several other relations, or a lookup
that follows a tuple to another object and re-checks a relation there.
`check()` answers a yes/no question by walking that graph; `write()` adds
facts to it.

This walkthrough builds the schema and data from
[`examples/seed_data.py`](../examples/seed_data.py); you can run it
directly with `python -m examples.seed_data`.

## 1. Construct a `Client`

```python
from authz import Client, PythonCallableEvaluator, SqliteStorage


async with SqliteStorage(":memory:") as storage:
    client = Client(storage=storage, condition_evaluator=PythonCallableEvaluator())
    ...
```

`Client` is the single entry point: it validates writes and checks
against a registered schema, persists tuples through the `storage`
backend, and evaluates `check()` calls. `SqliteStorage` is the Phase 1
backend, async, backed by `aiosqlite`. `PythonCallableEvaluator` resolves
ABAC conditions as plain Python functions (see step 4).

## 2. Define the Schema

Each relation is built from a small set of rewrite rules. `Direct()`
means the relation holds whenever a matching tuple was written for it.
`Union` gives RBAC-style role hierarchy: `Union(Direct(), From("owner"))`
on an `editor` relation means someone is an editor if there's a direct
`editor` tuple for them, or if they qualify as `owner`. `TupleToUserset`
gives ReBAC-style traversal: `TupleToUserset("parent", "viewer")` on
`document.viewer` means a document's viewers also include anyone who is
a `viewer` of the document's `parent` folder.

```python
from authz import Direct, From, Namespace, TupleToUserset, Union


group = Namespace("group", {"member": Direct()})

folder = Namespace("folder", {
    "owner":  Direct(),
    "editor": Union(Direct(), From("owner")),
    "viewer": Union(Direct(), From("editor")),
})

document = Namespace("document", {
    "parent": Direct(),
    "owner":  Direct(),
    "editor": Union(Direct(), From("owner")),
    "viewer": Union(Direct(), From("editor"), TupleToUserset("parent", "viewer")),
})

client.register_schema(group, folder, document)
```

`register_schema()` also runs a static cycle check over the rewrite rules
before accepting them; see [pitfalls.md](pitfalls.md) for what that
catches and what it doesn't.

## 3. Write Relationship Tuples

A subject in a tuple is either a plain object (`"user:alice"`) or a
**userset** reference (`"group:eng#member"`, read as "members of group
eng"). Userset subjects are how group membership composes with
everything else: nothing in the schema needs to special-case "this
subject might actually be a group."

```python
from authz import RelationTuple


await client.write([
    RelationTuple("folder", "workspace", "owner", "user:alice"),
    RelationTuple("group", "eng", "member", "user:bob"),
    RelationTuple("folder", "workspace", "viewer", "group:eng#member"),
    RelationTuple("document", "roadmap", "parent", "folder:workspace"),
])
```

`write()` returns a `Token`. Keep it if you need to guarantee a
subsequent `check()` observes this exact write (see step 5).

## 4. Check Access

```python
await client.check("user:alice", "viewer", "document:roadmap")  # True: alice owns the folder
await client.check("user:bob", "viewer", "document:roadmap")    # True: bob is in eng, eng can view the folder
await client.check("user:mallory", "viewer", "document:roadmap")  # False
```

ABAC conditions attach to an individual tuple and are evaluated at check
time, not write time, against the current subject, resource, and any
extra context passed in. That means the same tuple can produce a
different result on two calls made minutes apart, if the condition it
carries depends on something like the time of day. To add one, register
a Python callable and attach it to a tuple:

```python
from authz import Condition


def is_business_hours(*, subject, resource, timezone):
    ...  # your logic

client.register_condition("business_hours", is_business_hours)

# A condition returns True, False, or None. None means its context was
# missing or invalid; such a tuple never grants access.


await client.write([
    RelationTuple("document", "roadmap", "editor", "user:carol",
                  condition=Condition("business_hours", {"timezone": "UTC"})),
])
```

## 5. Consistency Tokens

Most checks don't need this: an ordinary `check()` already sees every
write that completed before it. The exception is right after a revoke,
when you need a guarantee that the very next check can't miss it.

```python
token = await client.write([...])
await client.check(subject, permission, resource, at_least_as_fresh_as=token)
```

`at_least_as_fresh_as` makes `check()` wait until storage has caught up
to that token before evaluating. See [pitfalls.md](pitfalls.md) for the
full explanation.

## 6. Debugging with `expand()`

```python
tree = await client.expand("viewer", "document:roadmap")
```

Returns a `UsersetTree` showing every direct subject and every relation
`check()` would traverse into: useful for answering "who can access
this, and by which chain of relations" without running a separate check
for every candidate subject.

## Next steps

Read [pitfalls.md](pitfalls.md) before designing your own schema. It
covers the failure modes that a reader would not notice just by looking
at the function signatures: cycles, depth limits, and when each rewrite
rule is the right tool.
