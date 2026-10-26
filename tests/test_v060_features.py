import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from authz import (
    CheckItem,
    Client,
    Condition,
    Direct,
    EvaluationDecision,
    From,
    Intersection,
    Namespace,
    ObjectRef,
    PythonCallableEvaluator,
    RelationTuple,
    SqliteStorage,
    TupleToUserset,
    Union as UnionRule,
    builtin_conditions,
)
from authz.integrations.fastapi import explain_access, requires


@pytest.fixture
async def sqlite_client():
    storage = SqliteStorage(":memory:")
    await storage.connect()
    evaluator = PythonCallableEvaluator.with_builtins()
    client = Client(storage=storage, condition_evaluator=evaluator)
    yield client
    await storage.close()


# -----------------------------------------------------------------------------
# 1. Dynamic Runtime Context for ABAC
# -----------------------------------------------------------------------------


async def test_runtime_context_passed_to_condition(sqlite_client):
    sqlite_client.register_schema(Namespace("claim", {"approve": Direct()}))
    # Grant with max_amount condition from builtins
    await sqlite_client.write(
        [
            RelationTuple(
                "claim",
                "101",
                "approve",
                "user:alice",
                condition=Condition("max_amount", {"max_amount": 5000}),
            )
        ]
    )

    # Under limit: allowed
    assert (
        await sqlite_client.check(
            "user:alice", "approve", "claim:101", context={"amount": 2500}
        )
        is True
    )

    # Over limit: denied
    assert (
        await sqlite_client.check(
            "user:alice", "approve", "claim:101", context={"amount": 7500}
        )
        is False
    )


async def test_stored_tuple_context_wins_over_request_context(sqlite_client):
    sqlite_client.register_schema(Namespace("claim", {"review": Direct()}))
    await sqlite_client.write(
        [
            RelationTuple(
                "claim",
                "102",
                "review",
                "user:bob",
                condition=Condition("max_amount", {"max_amount": 1000}),
            )
        ]
    )

    # The request cannot raise the limit the tuple was written with.
    assert (
        await sqlite_client.check(
            "user:bob",
            "review",
            "claim:102",
            context={"amount": 2000, "max_amount": 5000},
        )
        is False
    )
    assert (
        await sqlite_client.check(
            "user:bob",
            "review",
            "claim:102",
            context={"amount": 500, "max_amount": 5000},
        )
        is True
    )


async def test_request_precedence_lets_request_context_override_stored():
    storage = SqliteStorage(":memory:")
    await storage.connect()
    client = Client(
        storage=storage,
        condition_evaluator=PythonCallableEvaluator.with_builtins(),
        context_precedence="request",
    )
    client.register_schema(Namespace("claim", {"review": Direct()}))
    await client.write(
        [
            RelationTuple(
                "claim", "102", "review", "user:bob",
                condition=Condition("max_amount", {"max_amount": 1000}),
            )
        ]
    )
    assert (
        await client.check(
            "user:bob", "review", "claim:102",
            context={"amount": 2000, "max_amount": 5000},
        )
        is True
    )
    await storage.close()


async def test_runtime_context_supplements_static_context(sqlite_client):
    seen_context = {}

    def custom_checker(*, subject, resource, **ctx):
        seen_context.update(ctx)
        return ctx.get("env") == "prod" and ctx.get("role_level") >= 3

    sqlite_client.register_condition("custom_check", custom_checker)
    sqlite_client.register_schema(Namespace("server", {"admin": Direct()}))

    # Static context provides env="prod"
    await sqlite_client.write(
        [
            RelationTuple(
                "server",
                "srv1",
                "admin",
                "user:charlie",
                condition=Condition("custom_check", {"env": "prod"}),
            )
        ]
    )

    # Runtime context supplements role_level=3
    allowed = await sqlite_client.check(
        "user:charlie",
        "admin",
        "server:srv1",
        context={"role_level": 3, "ip": "10.0.0.1"},
    )
    assert allowed is True
    assert seen_context["env"] == "prod"
    assert seen_context["role_level"] == 3
    assert seen_context["ip"] == "10.0.0.1"


async def test_runtime_context_through_relations(sqlite_client):
    sqlite_client.register_schema(
        Namespace("folder", {"viewer": Direct()}),
        Namespace(
            "doc",
            {
                "parent": Direct(),
                "viewer": UnionRule(Direct(), TupleToUserset("parent", "viewer")),
            },
        ),
    )
    await sqlite_client.write(
        [
            RelationTuple(
                "folder",
                "f1",
                "viewer",
                "user:dave",
                condition=Condition("jurisdiction_match", {"allowed_jurisdictions": ["US", "CA"]}),
            ),
            RelationTuple("doc", "d1", "parent", "folder:f1"),
        ]
    )

    # Checking doc:d1 walks into folder:f1 and applies runtime context jurisdiction
    assert (
        await sqlite_client.check(
            "user:dave", "viewer", "doc:d1", context={"jurisdiction": "US"}
        )
        is True
    )
    assert (
        await sqlite_client.check(
            "user:dave", "viewer", "doc:d1", context={"jurisdiction": "EU"}
        )
        is False
    )


# -----------------------------------------------------------------------------
# 2. Audit Trail & Policy Explanation (EvaluationDecision & Client.explain)
# -----------------------------------------------------------------------------


async def test_explain_direct_grant_allowed(sqlite_client):
    sqlite_client.register_schema(Namespace("claim", {"viewer": Direct()}))
    t = RelationTuple("claim", "1", "viewer", "user:alice")
    await sqlite_client.write([t])

    decision = await sqlite_client.explain("user:alice", "viewer", "claim:1")

    assert isinstance(decision, EvaluationDecision)
    assert decision.allowed is True
    assert decision.subject == "user:alice"
    assert decision.permission == "viewer"
    assert decision.resource == "claim:1"
    assert decision.matched_tuples == (t,)
    assert decision.visited_path == ("claim:1#viewer",)
    assert "Allowed via user:alice -> claim:1#viewer" in decision.reason


async def test_explain_denied_grant(sqlite_client):
    sqlite_client.register_schema(Namespace("claim", {"viewer": Direct()}))
    decision = await sqlite_client.explain("user:mallory", "viewer", "claim:1")

    assert decision.allowed is False
    assert decision.subject == "user:mallory"
    assert decision.permission == "viewer"
    assert decision.resource == "claim:1"
    assert decision.matched_tuples == ()
    assert decision.visited_path == ("claim:1#viewer",)
    assert (
        decision.reason
        == "Denied: no matching relation or condition failed for user:mallory on claim:1#viewer"
    )


async def test_explain_records_condition_results(sqlite_client):
    sqlite_client.register_schema(Namespace("claim", {"settle": Direct()}))
    t = RelationTuple(
        "claim",
        "42",
        "settle",
        "user:bob",
        condition=Condition("max_amount", {"max_amount": 1000}),
    )
    await sqlite_client.write([t])

    # Case 1: condition passes
    dec_pass = await sqlite_client.explain(
        "user:bob", "settle", "claim:42", context={"amount": 500}
    )
    assert dec_pass.allowed is True
    assert dec_pass.condition_results == (("max_amount", True),)
    assert dec_pass.matched_tuples == (t,)

    # Case 2: condition fails
    dec_fail = await sqlite_client.explain(
        "user:bob", "settle", "claim:42", context={"amount": 1500}
    )
    assert dec_fail.allowed is False
    assert dec_fail.condition_results == (("max_amount", False),)
    assert dec_fail.matched_tuples == ()
    assert "Denied" in dec_fail.reason


async def test_explain_userset_traversal_chain(sqlite_client):
    sqlite_client.register_schema(
        Namespace("group", {"member": Direct()}),
        Namespace("claim", {"viewer": Direct()}),
    )
    t_group = RelationTuple("group", "adjusters", "member", "user:carol")
    t_claim = RelationTuple("claim", "99", "viewer", "group:adjusters#member")
    await sqlite_client.write([t_group, t_claim])

    decision = await sqlite_client.explain("user:carol", "viewer", "claim:99")
    assert decision.allowed is True
    assert decision.matched_tuples == (t_group, t_claim)
    assert "claim:99#viewer" in decision.visited_path
    assert "group:adjusters#member" in decision.visited_path
    assert (
        decision.reason
        == "Allowed via user:carol -> group:adjusters#member -> claim:99#viewer"
    )


# -----------------------------------------------------------------------------
# 3. Batch Permission Checks with Ephemeral Read Caching
# -----------------------------------------------------------------------------


async def test_check_batch_preserves_order_and_results(sqlite_client):
    sqlite_client.register_schema(
        Namespace("claim", {"viewer": Direct(), "editor": Direct()})
    )
    await sqlite_client.write(
        [
            RelationTuple("claim", "c1", "viewer", "user:alice"),
            RelationTuple("claim", "c1", "editor", "user:bob"),
            RelationTuple("claim", "c2", "viewer", "user:alice"),
        ]
    )

    checks = [
        CheckItem("user:alice", "viewer", "claim:c1"),
        CheckItem("user:alice", "editor", "claim:c1"),
        CheckItem("user:bob", "viewer", "claim:c1"),
        CheckItem("user:bob", "editor", "claim:c1"),
        CheckItem("user:alice", "viewer", "claim:c2"),
        CheckItem("user:bob", "viewer", "claim:c2"),
    ]

    results = await sqlite_client.check_batch(checks)
    assert results == [True, False, False, True, True, False]


async def test_check_batch_uses_ephemeral_cache(sqlite_client):
    sqlite_client.register_schema(Namespace("doc", {"viewer": Direct()}))
    await sqlite_client.write([RelationTuple("doc", "doc1", "viewer", "user:alice")])

    read_calls = 0
    orig_read_tuples = sqlite_client._storage.read_tuples

    async def counting_read_tuples(*args, **kwargs):
        nonlocal read_calls
        read_calls += 1
        return await orig_read_tuples(*args, **kwargs)

    sqlite_client._storage.read_tuples = counting_read_tuples

    # 10 checks for different users against the same doc1#viewer
    checks = [CheckItem(f"user:user_{i}", "viewer", "doc:doc1") for i in range(10)]
    results = await sqlite_client.check_batch(checks)

    # Should only read doc:doc1 viewer tuples from storage once!
    assert read_calls == 1
    assert len(results) == 10
    assert results[0] is False  # user_0 is not alice


# -----------------------------------------------------------------------------
# 4. Introspection (list_permissions & list_objects)
# -----------------------------------------------------------------------------


async def test_list_permissions(sqlite_client):
    sqlite_client.register_schema(
        Namespace(
            "claim",
            {
                "viewer": Direct(),
                "editor": Direct(),
                "auditor": Direct(),
            },
        )
    )
    await sqlite_client.write(
        [
            RelationTuple("claim", "10", "viewer", "user:alice"),
            RelationTuple("claim", "10", "auditor", "user:alice"),
            RelationTuple("claim", "10", "editor", "user:bob"),
        ]
    )

    # All permissions for alice on claim:10
    alice_perms = await sqlite_client.list_permissions("user:alice", "claim:10")
    assert sorted(alice_perms) == ["auditor", "viewer"]

    # Filtered candidate permissions
    filtered = await sqlite_client.list_permissions(
        "user:alice", "claim:10", permissions=["editor", "auditor"]
    )
    assert filtered == ["auditor"]

    bob_perms = await sqlite_client.list_permissions("user:bob", "claim:10")
    assert bob_perms == ["editor"]


async def test_list_objects_discovered_and_candidate(sqlite_client):
    sqlite_client.register_schema(
        Namespace("claim", {"viewer": Direct(), "approver": Direct()})
    )
    await sqlite_client.write(
        [
            RelationTuple("claim", "1", "viewer", "user:alice"),
            RelationTuple("claim", "2", "viewer", "user:alice"),
            RelationTuple("claim", "3", "viewer", "user:bob"),
            RelationTuple("claim", "4", "viewer", "user:alice"),
            RelationTuple("claim", "1", "approver", "user:alice"),
        ]
    )

    # Discover unique object IDs automatically from namespace
    viewable = await sqlite_client.list_objects("user:alice", "viewer", "claim")
    assert viewable == ["1", "2", "4"]

    # Explicit candidate list
    filtered = await sqlite_client.list_objects(
        "user:alice", "viewer", "claim", candidate_ids=["2", "3", "4", "5"]
    )
    assert filtered == ["2", "4"]

    # Approver
    approvable = await sqlite_client.list_objects("user:alice", "approver", "claim")
    assert approvable == ["1"]


async def test_list_objects_with_runtime_context(sqlite_client):
    sqlite_client.register_schema(Namespace("claim", {"pay": Direct()}))
    await sqlite_client.write(
        [
            RelationTuple(
                "claim",
                "c1",
                "pay",
                "user:finance",
                condition=Condition("max_amount", {"max_amount": 5000}),
            ),
            RelationTuple(
                "claim",
                "c2",
                "pay",
                "user:finance",
                condition=Condition("max_amount", {"max_amount": 10000}),
            ),
        ]
    )

    # amount 4000 can pay both
    res_4000 = await sqlite_client.list_objects(
        "user:finance", "pay", "claim", context={"amount": 4000}
    )
    assert res_4000 == ["c1", "c2"]

    # amount 7000 can only pay c2
    res_7000 = await sqlite_client.list_objects(
        "user:finance", "pay", "claim", context={"amount": 7000}
    )
    assert res_7000 == ["c2"]


# -----------------------------------------------------------------------------
# 5. Built-in ABAC Condition Predicates
# -----------------------------------------------------------------------------


def test_builtin_predicates():
    builtins = builtin_conditions()

    # max_amount
    max_fn = builtins["max_amount"]
    assert max_fn(subject="u", resource="r", amount=100, max_amount=150) is True
    assert max_fn(subject="u", resource="r", amount=150, max_amount=150) is True
    assert max_fn(subject="u", resource="r", amount=200, max_amount=150) is False

    # min_amount
    min_fn = builtins["min_amount"]
    assert min_fn(subject="u", resource="r", amount=100, min_amount=50) is True
    assert min_fn(subject="u", resource="r", amount=50, min_amount=50) is True
    assert min_fn(subject="u", resource="r", amount=25, min_amount=50) is False

    # equals_attr
    eq_fn = builtins["equals_attr"]
    assert (
        eq_fn(
            subject="u",
            resource="r",
            attribute="tier",
            tier="gold",
            expected="gold",
        )
        is True
    )
    assert (
        eq_fn(
            subject="u",
            resource="r",
            attribute="tier",
            tier="silver",
            expected="gold",
        )
        is False
    )

    # in_set
    inset_fn = builtins["in_set"]
    assert (
        inset_fn(
            subject="u",
            resource="r",
            attribute="status",
            status="pending",
            allowed_values=["draft", "pending"],
        )
        is True
    )
    assert (
        inset_fn(
            subject="u",
            resource="r",
            attribute="status",
            status="approved",
            allowed_values=["draft", "pending"],
        )
        is False
    )

    # jurisdiction_match
    jur_fn = builtins["jurisdiction_match"]
    assert (
        jur_fn(
            subject="u",
            resource="r",
            jurisdiction="US",
            allowed_jurisdictions=["US", "CA"],
        )
        is True
    )
    assert (
        jur_fn(
            subject="u",
            resource="r",
            jurisdiction="UK",
            allowed_jurisdictions=["US", "CA"],
        )
        is False
    )
    assert (
        jur_fn(
            subject="u",
            resource="r",
            jurisdiction="US",
            required_jurisdiction="US",
        )
        is True
    )
    assert (
        jur_fn(
            subject="u",
            resource="r",
            jurisdiction="CA",
            required_jurisdiction="US",
        )
        is False
    )
    assert jur_fn(subject="u", resource="r") is None

    # not_same_subject
    nss_fn = builtins["not_same_subject"]
    assert (
        nss_fn(subject="user:alice", resource="r", excluded_subject="user:bob") is True
    )
    assert (
        nss_fn(subject="user:alice", resource="r", excluded_subject="user:alice")
        is False
    )


def test_with_builtins_with_extra():
    evaluator = PythonCallableEvaluator.with_builtins(
        extra={"custom_rule": lambda **_: True}
    )
    assert evaluator.is_registered("max_amount") is True
    assert evaluator.is_registered("not_same_subject") is True
    assert evaluator.is_registered("custom_rule") is True


# -----------------------------------------------------------------------------
# 6. FastAPI Integration: requires with get_context, headers/query, explain_access
# -----------------------------------------------------------------------------


def test_fastapi_requires_with_runtime_context(sqlite_client):
    sqlite_client.register_schema(Namespace("claim", {"review": Direct()}))

    async def init_data():
        await sqlite_client.write(
            [
                RelationTuple(
                    "claim",
                    "100",
                    "review",
                    "user:auditor",
                    condition=Condition("max_amount", {"max_amount": 1000}),
                )
            ]
        )

    import asyncio

    asyncio.run(init_data())

    app = FastAPI()

    async def get_client():
        return sqlite_client

    async def get_subject():
        return "user:auditor"

    async def get_context(request: Request):
        amount = float(request.query_params.get("amount", 0))
        return {"amount": amount}

    @app.get("/claims/{claim_id}")
    async def view_claim(
        claim_id: str,
        _: None = Depends(
            requires(
                "review",
                "claim:{claim_id}",
                get_client=get_client,
                get_subject=get_subject,
                get_context=get_context,
            )
        ),
    ):
        return {"status": "ok", "claim_id": claim_id}

    test_client = TestClient(app)

    # Within limit -> 200
    res_ok = test_client.get("/claims/100?amount=500")
    assert res_ok.status_code == 200

    # Exceeds limit -> 403
    res_denied = test_client.get("/claims/100?amount=1500")
    assert res_denied.status_code == 403


def test_fastapi_resolve_resource_from_query_and_headers(sqlite_client):
    sqlite_client.register_schema(Namespace("report", {"read": Direct()}))

    async def init():
        await sqlite_client.write(
            [RelationTuple("report", "q_rep", "read", "user:analyst")]
        )

    import asyncio

    asyncio.run(init())

    app = FastAPI()

    async def get_client():
        return sqlite_client

    async def get_subject():
        return "user:analyst"

    # Resource template uses {rep_id} which comes from query param
    @app.get("/report/by-query")
    async def report_query(
        _: None = Depends(
            requires(
                "read",
                "report:{rep_id}",
                get_client=get_client,
                get_subject=get_subject,
                resource_sources=("query",),
            )
        ),
    ):
        return {"loaded": True}

    # Resource template uses {x_report_id} which comes from the x-report-id header
    @app.get("/report/by-header")
    async def report_header(
        _: None = Depends(
            requires(
                "read",
                "report:{x_report_id}",
                get_client=get_client,
                get_subject=get_subject,
                resource_sources=("header",),
            )
        ),
    ):
        return {"loaded": True}

    client = TestClient(app)

    # Query param matches
    res_q = client.get("/report/by-query?rep_id=q_rep")
    assert res_q.status_code == 200

    # Header matches
    res_h = client.get("/report/by-header", headers={"x-report-id": "q_rep"})
    assert res_h.status_code == 200


def test_fastapi_explain_access(sqlite_client):
    sqlite_client.register_schema(Namespace("claim", {"payout": Direct()}))

    async def init():
        await sqlite_client.write(
            [
                RelationTuple(
                    "claim",
                    "c77",
                    "payout",
                    "user:mgr",
                    condition=Condition("max_amount", {"max_amount": 50000}),
                )
            ]
        )

    import asyncio

    asyncio.run(init())

    app = FastAPI()

    async def get_client():
        return sqlite_client

    async def get_subject(request: Request):
        return request.headers.get("x-user", "user:mgr")

    def get_context(request: Request):
        return {"amount": float(request.query_params.get("amount", 0))}

    @app.get("/claims/{claim_id}/payout")
    async def payout(
        claim_id: str,
        request: Request,
        decision: EvaluationDecision = Depends(
            explain_access(
                "payout",
                "claim:{claim_id}",
                get_client=get_client,
                get_subject=get_subject,
                get_context=get_context,
                detail="Not permitted to payout claim",
            )
        ),
    ):
        # request.state.authz_decision should also be populated
        assert request.state.authz_decision is decision
        return {
            "allowed": decision.allowed,
            "reason": decision.reason,
            "claim_id": claim_id,
        }

    client = TestClient(app)

    # 1. Allowed request
    resp_ok = client.get("/claims/c77/payout?amount=10000")
    assert resp_ok.status_code == 200
    data = resp_ok.json()
    assert data["allowed"] is True
    assert "Allowed via" in data["reason"]

    # 2. Denied request due to amount
    resp_denied = client.get("/claims/c77/payout?amount=60000")
    assert resp_denied.status_code == 403
    assert resp_denied.json()["detail"] == "Not permitted to payout claim"

    # 3. Denied request due to unauthorized user
    resp_unauth = client.get(
        "/claims/c77/payout?amount=100", headers={"x-user": "user:stranger"}
    )
    assert resp_unauth.status_code == 403
