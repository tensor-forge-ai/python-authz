import functools

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from authz import (
    Client,
    Condition,
    Direct,
    Namespace,
    PythonCallableEvaluator,
    RelationTuple,
    SqliteStorage,
)
from authz.integrations.fastapi import explain_access, requires


@pytest.fixture
async def authz_client():
    storage = SqliteStorage(":memory:")
    await storage.connect()
    c = Client(storage=storage, condition_evaluator=PythonCallableEvaluator.with_builtins())
    c.register_schema(Namespace("document", {"viewer": Direct()}))
    await c.write(
        [
            RelationTuple("document", "doc42", "viewer", "user:alice"),
            RelationTuple(
                "document", "limited", "viewer", "user:alice",
                condition=Condition("max_amount", {"max_amount": 100}),
            ),
        ]
    )
    yield c
    await storage.close()


def make_app(authz_client, route, resource, *, explain=False, **kwargs):
    app = FastAPI()

    async def get_client():
        return authz_client

    async def get_subject():
        return "user:alice"

    guard = (explain_access if explain else requires)(
        "viewer", resource, get_client=get_client, get_subject=get_subject, **kwargs
    )

    @app.get(route)
    async def handler(request: Request, _=Depends(guard)):
        return dict(request.path_params)

    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("explain", [False, True])
def test_default_ignores_query_and_headers(authz_client, explain):
    http = make_app(authz_client, "/documents/{document_id}", "document:{document_id}", explain=explain)
    assert http.get("/documents/doc42?document_id=other").status_code == 200
    assert http.get("/documents/doc42", headers={"document_id": "other"}).status_code == 200
    assert http.get("/documents/other?document_id=doc42").status_code == 403


@pytest.mark.parametrize("explain", [False, True])
def test_placeholder_not_defined_by_the_route_is_400_not_500(authz_client, explain):
    http = make_app(authz_client, "/documents", "document:{doc}", explain=explain)
    assert http.get("/documents?doc=doc42").status_code == 400
    assert http.get("/documents", headers={"doc": "doc42"}).status_code == 400


def test_placeholder_from_query_requires_opt_in(authz_client):
    http = make_app(
        authz_client, "/documents", "document:{doc}", resource_sources=("query",)
    )
    assert http.get("/documents?doc=doc42").status_code == 200
    assert http.get("/documents?doc=nope").status_code == 403
    assert http.get("/documents").status_code == 400


def test_placeholder_from_header_uses_lowercase_name_with_underscores(authz_client):
    http = make_app(
        authz_client, "/documents", "document:{x_doc_id}", resource_sources=("header",)
    )
    assert http.get("/documents", headers={"X-Doc-Id": "doc42"}).status_code == 200
    assert http.get("/documents", headers={"x-doc-id": "nope"}).status_code == 403
    assert http.get("/documents").status_code == 400


def test_value_in_two_enabled_sources_must_agree(authz_client):
    http = make_app(
        authz_client,
        "/documents/{doc}",
        "document:{doc}",
        resource_sources=("path", "query", "header"),
    )
    assert http.get("/documents/doc42").status_code == 200
    assert http.get("/documents/doc42?doc=doc42").status_code == 200
    assert http.get("/documents/doc42?doc=other").status_code == 400
    assert http.get("/documents/doc42", headers={"doc": "other"}).status_code == 400
    assert http.get("/documents/other?doc=doc42").status_code == 400


def test_repeated_query_parameter_with_different_values_is_400(authz_client):
    http = make_app(
        authz_client, "/documents", "document:{doc}", resource_sources=("query",)
    )
    assert http.get("/documents?doc=doc42&doc=other").status_code == 400
    assert http.get("/documents?doc=doc42&doc=doc42").status_code == 200


@pytest.mark.parametrize("value", ["a%20b", "a%23b", "a%0Ab", "a%09b", "a%00b", "%20"])
def test_resolved_resource_failing_identifier_validation_is_400(authz_client, value):
    http = make_app(authz_client, "/documents/{doc}", "document:{doc}")
    assert http.get(f"/documents/{value}").status_code == 400


def test_empty_query_value_is_400(authz_client):
    http = make_app(
        authz_client, "/documents", "document:{doc}", resource_sources=("query",)
    )
    assert http.get("/documents?doc=").status_code == 400


def test_invalid_namespace_from_placeholder_is_400(authz_client):
    http = make_app(authz_client, "/r/{ns}/{doc}", "{ns}:{doc}")
    assert http.get("/r/document/doc42").status_code == 200
    assert http.get("/r/bad%20ns/doc42").status_code == 400
    assert http.get("/r/bad.ns/doc42").status_code == 400


def test_callable_resource_failing_validation_is_400(authz_client):
    http = make_app(authz_client, "/documents", lambda request: "document:a b")
    assert http.get("/documents").status_code == 400


@pytest.mark.parametrize(
    "template",
    [
        "document:{a.b}",
        "document:{a[0]}",
        "document:{a!r}",
        "document:{a:>5}",
        "document:{a!s:>5}",
        "document:{}",
        "document:{0}",
        "document:{x-y}",
        "document:{a.__class__}",
        "document:{a[b]}",
    ],
)
@pytest.mark.parametrize("factory", [requires, explain_access])
def test_templates_with_anything_but_bare_names_are_rejected_at_decoration(template, factory):
    with pytest.raises(ValueError, match="bare"):
        factory("viewer", template, get_client=lambda: None, get_subject=lambda: "user:a")


def test_bad_resource_sources_are_rejected_at_decoration():
    with pytest.raises(ValueError, match="unknown resource source"):
        requires(
            "viewer", "document:{a}", get_client=lambda: None, get_subject=lambda: "u",
            resource_sources=("cookie",),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="empty"):
        requires(
            "viewer", "document:{a}", get_client=lambda: None, get_subject=lambda: "u",
            resource_sources=(),
        )


def test_template_without_placeholders_is_allowed(authz_client):
    http = make_app(authz_client, "/documents", "document:doc42", resource_sources=())
    assert http.get("/documents").status_code == 200


def test_literal_braces_are_still_formatted_safely(authz_client):
    http = make_app(authz_client, "/documents/{doc}", "document:{doc}")
    assert http.get("/documents/%7Bdoc%7D").status_code == 403


# ---- get_context --------------------------------------------------------


def context_app(authz_client, get_context):
    return make_app(authz_client, "/limited", "document:limited", get_context=get_context)


def test_get_context_with_request_parameter_receives_the_request(authz_client):
    http = context_app(authz_client, lambda request: {"amount": int(request.query_params["amount"])})
    assert http.get("/limited?amount=50").status_code == 200
    assert http.get("/limited?amount=500").status_code == 403


def test_get_context_without_parameters_is_called_without_a_request(authz_client):
    http = context_app(authz_client, lambda: {"amount": 5})
    assert http.get("/limited").status_code == 200


def test_async_get_context_variants(authz_client):
    async def with_request(request: Request):
        return {"amount": 5}

    async def without_request():
        return {"amount": 500}

    assert context_app(authz_client, with_request).get("/limited").status_code == 200
    assert context_app(authz_client, without_request).get("/limited").status_code == 403


def test_get_context_callable_objects_and_partials(authz_client):
    class Ctx:
        def __call__(self, request):
            return {"amount": 5}

    def with_extra(extra, request):
        return {"amount": extra}

    assert context_app(authz_client, Ctx()).get("/limited").status_code == 200
    assert context_app(authz_client, functools.partial(with_extra, 500)).get("/limited").status_code == 403


def test_type_error_inside_get_context_is_not_swallowed_or_retried(authz_client):
    calls = []

    def buggy(request):
        calls.append(1)
        return {"amount": None + 1}

    app = FastAPI()

    async def get_client():
        return authz_client

    async def get_subject():
        return "user:alice"

    @app.get("/limited")
    async def handler(
        _=Depends(
            requires(
                "viewer", "document:limited",
                get_client=get_client, get_subject=get_subject, get_context=buggy,
            )
        ),
    ):
        return {}

    with pytest.raises(TypeError):
        TestClient(app).get("/limited")
    assert calls == [1]


def test_no_context_fallback_without_get_context(authz_client):
    http = make_app(authz_client, "/limited", "document:limited")
    assert http.get("/limited").status_code == 403
