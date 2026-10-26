import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from authz import Client, PythonCallableEvaluator, SqliteStorage

from examples.sample_app import domain
from examples.sample_app.auth import ADMIN_USERS, get_current_user, require_admin
from examples.sample_app.main import app
from examples.sample_app.schema import ALL_NAMESPACES
from examples.sample_app.seed import seed


def test_schema_has_no_cycles():
    from authz.schema import check_schema_cycles

    for ns in ALL_NAMESPACES:
        check_schema_cycles(ns)  # must not raise


async def test_get_current_user_returns_formatted_subject():
    subject = await get_current_user(x_user_id="alice")
    assert subject == "user:alice"


async def test_get_current_user_raises_401_when_header_missing():
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(x_user_id=None)
    assert exc_info.value.status_code == 401


async def test_require_admin_allows_admin_user():
    await require_admin(subject="user:alice")  # must not raise
    assert "user:alice" in ADMIN_USERS


async def test_require_admin_denies_non_admin_user():
    with pytest.raises(HTTPException) as exc_info:
        await require_admin(subject="user:bob")
    assert exc_info.value.status_code == 403


def is_active_contract(*, subject, resource, active):
    return active


@pytest.fixture
async def seeded_client():
    domain.projects.clear()
    domain.tasks.clear()
    storage = SqliteStorage(":memory:")
    await storage.connect()
    client = Client(storage=storage, condition_evaluator=PythonCallableEvaluator())
    client.register_schema(*ALL_NAMESPACES)
    client.register_condition("is_active_contract", is_active_contract)
    await seed(client)
    yield client
    await storage.close()


async def test_seed_populates_domain_data(seeded_client):
    assert "p1" in domain.projects
    assert "t1" in domain.tasks
    assert domain.tasks["t1"].assignee == "user:bob"


async def test_seed_grants_alice_project_ownership(seeded_client):
    assert await seeded_client.check("user:alice", "owner", "project:p1") is True


async def test_seed_grants_bob_task_editor_via_assignee(seeded_client):
    assert await seeded_client.check("user:bob", "editor", "task:t1") is True


async def test_seed_carol_has_conditional_editor_access(seeded_client):
    assert await seeded_client.check("user:carol", "editor", "project:p1") is True


@pytest.fixture
def app_client():
    domain.projects.clear()
    domain.tasks.clear()
    with TestClient(app) as c:
        yield c


def test_owner_can_view_their_project(app_client):
    response = app_client.get("/projects/p1", headers={"X-User-Id": "alice"})
    assert response.status_code == 200
    assert response.json()["id"] == "p1"


def test_unrelated_user_cannot_view_project(app_client):
    response = app_client.get("/projects/p1", headers={"X-User-Id": "mallory"})
    assert response.status_code == 403


def test_missing_header_returns_401(app_client):
    response = app_client.get("/projects/p1")
    assert response.status_code == 401


def test_assignee_can_view_their_task(app_client):
    response = app_client.get("/tasks/t1", headers={"X-User-Id": "bob"})
    assert response.status_code == 200
    assert response.json()["id"] == "t1"


def test_unrelated_user_cannot_create_task(app_client):
    response = app_client.post(
        "/projects/p1/tasks",
        headers={"X-User-Id": "bob"},
        json={"title": "New task"},
    )
    assert response.status_code == 403


def test_admin_can_check_permissions(app_client):
    response = app_client.post(
        "/authz/check",
        headers={"X-User-Id": "alice"},
        json={"subject": "user:bob", "permission": "editor", "resource": "project:p1"},
    )
    assert response.status_code == 200
    assert response.json() == {"allowed": False}


def test_non_admin_cannot_use_authz_endpoints(app_client):
    response = app_client.post(
        "/authz/check",
        headers={"X-User-Id": "bob"},
        json={"subject": "user:bob", "permission": "editor", "resource": "project:p1"},
    )
    assert response.status_code == 403


def test_unauthenticated_cannot_use_authz_endpoints(app_client):
    response = app_client.post(
        "/authz/check",
        json={"subject": "user:bob", "permission": "editor", "resource": "project:p1"},
    )
    assert response.status_code == 401


def test_admin_can_expand_a_permission(app_client):
    response = app_client.post(
        "/authz/expand",
        headers={"X-User-Id": "alice"},
        json={"permission": "owner", "resource": "project:p1"},
    )
    assert response.status_code == 200
    assert "user:alice" in response.json()["direct_subjects"]


def test_deny_then_admin_grants_then_retry_succeeds(app_client):
    # bob is denied project-level editor -> cannot create a task.
    denied = app_client.post(
        "/projects/p1/tasks",
        headers={"X-User-Id": "bob"},
        json={"title": "New task"},
    )
    assert denied.status_code == 403

    # alice (admin) grants bob editor on the project via the raw authz API.
    write_response = app_client.post(
        "/authz/write",
        headers={"X-User-Id": "alice"},
        json={
            "tuples": [
                {
                    "namespace": "project",
                    "object_id": "p1",
                    "relation": "editor",
                    "subject": "user:bob",
                }
            ]
        },
    )
    assert write_response.status_code == 200

    # bob retries the exact same request -- now succeeds.
    allowed = app_client.post(
        "/projects/p1/tasks",
        headers={"X-User-Id": "bob"},
        json={"title": "New task"},
    )
    assert allowed.status_code == 201
    assert allowed.json()["title"] == "New task"


def test_contractor_access_follows_active_contract_flag(app_client):
    # carol's seeded grant has active=True -> allowed.
    allowed = app_client.post(
        "/authz/check",
        headers={"X-User-Id": "alice"},
        json={"subject": "user:carol", "permission": "editor", "resource": "project:p1"},
    )
    assert allowed.json() == {"allowed": True}

    # alice flips the SAME tuple's condition to active=False by re-writing
    # it -- write_tuples upserts on (namespace, object_id, relation, subject).
    app_client.post(
        "/authz/write",
        headers={"X-User-Id": "alice"},
        json={
            "tuples": [
                {
                    "namespace": "project",
                    "object_id": "p1",
                    "relation": "editor",
                    "subject": "user:carol",
                    "condition_name": "is_active_contract",
                    "condition_context": {"active": False},
                }
            ]
        },
    )

    denied = app_client.post(
        "/authz/check",
        headers={"X-User-Id": "alice"},
        json={"subject": "user:carol", "permission": "editor", "resource": "project:p1"},
    )
    assert denied.json() == {"allowed": False}


def test_admin_write_with_invalid_identifier_is_422(app_client):
    response = app_client.post(
        "/authz/write",
        headers={"X-User-Id": "alice"},
        json={
            "tuples": [
                {
                    "namespace": "project",
                    "object_id": "p 1",
                    "relation": "editor",
                    "subject": "user:bob",
                }
            ]
        },
    )
    assert response.status_code == 422
    assert "whitespace" in response.json()["detail"]


def test_admin_check_with_invalid_resource_is_422(app_client):
    response = app_client.post(
        "/authz/check",
        headers={"X-User-Id": "alice"},
        json={"subject": "user:bob", "permission": "editor", "resource": "project:"},
    )
    assert response.status_code == 422
