import pytest

from authz.errors import (
    AuthError,
    CardinalityViolationError,
    ConditionNotFound,
    CycleDetected,
    DepthLimitExceeded,
    EvaluationBudgetExceeded,
    NamespaceNotFound,
    RelationNotFound,
    SchemaCycleDetected,
    WouldCreateCycle,
)


@pytest.mark.parametrize(
    "exc_type",
    [
        NamespaceNotFound,
        RelationNotFound,
        ConditionNotFound,
        SchemaCycleDetected,
        WouldCreateCycle,
        CycleDetected,
        DepthLimitExceeded,
        EvaluationBudgetExceeded,
        CardinalityViolationError,
    ],
)
def test_all_errors_are_auth_errors(exc_type):
    assert issubclass(exc_type, AuthError)


def test_namespace_not_found_message():
    err = NamespaceNotFound("document")
    assert err.namespace == "document"
    assert "document" in str(err)


def test_relation_not_found_message():
    err = RelationNotFound("document", "editor")
    assert err.namespace == "document"
    assert err.relation == "editor"
    assert "editor" in str(err)
    assert "document" in str(err)


def test_condition_not_found_message():
    err = ConditionNotFound("business_hours")
    assert err.name == "business_hours"
    assert "business_hours" in str(err)


def test_schema_cycle_detected_message():
    err = SchemaCycleDetected("document", ["viewer", "editor", "viewer"])
    assert err.namespace == "document"
    assert err.path == ["viewer", "editor", "viewer"]
    assert "viewer" in str(err)


def test_would_create_cycle_message():
    err = WouldCreateCycle("folder:A -> parent -> folder:B", "folder:B -> folder:A")
    assert "folder:B -> folder:A" in str(err)


def test_cycle_detected_message():
    err = CycleDetected(["folder:A#viewer", "folder:B#viewer", "folder:A#viewer"])
    assert err.path[0] == "folder:A#viewer"
    assert "folder:A#viewer" in str(err)


def test_depth_limit_exceeded_message():
    err = DepthLimitExceeded(25)
    assert err.max_depth == 25
    assert "25" in str(err)


def test_cardinality_violation_error_message():
    err = CardinalityViolationError(
        namespace="org",
        object_id="acme",
        relation="org_admin",
        max_subjects=1,
        existing_subjects=("user:alice",),
        attempted_subject="user:bob",
    )
    assert err.namespace == "org"
    assert err.object_id == "acme"
    assert err.relation == "org_admin"
    assert err.max_subjects == 1
    assert err.existing_subjects == ("user:alice",)
    assert err.attempted_subject == "user:bob"
    msg = str(err)
    assert "org:acme#org_admin" in msg
    assert "max_subjects=1" in msg
    assert "existing=['user:alice']" in msg
    assert "attempted='user:bob'" in msg


def test_evaluation_budget_exceeded_message():
    err = EvaluationBudgetExceeded(10_000)
    assert err.max_evaluations == 10_000
    assert "10000" in str(err)
