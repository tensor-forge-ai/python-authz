import pytest

from authz.conditions import PythonCallableEvaluator
from authz.errors import ConditionNotFound


async def test_is_registered_reflects_register_calls():
    evaluator = PythonCallableEvaluator()
    assert evaluator.is_registered("business_hours") is False
    evaluator.register("business_hours", lambda **_: True)
    assert evaluator.is_registered("business_hours") is True


async def test_evaluate_calls_sync_callable_with_subject_resource_context():
    seen = {}

    def is_owner(*, subject, resource, owner):
        seen["subject"] = subject
        seen["resource"] = resource
        return subject == owner

    evaluator = PythonCallableEvaluator()
    evaluator.register("is_owner", is_owner)

    result = await evaluator.evaluate(
        "is_owner", "user:alice", "document:doc42", {"owner": "user:alice"}
    )
    assert result is True
    assert seen == {"subject": "user:alice", "resource": "document:doc42"}


async def test_evaluate_calls_async_callable():
    async def always_true(**_):
        return True

    evaluator = PythonCallableEvaluator()
    evaluator.register("always_true", always_true)

    result = await evaluator.evaluate("always_true", "user:alice", "document:doc42", {})
    assert result is True


@pytest.mark.parametrize("value", [[1, 2, 3], 1, "yes", object()])
async def test_evaluate_rejects_truthy_non_bool_result(value):
    evaluator = PythonCallableEvaluator()
    evaluator.register("returns_value", lambda **_: value)
    with pytest.raises(TypeError, match="returns_value"):
        await evaluator.evaluate("returns_value", "user:alice", "document:doc42", {})


@pytest.mark.parametrize("value", [True, False, None])
async def test_evaluate_passes_through_true_false_and_none(value):
    evaluator = PythonCallableEvaluator()
    evaluator.register("returns_value", lambda **_: value)
    result = await evaluator.evaluate("returns_value", "user:alice", "document:doc42", {})
    assert result is value


async def test_evaluate_passes_through_async_none():
    async def unknown(**_):
        return None

    evaluator = PythonCallableEvaluator()
    evaluator.register("unknown", unknown)
    assert await evaluator.evaluate("unknown", "user:alice", "document:doc42", {}) is None


@pytest.mark.parametrize("key", ["subject", "resource"])
async def test_evaluate_rejects_reserved_context_keys(key):
    evaluator = PythonCallableEvaluator()
    evaluator.register("always_true", lambda **_: True)
    with pytest.raises(ValueError, match=key):
        await evaluator.evaluate("always_true", "user:alice", "document:doc42", {key: "x"})


async def test_evaluate_rejects_non_string_context_keys():
    evaluator = PythonCallableEvaluator()
    evaluator.register("always_true", lambda **_: True)
    with pytest.raises(ValueError, match="strings"):
        await evaluator.evaluate("always_true", "user:alice", "document:doc42", {1: "x"})


async def test_evaluate_raises_condition_not_found_for_unregistered_name():
    evaluator = PythonCallableEvaluator()
    with pytest.raises(ConditionNotFound):
        await evaluator.evaluate("missing", "user:alice", "document:doc42", {})
