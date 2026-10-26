import inspect
import math
from typing import Any, Awaitable, Callable, Mapping, Protocol, Union

from authz.errors import ConditionNotFound

ConditionResult = Union[bool, None]
ConditionFn = Callable[..., Union[ConditionResult, Awaitable[ConditionResult]]]

_RESERVED_KEYS = frozenset({"subject", "resource"})


class ConditionEvaluator(Protocol):
    def is_registered(self, name: str) -> bool: ...

    async def evaluate(
        self, name: str, subject: str, resource: str, context: Mapping[str, Any]
    ) -> bool | None: ...  # None: required context missing or invalid


class PythonCallableEvaluator:
    def __init__(self) -> None:
        self._conditions: dict[str, ConditionFn] = {}

    @classmethod
    def with_builtins(
        cls, extra: Mapping[str, ConditionFn] | None = None
    ) -> "PythonCallableEvaluator":
        evaluator = cls()
        for name, fn in builtin_conditions().items():
            evaluator.register(name, fn)
        if extra:
            for name, fn in extra.items():
                evaluator.register(name, fn)
        return evaluator

    def register(self, name: str, fn: ConditionFn) -> None:
        self._conditions[name] = fn

    def is_registered(self, name: str) -> bool:
        return name in self._conditions

    async def evaluate(
        self, name: str, subject: str, resource: str, context: Mapping[str, Any]
    ) -> bool | None:
        try:
            fn = self._conditions[name]
        except KeyError:
            raise ConditionNotFound(name) from None
        for key in context:
            if not isinstance(key, str):
                raise ValueError(
                    f"condition {name!r}: context keys must be strings, got {key!r}"
                )
            if key in _RESERVED_KEYS:
                raise ValueError(
                    f"condition {name!r}: context key {key!r} is reserved"
                )
        result = fn(subject=subject, resource=resource, **context)
        if inspect.isawaitable(result):
            result = await result
        if result is None or isinstance(result, bool):
            return result
        raise TypeError(
            f"condition {name!r} must return True, False or None, "
            f"got {type(result).__name__}"
        )


def _number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (ValueError, TypeError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _collection(value: Any) -> Any:
    return value if isinstance(value, (list, tuple, set, frozenset)) else None


def _attribute(ctx: Mapping[str, Any]) -> Any:
    name = ctx.get("attribute")
    if not isinstance(name, str) or not name:
        return None
    return ctx.get(name)


def _member(value: Any, allowed: Any) -> bool | None:
    try:
        return value in allowed
    except TypeError:
        return None


def _max_amount(*, subject: str, resource: str, **ctx: Any) -> bool | None:
    amount, limit = _number(ctx.get("amount")), _number(ctx.get("max_amount"))
    if amount is None or limit is None:
        return None
    return amount <= limit


def _min_amount(*, subject: str, resource: str, **ctx: Any) -> bool | None:
    amount, limit = _number(ctx.get("amount")), _number(ctx.get("min_amount"))
    if amount is None or limit is None:
        return None
    return amount >= limit


def _equals_attr(*, subject: str, resource: str, **ctx: Any) -> bool | None:
    actual, expected = _attribute(ctx), ctx.get("expected")
    if actual is None or expected is None:
        return None
    return actual == expected


def _in_set(*, subject: str, resource: str, **ctx: Any) -> bool | None:
    actual, allowed = _attribute(ctx), _collection(ctx.get("allowed_values"))
    if actual is None or allowed is None:
        return None
    return _member(actual, allowed)


def _jurisdiction_match(*, subject: str, resource: str, **ctx: Any) -> bool | None:
    jurisdiction = ctx.get("jurisdiction")
    if jurisdiction is None:
        return None
    allowed, required = ctx.get("allowed_jurisdictions"), ctx.get("required_jurisdiction")
    if allowed is None and required is None:
        return None
    results = []
    if allowed is not None:
        allowed = _collection(allowed)
        results.append(None if allowed is None else _member(jurisdiction, allowed))
    if required is not None:
        results.append(jurisdiction == required)
    if False in results:
        return False
    return None if None in results else True


def _not_same_subject(*, subject: str, resource: str, **ctx: Any) -> bool | None:
    excluded = ctx.get("excluded_subject")
    if not isinstance(excluded, str) or not excluded:
        return None
    return subject != excluded


def builtin_conditions() -> dict[str, ConditionFn]:
    return {
        "max_amount": _max_amount,
        "min_amount": _min_amount,
        "equals_attr": _equals_attr,
        "in_set": _in_set,
        "jurisdiction_match": _jurisdiction_match,
        "not_same_subject": _not_same_subject,
    }
