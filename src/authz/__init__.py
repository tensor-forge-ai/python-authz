from typing import TYPE_CHECKING, Any

from authz.conditions import (
    ConditionEvaluator,
    PythonCallableEvaluator,
    builtin_conditions,
)
from authz.engine import CheckItem, Client, EvaluationDecision, UsersetTree
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
from authz.schema import (
    Direct,
    Exclusion,
    From,
    Intersection,
    Namespace,
    RewriteRule,
    TupleToUserset,
    Union,
    build_role_hierarchy,
)
from authz.storage.base import Storage, Token
from authz.storage.sqlite import SqliteStorage
from authz.tuples import Condition, ObjectRef, RelationTuple, SubjectRef

if TYPE_CHECKING:
    from authz.storage.postgres import PostgresStorage

__all__ = [
    "AuthError",
    "CardinalityViolationError",
    "CheckItem",
    "Client",
    "Condition",
    "ConditionEvaluator",
    "ConditionNotFound",
    "CycleDetected",
    "DepthLimitExceeded",
    "Direct",
    "EvaluationBudgetExceeded",
    "EvaluationDecision",
    "Exclusion",
    "From",
    "Intersection",
    "Namespace",
    "NamespaceNotFound",
    "ObjectRef",
    "PythonCallableEvaluator",
    "RelationNotFound",
    "RelationTuple",
    "RewriteRule",
    "SchemaCycleDetected",
    "SqliteStorage",
    "Storage",
    "SubjectRef",
    "Token",
    "TupleToUserset",
    "Union",
    "UsersetTree",
    "WouldCreateCycle",
    "build_role_hierarchy",
    "builtin_conditions",
]


def __getattr__(name: str) -> Any:
    if name == "PostgresStorage":
        try:
            from authz.storage.postgres import PostgresStorage
        except ImportError as exc:
            raise ImportError(
                "PostgresStorage requires asyncpg; install it with "
                "'pip install python-authz[postgres]'"
            ) from exc
        return PostgresStorage
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
