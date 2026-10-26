class AuthError(Exception):
    """Base class for all authz errors."""


class NamespaceNotFound(AuthError):
    def __init__(self, namespace: str):
        super().__init__(f"namespace {namespace!r} is not registered")
        self.namespace = namespace


class RelationNotFound(AuthError):
    def __init__(self, namespace: str, relation: str):
        super().__init__(
            f"relation {relation!r} is not defined on namespace {namespace!r}"
        )
        self.namespace = namespace
        self.relation = relation


class ConditionNotFound(AuthError):
    def __init__(self, name: str):
        super().__init__(f"condition {name!r} is not registered")
        self.name = name


class SchemaCycleDetected(AuthError):
    def __init__(self, namespace: str, path: list[str]):
        super().__init__(
            f"schema cycle in namespace {namespace!r}: {' -> '.join(path)}"
        )
        self.namespace = namespace
        self.path = path


class WouldCreateCycle(AuthError):
    def __init__(self, tuple_, description: str):
        super().__init__(f"writing {tuple_} would create a cycle: {description}")
        self.tuple = tuple_


class CycleDetected(AuthError):
    def __init__(self, path: list[str]):
        super().__init__(f"cycle detected during check: {' -> '.join(path)}")
        self.path = path


class DepthLimitExceeded(AuthError):
    def __init__(self, max_depth: int):
        super().__init__(f"recursion exceeded max_depth={max_depth}")
        self.max_depth = max_depth


class EvaluationBudgetExceeded(AuthError):
    def __init__(self, max_evaluations: int):
        super().__init__(f"evaluation exceeded max_evaluations={max_evaluations}")
        self.max_evaluations = max_evaluations


class CardinalityViolationError(AuthError):
    """Raised when writing a tuple would exceed a relation's max_subjects limit (e.g. singleton org_admin)."""

    def __init__(
        self,
        namespace: str,
        object_id: str,
        relation: str,
        max_subjects: int,
        existing_subjects: tuple[str, ...],
        attempted_subject: str,
    ) -> None:
        self.namespace = namespace
        self.object_id = object_id
        self.relation = relation
        self.max_subjects = max_subjects
        self.existing_subjects = existing_subjects
        self.attempted_subject = attempted_subject
        super().__init__(
            f"Cardinality violation on {namespace}:{object_id}#{relation}: "
            f"max_subjects={max_subjects}, existing={list(existing_subjects)}, "
            f"attempted={attempted_subject!r}"
        )
