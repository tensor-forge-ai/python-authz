from collections.abc import Iterable, Mapping, Sequence
from types import MappingProxyType
from typing import Iterator

from authz.errors import SchemaCycleDetected


class RewriteRule:
    """Base class for relation-rewrite expressions."""


class Direct(RewriteRule):
    def __repr__(self) -> str:
        return "Direct()"


class Union(RewriteRule):
    def __init__(self, *children: RewriteRule):
        self.children = children

    def __repr__(self) -> str:
        return f"Union{self.children!r}"


class Intersection(RewriteRule):
    def __init__(self, *children: RewriteRule):
        self.children = children

    def __repr__(self) -> str:
        return f"Intersection{self.children!r}"


class Exclusion(RewriteRule):
    def __init__(self, base: RewriteRule, subtract: RewriteRule):
        self.base = base
        self.subtract = subtract

    def __repr__(self) -> str:
        return f"Exclusion({self.base!r}, {self.subtract!r})"


class From(RewriteRule):
    def __init__(self, relation: str):
        self.relation = relation

    def __repr__(self) -> str:
        return f"From({self.relation!r})"


class TupleToUserset(RewriteRule):
    def __init__(self, tupleset_relation: str, computed_relation: str):
        self.tupleset_relation = tupleset_relation
        self.computed_relation = computed_relation

    def __repr__(self) -> str:
        return f"TupleToUserset({self.tupleset_relation!r}, {self.computed_relation!r})"


class Namespace:
    def __init__(
        self,
        name: str,
        relations: Mapping[str, RewriteRule],
        singleton_relations: Iterable[str] | None = None,
        max_subjects: Mapping[str, int] | None = None,
    ) -> None:
        self.name = name
        self.relations: Mapping[str, RewriteRule] = MappingProxyType(dict(relations))
        self.singleton_relations: frozenset[str] = (
            frozenset(singleton_relations) if singleton_relations is not None else frozenset()
        )
        self.max_subjects: Mapping[str, int] = MappingProxyType(
            dict(max_subjects) if max_subjects is not None else {}
        )

    def max_subjects_for(self, relation: str) -> int | None:
        if relation in self.singleton_relations:
            return 1
        return self.max_subjects.get(relation)


def build_role_hierarchy(
    roles_high_to_low: Sequence[str],
    *,
    extra_relations: Mapping[str, RewriteRule] | None = None,
) -> dict[str, RewriteRule]:
    """Build a role hierarchy with transitive downward inheritance and strict upward override relations.

    Given an ordered sequence of roles from highest to lowest (e.g. ['org_admin', 'org_manager', ...]):
    - Index 0 (top role): Direct() and override_<top_role> = From(<top_role>)
    - Index i > 0: Union(Direct(), From(<superior_role>)) and override_<role> = From(<superior_role>)
    - Merges any extra_relations provided.
    """
    if len(roles_high_to_low) != len(set(roles_high_to_low)):
        raise ValueError("Role hierarchy must not contain duplicate roles")

    relations: dict[str, RewriteRule] = {}
    for i, role in enumerate(roles_high_to_low):
        if i == 0:
            relations[role] = Direct()
            relations[f"override_{role}"] = From(role)
        else:
            superior_role = roles_high_to_low[i - 1]
            relations[role] = Union(Direct(), From(superior_role))
            relations[f"override_{role}"] = From(superior_role)

    if extra_relations is not None:
        relations.update(extra_relations)

    return relations


def _from_edges(rule: RewriteRule) -> Iterator[str]:
    if isinstance(rule, From):
        yield rule.relation
    elif isinstance(rule, (Union, Intersection)):
        for child in rule.children:
            yield from _from_edges(child)
    elif isinstance(rule, Exclusion):
        yield from _from_edges(rule.base)
        yield from _from_edges(rule.subtract)


def check_schema_cycles(namespace: Namespace) -> None:
    graph: dict[str, list[str]] = {
        relation: list(_from_edges(rule))
        for relation, rule in namespace.relations.items()
    }

    visiting: set[str] = set()
    visited: set[str] = set()

    def dfs(relation: str, path: list[str]) -> None:
        if relation in visiting:
            raise SchemaCycleDetected(namespace.name, path + [relation])
        if relation in visited or relation not in graph:
            return
        visiting.add(relation)
        for neighbor in graph[relation]:
            dfs(neighbor, path + [relation])
        visiting.discard(relation)
        visited.add(relation)

    for relation in graph:
        if relation not in visited:
            dfs(relation, [])


def tuple_to_usersets(rule: RewriteRule) -> Iterator[TupleToUserset]:
    if isinstance(rule, TupleToUserset):
        yield rule
    elif isinstance(rule, (Union, Intersection)):
        for child in rule.children:
            yield from tuple_to_usersets(child)
    elif isinstance(rule, Exclusion):
        yield from tuple_to_usersets(rule.base)
        yield from tuple_to_usersets(rule.subtract)


def tupleset_relations(rule: RewriteRule) -> set[str]:
    return {r.tupleset_relation for r in tuple_to_usersets(rule)}
