from collections import deque
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence

from authz.conditions import ConditionEvaluator, ConditionFn
from authz.errors import (
    CardinalityViolationError,
    ConditionNotFound,
    CycleDetected,
    DepthLimitExceeded,
    EvaluationBudgetExceeded,
    NamespaceNotFound,
    RelationNotFound,
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
    check_schema_cycles,
    tuple_to_usersets,
)
from authz.storage.base import Storage, Token
from authz.tuples import ObjectRef, RelationTuple, SubjectRef

ReadCache = dict[tuple[str, str | None, str | None, str | None], list[RelationTuple]]


@dataclass(frozen=True)
class CheckItem:
    subject: str
    permission: str
    resource: str
    context: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class EvaluationDecision:
    allowed: bool
    subject: str
    permission: str
    resource: str
    matched_tuples: tuple[RelationTuple, ...] = ()
    visited_path: tuple[str, ...] = ()
    condition_results: tuple[tuple[str, bool | None], ...] = ()
    reason: str = ""
    indeterminate: bool = False


@dataclass(frozen=True)
class UsersetTree:
    relation: str
    object: ObjectRef
    direct_subjects: tuple[str, ...] = ()
    children: tuple["UsersetTree", ...] = ()


def _and(a: bool | None, b: bool | None) -> bool | None:
    if a is False or b is False:
        return False
    return None if a is None or b is None else True


def _not(value: bool | None) -> bool | None:
    return None if value is None else not value


class _TraceCollector:
    __slots__ = ("visited_path", "matched_tuples", "condition_results")

    def __init__(self) -> None:
        self.visited_path: list[str] = []
        self.matched_tuples: list[RelationTuple] = []
        self.condition_results: list[tuple[str, bool | None]] = []


class _Budget:
    __slots__ = ("limit", "left")

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.left = limit

    def spend(self) -> None:
        if self.left <= 0:
            raise EvaluationBudgetExceeded(self.limit)
        self.left -= 1


class _CheckState:
    # Subject and context are fixed within one top-level check, so results
    # keyed by (namespace, object_id, relation) can be memoized.
    __slots__ = (
        "subject", "subject_ref", "context", "read_cache", "memo", "budget", "collector",
    )

    def __init__(
        self,
        subject: str,
        context: Mapping[str, Any] | None,
        read_cache: ReadCache,
        budget: _Budget,
        collector: _TraceCollector | None,
    ) -> None:
        self.subject = subject
        self.subject_ref = SubjectRef.parse(subject)
        self.context = context or {}
        self.read_cache = read_cache
        self.memo: dict[tuple[str, str, str], bool | None] | None = (
            {} if collector is None else None
        )
        self.budget = budget
        self.collector = collector

    def mark(self) -> int:
        return len(self.collector.matched_tuples) if self.collector is not None else 0

    def rewind(self, mark: int) -> None:
        if self.collector is not None:
            del self.collector.matched_tuples[mark:]


class Client:
    def __init__(
        self,
        storage: Storage,
        condition_evaluator: ConditionEvaluator,
        max_depth: int = 25,
        *,
        context_precedence: Literal["stored", "request"] = "stored",
        max_evaluations: int = 10_000,
    ):
        if context_precedence not in ("stored", "request"):
            raise ValueError(
                f"context_precedence must be 'stored' or 'request', got {context_precedence!r}"
            )
        if max_evaluations < 1:
            raise ValueError(f"max_evaluations must be at least 1, got {max_evaluations!r}")
        self._storage = storage
        self._conditions = condition_evaluator
        self._max_depth = max_depth
        self._context_precedence = context_precedence
        self._max_evaluations = max_evaluations
        self._namespaces: dict[str, Namespace] = {}
        self._traversal_relations: dict[str, set[str]] = {}
        self._tupleset_rules: dict[str, dict[str, list[TupleToUserset]]] = {}

    def register_schema(self, *namespaces: Namespace) -> None:
        for ns in namespaces:
            check_schema_cycles(ns)
            self._namespaces[ns.name] = ns
            rules: dict[str, list[TupleToUserset]] = {}
            for rule in ns.relations.values():
                for ttu in tuple_to_usersets(rule):
                    rules.setdefault(ttu.tupleset_relation, []).append(ttu)
            self._tupleset_rules[ns.name] = rules
            self._traversal_relations[ns.name] = set(rules)

    def register_condition(self, name: str, fn: ConditionFn) -> None:
        self._conditions.register(name, fn)

    @property
    def schema(self) -> dict[str, Namespace]:
        return self._namespaces

    @property
    def _schema(self) -> dict[str, Namespace]:
        return self._namespaces

    def _get_relation(self, namespace: str, relation: str) -> RewriteRule:
        ns = self._namespaces.get(namespace)
        if ns is None:
            raise NamespaceNotFound(namespace)
        rule = ns.relations.get(relation)
        if rule is None:
            raise RelationNotFound(namespace, relation)
        return rule

    def _validate_tuple(self, t: RelationTuple) -> None:
        self._get_relation(t.namespace, t.relation)
        if t.condition is not None and not self._conditions.is_registered(t.condition.name):
            raise ConditionNotFound(t.condition.name)
        subject = t.subject_ref
        if subject.is_userset:
            self._get_relation(subject.namespace, subject.relation)
        rules = self._tupleset_rules[t.namespace].get(t.relation, ())
        if rules and subject.is_userset:
            raise ValueError(
                f"{t.namespace}#{t.relation} is a tupleset relation; "
                f"its subject must not be a userset, got {t.subject!r}"
            )
        for rule in rules:
            self._get_relation(subject.namespace, rule.computed_relation)

    def _is_graph_edge(self, t: RelationTuple) -> bool:
        if t.relation in self._traversal_relations.get(t.namespace, set()):
            return True
        return t.subject_ref.is_userset

    async def _guard_against_cycle(self, t: RelationTuple) -> None:
        source = (t.namespace, t.object_id)
        subject_ref = t.subject_ref
        if subject_ref.is_userset:
            start = (subject_ref.namespace, subject_ref.object_id, subject_ref.relation)
        else:
            start = (subject_ref.namespace, subject_ref.object_id, t.relation)

        visited: set[tuple[str, str]] = set()
        queue: deque[tuple[str, str, str]] = deque([start])
        while queue:
            namespace, object_id, relation = queue.popleft()
            if (namespace, object_id) == source:
                raise WouldCreateCycle(t, f"{t.object} -> {namespace}:{object_id}")
            if (namespace, object_id) in visited:
                continue
            visited.add((namespace, object_id))
            existing = await self._storage.read_tuples(
                namespace, object_id=object_id, relation=relation
            )
            for et in existing:
                eref = et.subject_ref
                if eref.is_userset:
                    queue.append((eref.namespace, eref.object_id, eref.relation))
                elif relation in self._traversal_relations.get(namespace, set()):
                    queue.append((eref.namespace, eref.object_id, relation))

    async def write(self, tuples: Sequence[RelationTuple]) -> Token:
        for t in tuples:
            self._validate_tuple(t)
        async with self._storage.transaction():
            limited = {
                (t.namespace, t.object_id, t.relation)
                for t in tuples
                if self._namespaces[t.namespace].max_subjects_for(t.relation) is not None
            }
            lock = getattr(self._storage, "lock", None)
            if lock is not None:
                # Always cardinality keys (sorted) before the graph key, so
                # concurrent writers cannot deadlock.
                for namespace, object_id, relation in sorted(limited):
                    await lock(f"authz:cardinality:{namespace}:{object_id}#{relation}")
                if any(self._is_graph_edge(t) for t in tuples):
                    await lock("authz:graph")

            target_subjects: dict[tuple[str, str, str], list[str]] = {}
            for t in tuples:
                ns = self._namespaces[t.namespace]
                max_limit = ns.max_subjects_for(t.relation)
                if max_limit is not None:
                    target_key = (t.namespace, t.object_id, t.relation)
                    if target_key not in target_subjects:
                        existing = await self._storage.read_tuples(
                            t.namespace, object_id=t.object_id, relation=t.relation
                        )
                        target_subjects[target_key] = list(
                            dict.fromkeys(et.subject for et in existing)
                        )
                    current = target_subjects[target_key]
                    if t.subject not in current:
                        if len(current) >= max_limit:
                            raise CardinalityViolationError(
                                namespace=t.namespace,
                                object_id=t.object_id,
                                relation=t.relation,
                                max_subjects=max_limit,
                                existing_subjects=tuple(current),
                                attempted_subject=t.subject,
                            )
                        current.append(t.subject)

            for t in tuples:
                if self._is_graph_edge(t):
                    await self._guard_against_cycle(t)
                await self._storage.write_tuples([t])
            return await self._storage.current_token()

    async def delete(self, tuples: Sequence[RelationTuple]) -> Token:
        for t in tuples:
            self._get_relation(t.namespace, t.relation)
        return await self._storage.delete_tuples(tuples)

    async def read(
        self,
        namespace: str,
        object_id: str | None = None,
        relation: str | None = None,
        subject: str | None = None,
    ) -> list[RelationTuple]:
        if namespace not in self._namespaces:
            raise NamespaceNotFound(namespace)
        if relation is not None:
            self._get_relation(namespace, relation)
        return await self._storage.read_tuples(
            namespace, object_id=object_id, relation=relation, subject=subject
        )

    async def _read_tuples(
        self,
        state: _CheckState,
        namespace: str,
        object_id: str,
        relation: str,
    ) -> list[RelationTuple]:
        key = (namespace, object_id, relation, None)
        if key not in state.read_cache:
            state.read_cache[key] = await self._storage.read_tuples(
                namespace, object_id=object_id, relation=relation
            )
        return state.read_cache[key]

    async def _evaluate(
        self,
        subject: str,
        permission: str,
        resource: str,
        context: Mapping[str, Any] | None,
        read_cache: ReadCache | None,
        collector: _TraceCollector | None,
    ) -> bool | None:
        target = ObjectRef.parse(resource)
        self._get_relation(target.namespace, permission)
        state = _CheckState(
            subject,
            context,
            {} if read_cache is None else read_cache,
            _Budget(self._max_evaluations),
            collector,
        )
        return await self._check_relation(
            state, target.namespace, target.object_id, permission, []
        )

    async def check(
        self,
        subject: str,
        permission: str,
        resource: str,
        *,
        at_least_as_fresh_as: Token | None = None,
        context: Mapping[str, Any] | None = None,
        _read_cache: ReadCache | None = None,
    ) -> bool:
        if at_least_as_fresh_as is not None:
            await self._storage.wait_for_token(at_least_as_fresh_as)
        result = await self._evaluate(
            subject, permission, resource, context, _read_cache, None
        )
        return result is True

    async def explain(
        self,
        subject: str,
        permission: str,
        resource: str,
        *,
        at_least_as_fresh_as: Token | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> EvaluationDecision:
        if at_least_as_fresh_as is not None:
            await self._storage.wait_for_token(at_least_as_fresh_as)

        collector = _TraceCollector()
        result = await self._evaluate(
            subject, permission, resource, context, None, collector
        )
        allowed = result is True
        indeterminate = result is None

        target_node = f"{resource}#{permission}"
        if allowed:
            matched = tuple(collector.matched_tuples)
            chain = [subject]
            for t in matched:
                node = f"{t.namespace}:{t.object_id}#{t.relation}"
                if node not in chain:
                    chain.append(node)
            if target_node not in chain:
                chain.append(target_node)
            reason = f"Allowed via {' -> '.join(chain)}"
        else:
            matched = ()
            if indeterminate:
                reason = (
                    "Denied: indeterminate, missing or invalid condition context "
                    f"for {subject} on {target_node}"
                )
            else:
                reason = f"Denied: no matching relation or condition failed for {subject} on {target_node}"

        return EvaluationDecision(
            allowed=allowed,
            subject=subject,
            permission=permission,
            resource=resource,
            matched_tuples=matched,
            visited_path=tuple(collector.visited_path),
            condition_results=tuple(collector.condition_results),
            reason=reason,
            indeterminate=indeterminate,
        )

    async def check_batch(
        self,
        checks: Sequence[CheckItem],
        *,
        at_least_as_fresh_as: Token | None = None,
    ) -> list[bool]:
        if at_least_as_fresh_as is not None:
            await self._storage.wait_for_token(at_least_as_fresh_as)
        read_cache: ReadCache = {}
        results: list[bool] = []
        for item in checks:
            res = await self.check(
                item.subject,
                item.permission,
                item.resource,
                context=item.context,
                _read_cache=read_cache,
            )
            results.append(res)
        return results

    async def list_permissions(
        self,
        subject: str,
        resource: str,
        permissions: Sequence[str] | None = None,
        *,
        at_least_as_fresh_as: Token | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> list[str]:
        target = ObjectRef.parse(resource)
        ns = self._namespaces.get(target.namespace)
        if ns is None:
            raise NamespaceNotFound(target.namespace)
        if permissions is None:
            candidate_perms = list(ns.relations.keys())
        else:
            candidate_perms = list(permissions)
        checks = [
            CheckItem(
                subject=subject,
                permission=perm,
                resource=resource,
                context=context,
            )
            for perm in candidate_perms
        ]
        results = await self.check_batch(checks, at_least_as_fresh_as=at_least_as_fresh_as)
        return [perm for perm, allowed in zip(candidate_perms, results) if allowed]

    async def list_objects(
        self,
        subject: str,
        permission: str,
        namespace: str,
        candidate_ids: Sequence[str] | None = None,
        *,
        at_least_as_fresh_as: Token | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> list[str]:
        self._get_relation(namespace, permission)
        if candidate_ids is None:
            if at_least_as_fresh_as is not None:
                await self._storage.wait_for_token(at_least_as_fresh_as)
                at_least_as_fresh_as = None
            tuples = await self._storage.read_tuples(namespace)
            seen: set[str] = set()
            discovered: list[str] = []
            for t in tuples:
                if t.object_id not in seen:
                    seen.add(t.object_id)
                    discovered.append(t.object_id)
            candidate_ids = discovered

        if not candidate_ids:
            return []

        checks = [
            CheckItem(
                subject=subject,
                permission=permission,
                resource=f"{namespace}:{oid}",
                context=context,
            )
            for oid in candidate_ids
        ]
        results = await self.check_batch(checks, at_least_as_fresh_as=at_least_as_fresh_as)
        return [oid for oid, allowed in zip(candidate_ids, results) if allowed]

    async def _check_relation(
        self,
        state: _CheckState,
        namespace: str,
        object_id: str,
        relation: str,
        path: list[tuple[str, str, str]],
    ) -> bool | None:
        state.budget.spend()
        node = (namespace, object_id, relation)
        node_str = f"{namespace}:{object_id}#{relation}"
        collector = state.collector
        if collector is not None and node_str not in collector.visited_path:
            collector.visited_path.append(node_str)

        if node in path:
            trail = [f"{ns}:{oid}#{rel}" for ns, oid, rel in path]
            trail.append(node_str)
            raise CycleDetected(trail)
        # Only completed nodes are memoized, so an in-progress node is never
        # served from the memo and the cycle check above stays authoritative.
        if state.memo is not None and node in state.memo:
            return state.memo[node]
        if len(path) >= self._max_depth:
            raise DepthLimitExceeded(self._max_depth)
        rule = self._get_relation(namespace, relation)
        result = await self._eval_rule(
            state, rule, namespace, object_id, relation, path + [node]
        )
        if state.memo is not None:
            state.memo[node] = result
        return result

    async def _eval_rule(
        self,
        state: _CheckState,
        rule: RewriteRule,
        namespace: str,
        object_id: str,
        relation: str,
        path: list[tuple[str, str, str]],
    ) -> bool | None:
        if isinstance(rule, Direct):
            return await self._eval_direct(state, namespace, object_id, relation, path)
        if isinstance(rule, Union):
            result: bool | None = False
            for child in rule.children:
                mark = state.mark()
                value = await self._eval_rule(
                    state, child, namespace, object_id, relation, path
                )
                if value is True:
                    return True
                if value is None:
                    result = None
                state.rewind(mark)
            return result
        if isinstance(rule, Intersection):
            result = True
            mark = state.mark()
            for child in rule.children:
                value = await self._eval_rule(
                    state, child, namespace, object_id, relation, path
                )
                if value is False:
                    state.rewind(mark)
                    return False
                if value is None:
                    result = None
            if result is None:
                state.rewind(mark)
            return result
        if isinstance(rule, Exclusion):
            mark = state.mark()
            base = await self._eval_rule(
                state, rule.base, namespace, object_id, relation, path
            )
            if base is False:
                state.rewind(mark)
                return False
            sub_mark = state.mark()
            subtract = await self._eval_rule(
                state, rule.subtract, namespace, object_id, relation, path
            )
            state.rewind(sub_mark)
            result = _and(base, _not(subtract))
            if result is not True:
                state.rewind(mark)
            return result
        if isinstance(rule, From):
            return await self._check_relation(
                state, namespace, object_id, rule.relation, path
            )
        if isinstance(rule, TupleToUserset):
            parents = await self._read_tuples(
                state, namespace, object_id, rule.tupleset_relation
            )
            result = False
            for pt in parents:
                pref = pt.subject_ref
                holds = await self._condition_holds(state, pt, namespace, object_id)
                if holds is False:
                    continue
                mark = state.mark()
                if pref.is_userset:
                    value = None  # not writable through Client; never traverse
                else:
                    value = await self._check_relation(
                        state, pref.namespace, pref.object_id, rule.computed_relation, path
                    )
                value = _and(holds, value)
                if value is True:
                    if state.collector is not None:
                        state.collector.matched_tuples.append(pt)
                    return True
                if value is None:
                    result = None
                state.rewind(mark)
            return result
        raise TypeError(f"unsupported rewrite rule: {rule!r}")

    async def _condition_holds(
        self, state: _CheckState, t: RelationTuple, namespace: str, object_id: str
    ) -> bool | None:
        if t.condition is None:
            return True
        request = state.context
        if self._context_precedence == "stored":
            merged = {**request, **t.condition.context}
        else:
            merged = {**t.condition.context, **request}
        holds = await self._conditions.evaluate(
            t.condition.name, state.subject, f"{namespace}:{object_id}", merged
        )
        if holds is not None and not isinstance(holds, bool):
            raise TypeError(
                f"condition {t.condition.name!r} returned {type(holds).__name__}; "
                "evaluators must return True, False or None"
            )
        if state.collector is not None:
            state.collector.condition_results.append((t.condition.name, holds))
        return holds

    async def _eval_direct(
        self,
        state: _CheckState,
        namespace: str,
        object_id: str,
        relation: str,
        path: list[tuple[str, str, str]],
    ) -> bool | None:
        subject_ref = state.subject_ref
        tuples = await self._read_tuples(state, namespace, object_id, relation)
        result: bool | None = False
        for t in tuples:
            tref = t.subject_ref
            if not tref.is_userset:
                # Plain tuple subjects match plain request subjects only.
                if tref != subject_ref:
                    continue
                holds = await self._condition_holds(state, t, namespace, object_id)
                if holds is True:
                    if state.collector is not None:
                        state.collector.matched_tuples.append(t)
                    return True
                if holds is None:
                    result = None
                continue
            holds = await self._condition_holds(state, t, namespace, object_id)
            if holds is False:
                continue
            mark = state.mark()
            if tref == subject_ref:
                value: bool | None = True
            else:
                value = await self._check_relation(
                    state, tref.namespace, tref.object_id, tref.relation, path
                )
            value = _and(holds, value)
            if value is True:
                if state.collector is not None:
                    state.collector.matched_tuples.append(t)
                return True
            if value is None:
                result = None
            state.rewind(mark)
        return result

    async def expand(self, permission: str, resource: str) -> "UsersetTree":
        target = ObjectRef.parse(resource)
        rule = self._get_relation(target.namespace, permission)
        return await self._expand_rule(
            rule, target.namespace, target.object_id, permission, (), _Budget(self._max_evaluations)
        )

    async def _expand_rule(
        self,
        rule,
        namespace: str,
        object_id: str,
        relation: str,
        path: tuple[tuple[str, str, str], ...],
        budget: _Budget,
    ) -> "UsersetTree":
        budget.spend()
        node = (namespace, object_id, relation)
        if node in path:
            trail = [f"{ns}:{oid}#{rel}" for ns, oid, rel in path]
            trail.append(f"{namespace}:{object_id}#{relation}")
            raise CycleDetected(trail)
        if len(path) >= self._max_depth:
            raise DepthLimitExceeded(self._max_depth)
        path = path + (node,)
        direct_subjects: list[str] = []
        children: list[UsersetTree] = []

        async def walk(r) -> None:
            if isinstance(r, Direct):
                tuples = await self._storage.read_tuples(
                    namespace, object_id=object_id, relation=relation
                )
                direct_subjects.extend(t.subject for t in tuples)
            elif isinstance(r, (Union, Intersection)):
                for child in r.children:
                    await walk(child)
            elif isinstance(r, Exclusion):
                await walk(r.base)
            elif isinstance(r, From):
                children.append(
                    await self._expand_rule(
                        self._get_relation(namespace, r.relation),
                        namespace,
                        object_id,
                        r.relation,
                        path,
                        budget,
                    )
                )
            elif isinstance(r, TupleToUserset):
                parents = await self._storage.read_tuples(
                    namespace, object_id=object_id, relation=r.tupleset_relation
                )
                for pt in parents:
                    pref = pt.subject_ref
                    children.append(
                        await self._expand_rule(
                            self._get_relation(pref.namespace, r.computed_relation),
                            pref.namespace,
                            pref.object_id,
                            r.computed_relation,
                            path,
                            budget,
                        )
                    )

        await walk(rule)
        return UsersetTree(
            relation=relation,
            object=ObjectRef(namespace, object_id),
            direct_subjects=tuple(direct_subjects),
            children=tuple(children),
        )
