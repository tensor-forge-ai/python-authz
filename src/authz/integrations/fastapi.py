import inspect
import re
import string
from typing import Any, Awaitable, Callable, Literal, Mapping, Sequence

from fastapi import Depends, HTTPException, Request

from authz.engine import Client, EvaluationDecision
from authz.tuples import ObjectRef

ResourceFn = Callable[[Request], str | Awaitable[str]]
ContextFn = Callable[..., Mapping[str, Any] | Awaitable[Mapping[str, Any]]]
ResourceSource = Literal["path", "query", "header"]

__all__ = ["ContextFn", "ResourceFn", "ResourceSource", "explain_access", "requires"]

_PLACEHOLDER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _placeholders(template: str) -> list[str]:
    names = []
    for _, name, spec, conversion in string.Formatter().parse(template):
        if name is None:
            continue
        if spec or conversion or not _PLACEHOLDER.fullmatch(name):
            raise ValueError(
                f"resource template {template!r}: only bare '{{name}}' fields are allowed"
            )
        names.append(name)
    return names


def _source_items(request: Request, source: ResourceSource):
    if source == "path":
        return ((k, str(v)) for k, v in request.path_params.items())
    if source == "query":
        return request.query_params.multi_items()
    # Header placeholders use the lowercase header name with dashes replaced by underscores.
    return ((k.lower().replace("-", "_"), v) for k, v in request.headers.items())


def _format_resource(
    template: str, names: list[str], sources: Sequence[ResourceSource], request: Request
) -> str:
    wanted = set(names)
    values: dict[str, set[str]] = {}
    for source in sources:
        for key, value in _source_items(request, source):
            if key in wanted:
                values.setdefault(key, set()).add(value)
    for name in names:
        found = values.get(name, ())
        if len(found) != 1:
            problem = "missing" if not found else "ambiguous"
            raise HTTPException(status_code=400, detail=f"{problem} resource parameter {name!r}")
    return template.format(**{name: next(iter(values[name])) for name in names})


def _resource_resolver(
    resource: str | ResourceFn, sources: Sequence[ResourceSource]
) -> Callable[[Request], Awaitable[str]]:
    for source in sources:
        if source not in ("path", "query", "header"):
            raise ValueError(f"unknown resource source {source!r}")
    names = _placeholders(resource) if isinstance(resource, str) else []
    if names and not sources:
        raise ValueError("resource_sources must not be empty for a templated resource")

    async def resolve(request: Request) -> str:
        if isinstance(resource, str):
            resolved = _format_resource(resource, names, sources, request)
        else:
            resolved = resource(request)
            if inspect.isawaitable(resolved):
                resolved = await resolved
        try:
            ObjectRef.parse(resolved)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid resource") from None
        return resolved

    return resolve


def _context_resolver(
    get_context: ContextFn | None,
) -> Callable[[Request], Awaitable[Mapping[str, Any] | None]]:
    takes_request = get_context is not None and any(
        p.kind
        in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.VAR_POSITIONAL)
        for p in inspect.signature(get_context).parameters.values()
    )

    async def resolve(request: Request) -> Mapping[str, Any] | None:
        if get_context is None:
            return None
        result = get_context(request) if takes_request else get_context()
        if inspect.isawaitable(result):
            result = await result
        return result

    return resolve


def requires(
    permission: str,
    resource: str | ResourceFn,
    *,
    get_client: Callable[..., Client | Awaitable[Client]],
    get_subject: Callable[..., str | Awaitable[str]],
    get_context: ContextFn | None = None,
    detail: str = "Forbidden",
    resource_sources: Sequence[ResourceSource] = ("path",),
) -> Callable:
    resolve_resource = _resource_resolver(resource, resource_sources)
    resolve_context = _context_resolver(get_context)

    async def dependency(
        request: Request,
        client: Client = Depends(get_client),
        subject: str = Depends(get_subject),
    ) -> None:
        resolved = await resolve_resource(request)
        ctx = await resolve_context(request)
        if not await client.check(subject, permission, resolved, context=ctx):
            raise HTTPException(status_code=403, detail=detail)

    return dependency


def explain_access(
    permission: str,
    resource: str | ResourceFn,
    *,
    get_client: Callable[..., Client | Awaitable[Client]],
    get_subject: Callable[..., str | Awaitable[str]],
    get_context: ContextFn | None = None,
    detail: str = "Forbidden",
    resource_sources: Sequence[ResourceSource] = ("path",),
) -> Callable:
    resolve_resource = _resource_resolver(resource, resource_sources)
    resolve_context = _context_resolver(get_context)

    async def dependency(
        request: Request,
        client: Client = Depends(get_client),
        subject: str = Depends(get_subject),
    ) -> EvaluationDecision:
        resolved = await resolve_resource(request)
        ctx = await resolve_context(request)
        decision = await client.explain(subject, permission, resolved, context=ctx)
        request.state.authz_decision = decision
        if not decision.allowed:
            raise HTTPException(status_code=403, detail=detail)
        return decision

    return dependency
