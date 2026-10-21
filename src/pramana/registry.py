"""Registry that lets check modules declare themselves with a decorator."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from pramana.types import CheckResult

CheckFn = Callable[["AuditContext"], CheckResult]  # noqa: F821


@dataclass(frozen=True)
class CheckDefinition:
    check_id: str
    title: str
    category: str
    system_types: tuple[str, ...]
    fn: CheckFn
    order: int


_REGISTRY: dict[str, CheckDefinition] = {}


def register(
    check_id: str,
    *,
    title: str,
    category: str,
    system_types: tuple[str, ...],
    order: int = 100,
) -> Callable[[CheckFn], CheckFn]:
    def decorator(fn: CheckFn) -> CheckFn:
        if check_id in _REGISTRY:
            raise ValueError(f"Duplicate check id: {check_id}")
        _REGISTRY[check_id] = CheckDefinition(check_id, title, category, system_types, fn, order)
        return fn

    return decorator


def all_checks() -> list[CheckDefinition]:
    import pramana.checks  # noqa: F401  (imports every check module so they register)

    return sorted(_REGISTRY.values(), key=lambda d: (d.order, d.check_id))


def checks_for(system_type: str, extra_types: tuple[str, ...] = ()) -> list[CheckDefinition]:
    wanted = {system_type, *extra_types}
    return [d for d in all_checks() if wanted.intersection(d.system_types)]
