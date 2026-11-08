"""Expand address / service groups into flat leaf values. Vendor-neutral.

Each object comes back with:
- resolved: every leaf value it expands to (order kept, duplicates dropped)
- unresolved: member names that don't exist in the config

A group cycle (A contains B contains A) is a broken config, so it raises.
"""

from collections.abc import Callable, Iterable

from fwlens.models import AddressKind, AddressObject, ServiceObject


def resolve_addresses(objects: Iterable[AddressObject]) -> tuple[AddressObject, ...]:
    return _resolve(
        objects,
        is_group=lambda o: o.kind is AddressKind.GROUP,
        leaf=lambda o: (o.value,),
    )


def resolve_services(objects: Iterable[ServiceObject]) -> tuple[ServiceObject, ...]:
    return _resolve(
        objects,
        is_group=lambda o: o.is_group,
        leaf=lambda o: o.entries,
    )


def _resolve[T: (AddressObject, ServiceObject)](
    objects: Iterable[T],
    is_group: Callable[[T], bool],
    leaf: Callable[[T], tuple[str, ...]],
) -> tuple[T, ...]:
    by_name = {o.name: o for o in objects}
    resolved = []
    for obj in by_name.values():
        values, missing = _flatten(obj.name, by_name, is_group, leaf, path=())
        resolved.append(
            obj.model_copy(update={"resolved": _dedup(values), "unresolved": _dedup(missing)})
        )
    return tuple(resolved)


def _flatten[T: (AddressObject, ServiceObject)](
    name: str,
    by_name: dict[str, T],
    is_group: Callable[[T], bool],
    leaf: Callable[[T], tuple[str, ...]],
    path: tuple[str, ...],
) -> tuple[list[str], list[str]]:
    """Depth-first expansion. `path` is the chain of groups we're inside, for cycle detection."""
    obj = by_name.get(name)
    if obj is None:
        return [], [name]
    if not is_group(obj):
        return list(leaf(obj)), []
    if name in path:
        raise ValueError(f"group cycle: {' -> '.join((*path, name))}")

    values: list[str] = []
    missing: list[str] = []
    for member in obj.members:
        member_values, member_missing = _flatten(member, by_name, is_group, leaf, (*path, name))
        values += member_values
        missing += member_missing
    return values, missing


def _dedup(items: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))
