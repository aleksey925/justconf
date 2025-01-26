import types
from dataclasses import dataclass
from typing import Annotated, Any, Union, get_args, get_origin, get_type_hints

from justconf.exception import PlaceholderError
from justconf.merge import merge


@dataclass(frozen=True)
class Placeholder:
    """Marker for fields with placeholder values to be processed.

    Example:
        password: Annotated[str, Placeholder("${vault:db#password}")]
        api_key: Annotated[str, Placeholder("${env:API_KEY}")]
    """

    value: str


@dataclass(frozen=True)
class WithPlaceholders:
    """Override placeholders for a nested type.

    Example:
        class AppConfig:
            db: Annotated[DatabaseConfig, WithPlaceholders({
                'password': '${vault:secret/data/db#password}',
            })]
    """

    overrides: dict[str, Any]


def _is_class_with_fields(cls: type) -> bool:
    """Check if class has extractable type hints."""
    try:
        hints = get_type_hints(cls, include_extras=True)
        return bool(hints)
    except Exception:
        return False


def _get_placeholder(type_hint: Any) -> Placeholder | None:
    """Extract Placeholder marker from Annotated type hint."""
    if get_origin(type_hint) is not Annotated:
        return None
    for arg in get_args(type_hint)[1:]:
        if isinstance(arg, Placeholder):
            return arg
    return None


def _unwrap_optional(tp: Any) -> Any:
    """Extract T from Optional[T] / T | None."""
    origin = get_origin(tp)
    if origin is Union or origin is types.UnionType:
        args = [a for a in get_args(tp) if a is not type(None)]
        if len(args) == 1:
            return args[0]
    return tp


def _get_with_placeholders(type_hint: Any) -> WithPlaceholders | None:
    """Extract WithPlaceholders marker from Annotated type hint."""
    if get_origin(type_hint) is not Annotated:
        return None
    for arg in get_args(type_hint)[1:]:
        if isinstance(arg, WithPlaceholders):
            return arg
    return None


def _validate_override_keys(
    overrides: dict[str, Any],
    target_type: type,
    path: str = '',
) -> None:
    """Validate that all keys in overrides exist in the target type."""
    try:
        hints = get_type_hints(target_type, include_extras=True)
    except (NameError, AttributeError, TypeError):
        hints = {}

    for key, value in overrides.items():
        if key not in hints:
            full_path = f'{path}.{key}' if path else key
            available = ', '.join(sorted(hints.keys())) if hints else 'none'
            raise PlaceholderError(
                f"WithPlaceholders key '{full_path}' does not exist in {target_type.__name__}. "
                f'Available keys: {available}'
            )

        # recursively validate nested dicts
        if isinstance(value, dict):
            field_type = hints[key]
            actual_type = get_args(field_type)[0] if get_origin(field_type) is Annotated else field_type
            actual_type = _unwrap_optional(actual_type)
            if isinstance(actual_type, type):
                nested_path = f'{path}.{key}' if path else key
                _validate_override_keys(value, actual_type, nested_path)


def extract_placeholders(model: type) -> dict[str, Any]:
    """Extract placeholder values from any class with Annotated type hints.

    Recursively walks through type hints and extracts Placeholder markers.
    Works with Pydantic, dataclasses, msgspec, attrs, or plain classes.

    Args:
        model: Class with type hints.

    Returns:
        Dictionary with placeholder values for fields that have Placeholder annotation.

    Example:
        >>> class Config:
        ...     password: Annotated[str, Placeholder("${vault:db#pass}")]
        >>> extract_placeholders(Config)
        {'password': '${vault:db#pass}'}
    """
    result: dict[str, Any] = {}

    try:
        hints = get_type_hints(model, include_extras=True)
    except Exception:
        return result

    for field_name, field_type in hints.items():
        placeholder = _get_placeholder(field_type)
        if placeholder is not None:
            result[field_name] = placeholder.value
            continue

        # check for WithPlaceholders marker
        with_placeholders = _get_with_placeholders(field_type)
        actual_type = get_args(field_type)[0] if get_origin(field_type) is Annotated else field_type
        actual_type = _unwrap_optional(actual_type)

        is_nested_class = isinstance(actual_type, type) and _is_class_with_fields(actual_type)

        if with_placeholders is not None and not is_nested_class:
            type_name = getattr(actual_type, '__name__', str(actual_type))
            raise PlaceholderError(
                f"WithPlaceholders cannot be applied to '{field_name}': '{type_name}' is not a class with fields"
            )

        if is_nested_class:
            nested = extract_placeholders(actual_type)

            if with_placeholders is not None:
                _validate_override_keys(with_placeholders.overrides, actual_type, field_name)
                nested = merge(nested, with_placeholders.overrides)

            if nested:
                result[field_name] = nested

    return result
