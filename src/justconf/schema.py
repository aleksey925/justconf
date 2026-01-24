from dataclasses import dataclass
from typing import Annotated, Any, get_args, get_origin, get_type_hints


@dataclass(frozen=True)
class Placeholder:
    """Marker for fields with placeholder values to be processed.

    Example:
        password: Annotated[str, Placeholder("${vault:db#password}")]
        api_key: Annotated[str, Placeholder("${env:API_KEY}")]
    """

    value: str


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

        # recursively handle nested classes
        actual_type = get_args(field_type)[0] if get_origin(field_type) is Annotated else field_type
        if isinstance(actual_type, type) and _is_class_with_fields(actual_type):
            nested = extract_placeholders(actual_type)
            if nested:
                result[field_name] = nested

    return result
