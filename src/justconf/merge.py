from typing import Any


def merge(*dicts: dict[str, Any]) -> dict[str, Any]:
    """Merge multiple dictionaries with deep merge strategy.

    Later arguments have higher priority. Nested dicts are merged recursively,
    all other types (lists, scalars) are overwritten.

    Example:
        >>> merge(
        ...     {"db": {"host": "localhost", "port": 5432}, "tags": ["a"]},
        ...     {"db": {"port": 3306}, "tags": ["b"]}
        ... )
        {"db": {"host": "localhost", "port": 3306}, "tags": ["b"]}
    """
    result: dict[str, Any] = {}

    for d in dicts:
        for key, value in d.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = merge(result[key], value)
            else:
                result[key] = value

    return result
