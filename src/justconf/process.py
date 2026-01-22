import json
import os
import re
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any, cast

from justconf.exception import PlaceholderError
from justconf.processor.base import Processor

# Pattern: ${processor:path#key|modifier:value|modifier:value}
PLACEHOLDER_PATTERN = re.compile(
    r'\$\{(?P<processor>[a-z_][a-z0-9_]*):(?P<path>[^#|}]+)'
    r'(?:#(?P<key>[^|}]+))?'
    r'(?P<modifiers>(?:\|[a-z_]+:[^|}]+)*)\}'
)

MODIFIER_PATTERN = re.compile(r'\|(?P<name>[a-z_]+):(?P<value>[^|]+)')


@dataclass
class Placeholder:
    """Parsed placeholder."""

    processor: str
    path: str
    key: str | None
    modifiers: dict[str, str]

    @classmethod
    def parse(cls, match: re.Match[str]) -> 'Placeholder':
        modifiers_str = match.group('modifiers') or ''
        modifiers = {}
        for mod_match in MODIFIER_PATTERN.finditer(modifiers_str):
            modifiers[mod_match.group('name')] = mod_match.group('value')

        return cls(
            processor=match.group('processor'),
            path=match.group('path'),
            key=match.group('key'),
            modifiers=modifiers,
        )


def _apply_modifiers(
    value: Any,
    modifiers: dict[str, str],
) -> Any:
    """Apply modifiers to the resolved value.

    Supported modifiers:
        - file:<path> — write value to file, return file path
        - encoding:<enc> — encoding for file modifier (default: utf-8)
    """
    if 'file' not in modifiers:
        return value

    file_path = modifiers['file']
    encoding = modifiers.get('encoding', 'utf-8')

    parent_dir = os.path.dirname(file_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    with open(file_path, 'w', encoding=encoding) as f:
        if isinstance(value, (dict, list)):
            json.dump(value, f, ensure_ascii=False)
        else:
            f.write(str(value))

    return file_path


def _resolve_value(
    value: str,
    processors_map: dict[str, Processor],
) -> Any:
    """Resolve all placeholders in a string value."""
    match = PLACEHOLDER_PATTERN.fullmatch(value)

    if match:
        # full string is a placeholder — resolve and return (possibly non-string)
        placeholder = Placeholder.parse(match)
        processor = processors_map.get(placeholder.processor)

        if processor is None:
            raise PlaceholderError(f'Unknown processor: {placeholder.processor}')

        resolved = processor.resolve(placeholder.path, placeholder.key)
        return _apply_modifiers(resolved, placeholder.modifiers)

    # check for embedded placeholders
    def replace_match(m: re.Match[str]) -> str:
        placeholder = Placeholder.parse(m)
        processor = processors_map.get(placeholder.processor)

        if processor is None:
            raise PlaceholderError(f'Unknown processor: {placeholder.processor}')

        resolved = processor.resolve(placeholder.path, placeholder.key)
        result = _apply_modifiers(resolved, placeholder.modifiers)
        return str(result)

    return PLACEHOLDER_PATTERN.sub(replace_match, value)


def _walk(
    obj: Any,
    processors_map: dict[str, Processor],
) -> Any:
    """Recursively walk config and resolve placeholders."""
    if isinstance(obj, dict):
        return {k: _walk(v, processors_map) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(item, processors_map) for item in obj]
    if isinstance(obj, str):
        return _resolve_value(obj, processors_map)
    return obj


def process(
    config: dict[str, Any],
    processors: list[Processor],
) -> dict[str, Any]:
    """Process config and resolve all placeholders.

    Walks through the config tree, finds placeholders in the format
    ${processor:path#key|modifier:value}, and resolves them using
    the appropriate processor.

    Args:
        config: Configuration dictionary.
        processors: List of processors to use for resolving placeholders.

    Returns:
        New config dictionary with all placeholders resolved.

    Example:
        >>> from justconf.processor import VaultProcessor, TokenAuth
        >>> processor = VaultProcessor(
        ...     url="http://vault:8200",
        ...     auth=TokenAuth(token="hvs.xxx"),
        ...     mount_path="secret",
        ... )
        >>> config = {"db_password": "${vault:db#password}"}
        >>> result = process(config, [processor])
        >>> result["db_password"]
        'actual_password_from_vault'
    """
    processors_map = {p.name: p for p in processors}

    # enable caching on all processors that support it
    with ExitStack() as stack:
        for p in processors:
            stack.enter_context(p.caching())

        return cast(dict[str, Any], _walk(config, processors_map))
