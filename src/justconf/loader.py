import os
import tomllib
from typing import Any

from justconf.exception import TomlLoadError


def _strip_prefix(key: str, prefix: str, case_sensitive: bool) -> str | None:
    """Strip prefix from key if it matches. Returns None if no match."""
    if case_sensitive:
        if not key.startswith(prefix):
            return None
        return key[len(prefix) :]

    if not key.lower().startswith(prefix.lower()):
        return None
    return key[len(prefix) :]


def _set_nested(
    result: dict[str, Any],
    key: str,
    value: str,
    delimiter: str | None,
    max_split: int | None,
) -> None:
    """Set a value in nested dict structure using delimiter as separator."""
    if delimiter is None:
        result[key] = value
        return

    if max_split is None or max_split < 0:
        parts = key.split(delimiter)
    else:
        parts = key.split(delimiter, max(max_split - 1, 0))
    current = result
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


def _parse_env_vars(
    env_vars: dict[str, str],
    prefix: str | None = None,
    case_sensitive: bool = False,
    nested_delimiter: str | None = '__',
    nested_max_split: int | None = None,
) -> dict[str, Any]:
    """Parse environment variables into a nested dictionary."""
    result: dict[str, Any] = {}

    for key, value in env_vars.items():
        if prefix is not None:
            stripped = _strip_prefix(key, prefix, case_sensitive)
            if stripped is None:
                continue
            key = stripped

        if not key:
            continue

        if not case_sensitive:
            key = key.lower()

        _set_nested(result, key, value, nested_delimiter, nested_max_split)

    return result


def env_loader(
    prefix: str | None = None,
    case_sensitive: bool = False,
    nested_delimiter: str | None = '__',
    nested_max_split: int | None = None,
) -> dict[str, Any]:
    """Load configuration from environment variables.

    Args:
        prefix: Filter variables by prefix and strip it. The prefix is matched
            exactly as given — include the separator if needed (e.g. "APP_").
        case_sensitive: If False (default), all keys are converted to lowercase.
        nested_delimiter: Delimiter for creating nested dict structures.
            Defaults to "__". Set to None to disable nesting.
        nested_max_split: Maximum number of parts when splitting by nested
            delimiter. None means unlimited. 0 disables nesting.

    Returns:
        Dictionary with configuration values. All values are strings.
    """
    return _parse_env_vars(dict(os.environ), prefix, case_sensitive, nested_delimiter, nested_max_split)


def dotenv_loader(
    path: str = '.env',
    prefix: str | None = None,
    case_sensitive: bool = False,
    nested_delimiter: str | None = '__',
    nested_max_split: int | None = None,
    encoding: str = 'utf-8',
) -> dict[str, Any]:
    """Load configuration from a .env file.

    Uses python-dotenv for parsing. Interpolation is enabled by default.
    Does not modify os.environ.

    Args:
        path: Path to .env file.
        prefix: Filter variables by prefix and strip it. The prefix is matched
            exactly as given — include the separator if needed (e.g. "APP_").
        case_sensitive: If False (default), all keys are converted to lowercase.
        nested_delimiter: Delimiter for creating nested dict structures.
            Defaults to "__". Set to None to disable nesting.
        nested_max_split: Maximum number of parts when splitting by nested
            delimiter. None means unlimited. 0 disables nesting.
        encoding: File encoding.

    Returns:
        Dictionary with configuration values. All values are strings.

    Raises:
        FileNotFoundError: If the file does not exist.
        ImportError: If python-dotenv is not installed.
    """
    try:
        from dotenv import dotenv_values
    except ImportError:
        raise ImportError(
            'python-dotenv is required for dotenv_loader. Install it with: pip install justconf[dotenv]'
        ) from None

    if not os.path.exists(path):
        raise FileNotFoundError(f'File not found: {path}')

    raw_env_vars = dotenv_values(path, encoding=encoding)
    env_vars: dict[str, str] = {k: v for k, v in raw_env_vars.items() if v is not None}

    return _parse_env_vars(env_vars, prefix, case_sensitive, nested_delimiter, nested_max_split)


def toml_loader(
    path: str = 'config.toml',
    encoding: str = 'utf-8',
) -> dict[str, Any]:
    """Load configuration from a TOML file.

    Args:
        path: Path to TOML file.
        encoding: File encoding.

    Returns:
        Dictionary with configuration values. Native TOML types are preserved
        (int, float, bool, list, dict, datetime).

    Raises:
        FileNotFoundError: If the file does not exist.
        TomlLoadError: If the file contains invalid TOML.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f'File not found: {path}')

    try:
        with open(path, 'rb') as f:
            content = f.read().decode(encoding)
            return tomllib.loads(content)
    except tomllib.TOMLDecodeError as e:
        raise TomlLoadError(f'Failed to parse {path}: {e}') from e
