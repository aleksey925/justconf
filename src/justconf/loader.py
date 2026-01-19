import os
import tomllib
from typing import Any

from justconf.exception import TomlLoadError


def _strip_prefix(key: str, prefix: str, case_sensitive: bool) -> str | None:
    """Strip prefix from key if it matches. Returns None if no match."""
    prefix_with_sep = f'{prefix}_'
    if case_sensitive:
        if not key.startswith(prefix_with_sep):
            return None
        return key[len(prefix_with_sep) :]

    if not key.lower().startswith(prefix_with_sep.lower()):
        return None
    return key[len(prefix_with_sep) :]


def _set_nested(result: dict[str, Any], key: str, value: str) -> None:
    """Set a value in nested dict structure using __ as separator."""
    parts = key.split('__')
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

        _set_nested(result, key, value)

    return result


def env_loader(
    prefix: str | None = None,
    case_sensitive: bool = False,
) -> dict[str, Any]:
    """Load configuration from environment variables.

    Args:
        prefix: Filter variables by prefix. If prefix="APP", only variables
            starting with "APP_" are loaded, and the prefix is stripped.
        case_sensitive: If False (default), all keys are converted to lowercase.

    Returns:
        Dictionary with configuration values. All values are strings.
    """
    return _parse_env_vars(dict(os.environ), prefix, case_sensitive)


def dotenv_loader(
    path: str = '.env',
    prefix: str | None = None,
    case_sensitive: bool = False,
    encoding: str = 'utf-8',
) -> dict[str, Any]:
    """Load configuration from a .env file.

    Uses python-dotenv for parsing. Interpolation is enabled by default.
    Does not modify os.environ.

    Args:
        path: Path to .env file.
        prefix: Filter variables by prefix (same as env_loader).
        case_sensitive: If False (default), all keys are converted to lowercase.
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

    return _parse_env_vars(env_vars, prefix, case_sensitive)


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
