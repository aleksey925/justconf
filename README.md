# justconf

Minimal schema-agnostic configuration loader for Python.

Load configuration from environment variables, `.env` files, and TOML files, then merge them with a simple priority system. No schema enforcement — use your preferred validation library (Pydantic, msgspec, dataclasses, or none at all).

## Installation

```bash
pip install justconf
```

For `.env` file support:

```bash
pip install justconf[dotenv]
```

## Quick Start

```python
from justconf import env_loader, dotenv_loader, toml_loader, merge

# Load from multiple sources and merge (later sources have higher priority)
config = merge(
    toml_loader("config.toml"),      # base config
    dotenv_loader(".env"),           # override with .env
    env_loader(prefix="APP"),        # highest priority: environment variables
)

# Use with your preferred validation library
from pydantic import BaseModel

class DatabaseConfig(BaseModel):
    host: str
    port: int = 5432

class AppConfig(BaseModel):
    debug: bool = False
    database: DatabaseConfig

app_config = AppConfig(**config)
```

## Loaders

### env_loader

Load configuration from environment variables.

```python
from justconf import env_loader

# Load all environment variables
config = env_loader()

# Load only variables with APP_ prefix (prefix is stripped)
config = env_loader(prefix="APP")
# APP_DEBUG=true -> {"debug": "true"}

# Preserve original case
config = env_loader(prefix="APP", case_sensitive=True)
# APP_Debug=true -> {"Debug": "true"}
```

### dotenv_loader

Load configuration from `.env` files. Requires `python-dotenv` (`pip install justconf[dotenv]`).

```python
from justconf import dotenv_loader

# Load from .env file
config = dotenv_loader(".env")

# With prefix filtering
config = dotenv_loader(".env", prefix="APP")

# Interpolation is supported
# BASE_DIR=/app
# DATA_DIR=${BASE_DIR}/data
# -> {"base_dir": "/app", "data_dir": "/app/data"}
```

### toml_loader

Load configuration from TOML files. Uses Python's built-in `tomllib`.

```python
from justconf import toml_loader

config = toml_loader("config.toml")
# Native TOML types are preserved (int, float, bool, list, dict, datetime)
```

## Nested Configuration

Use double underscores (`__`) to create nested structures from flat environment variables:

```bash
export DATABASE__HOST=localhost
export DATABASE__PORT=5432
```

```python
config = env_loader()
# {"database": {"host": "localhost", "port": "5432"}}
```

## Merging

The `merge` function combines multiple dictionaries with deep merge:

```python
from justconf import merge

config = merge(
    {"db": {"host": "localhost", "port": 5432}, "tags": ["a", "b"]},
    {"db": {"port": 3306}, "tags": ["c"]},
)
# {"db": {"host": "localhost", "port": 3306}, "tags": ["c"]}
```

**Merge strategy:**
- `dict` + `dict` → recursive deep merge
- Everything else (list, str, int, etc.) → overwrite

**Priority:** later arguments have higher priority.

## Exceptions

```python
from justconf import LoaderError, TomlLoadError

try:
    config = toml_loader("config.toml")
except FileNotFoundError:
    # File does not exist
    pass
except TomlLoadError as e:
    # Invalid TOML syntax
    pass
except LoaderError:
    # Base class for all loader errors
    pass
```

## API Reference

### Loaders

#### `env_loader(prefix=None, case_sensitive=False) -> dict[str, Any]`

Load from `os.environ`.

- `prefix`: Filter by prefix, strip it from keys
- `case_sensitive`: If `False`, keys are lowercased

#### `dotenv_loader(path=".env", prefix=None, case_sensitive=False, encoding="utf-8") -> dict[str, Any]`

Load from `.env` file.

- `path`: Path to file
- `prefix`: Filter by prefix, strip it from keys
- `case_sensitive`: If `False`, keys are lowercased
- `encoding`: File encoding

Raises: `FileNotFoundError`, `ImportError` (if python-dotenv not installed)

#### `toml_loader(path="config.toml", encoding="utf-8") -> dict[str, Any]`

Load from TOML file.

- `path`: Path to file
- `encoding`: File encoding

Raises: `FileNotFoundError`, `TomlLoadError`

### Merge

#### `merge(*dicts) -> dict[str, Any]`

Deep merge dictionaries. Later arguments override earlier ones.

### Exceptions

- `LoaderError` — base exception for all loader errors
- `TomlLoadError` — TOML parsing error

## License

MIT
