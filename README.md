justconf
========

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

## Secret Resolution

The `process` function resolves placeholders in your config, fetching secrets from external sources like HashiCorp Vault.

### Placeholder Syntax

```
${processor:path#key|modifier:value}
```

- `processor` — name of the processor (e.g., `vault`)
- `path` — path to the secret
- `key` — (optional) specific key within the secret
- `modifiers` — (optional) post-processing modifiers

### Basic Usage

```python
from justconf import process
from justconf.processor import VaultProcessor, TokenAuth

processor = VaultProcessor(
    url="http://vault:8200",
    auth=TokenAuth(token="hvs.xxx"),
)

config = {
    "db_password": "${vault:secret/db#password}",
    "api_key": "${vault:secret/api#key}",
}

result = process(config, [processor])
# {"db_password": "actual_password", "api_key": "actual_key"}
```

### Embedded Placeholders

Placeholders can be embedded within strings:

```python
config = {
    "dsn": "postgres://user:${vault:secret/db#password}@localhost/db",
}
```

### File Modifier

Write secrets to files instead of keeping them in memory. Useful for certificates and keys:

```python
config = {
    "tls_cert": "${vault:secret/tls#cert|file:/etc/ssl/cert.pem}",
    "tls_key": "${vault:secret/tls#key|file:/etc/ssl/key.pem|encoding:utf-8}",
}

result = process(config, [processor])
# {"tls_cert": "/etc/ssl/cert.pem", "tls_key": "/etc/ssl/key.pem"}
# Files are created with the secret content
```

If the value is a dict or list, it's serialized as JSON.

### VaultProcessor

Fetches secrets from HashiCorp Vault (KV v2).

```python
from justconf.processor import VaultProcessor

processor = VaultProcessor(
    url="http://vault:8200",
    auth=auth_method,           # see authentication methods below
    mount_path="secret",        # KV v2 mount path (default: "secret")
    timeout=30,                 # request timeout in seconds
)
```

### Authentication Methods

#### TokenAuth

Direct token authentication:

```python
from justconf.processor import TokenAuth

auth = TokenAuth(token="hvs.xxx")
```

#### AppRoleAuth

For automated workflows:

```python
from justconf.processor import AppRoleAuth

auth = AppRoleAuth(
    role_id="xxx",
    secret_id="yyy",
    mount_path="approle",  # default: "approle"
)
```

#### JwtAuth

For GitLab CI/CD and similar:

```python
from justconf.processor import JwtAuth

auth = JwtAuth(
    role="myproject",
    jwt=os.environ["CI_JOB_JWT"],
    mount_path="jwt",  # default: "jwt"
)
```

#### KubernetesAuth

For Kubernetes pods:

```python
from justconf.processor import KubernetesAuth

auth = KubernetesAuth(
    role="myapp",
    # jwt is read from /var/run/secrets/kubernetes.io/serviceaccount/token by default
)
```

#### UserpassAuth

Username/password authentication:

```python
from justconf.processor import UserpassAuth

auth = UserpassAuth(
    username="admin",
    password="secret",
    mount_path="userpass",  # default: "userpass"
)
```

### Auth Fallback Chain

Pass a list of auth methods to try them in order until one succeeds:

```python
processor = VaultProcessor(
    url="http://vault:8200",
    auth=[
        TokenAuth(token=os.environ.get("VAULT_TOKEN", "")),
        KubernetesAuth(role="myapp"),
        AppRoleAuth(role_id="xxx", secret_id="yyy"),
    ],
)
```

## Exceptions

```python
from justconf import LoaderError, TomlLoadError, ProcessorError, SecretNotFoundError

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

try:
    result = process(config, [processor])
except SecretNotFoundError as e:
    # Secret or key not found in Vault
    pass
except AuthenticationError as e:
    # Authentication failed
    pass
except ProcessorError:
    # Base class for all processor errors
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

### Process

#### `process(config, processors) -> dict[str, Any]`

Resolve placeholders in config using processors.

- `config`: Configuration dictionary
- `processors`: List of processors

Raises: `PlaceholderError`, `SecretNotFoundError`, `AuthenticationError`

### Exceptions

- `LoaderError` — base exception for all loader errors
- `TomlLoadError` — TOML parsing error
- `ProcessorError` — base exception for all processor errors
- `PlaceholderError` — unknown processor in placeholder
- `SecretNotFoundError` — secret or key not found
- `AuthenticationError` — authentication failed
- `NoValidAuthError` — all auth methods in fallback chain failed

## License

MIT
