# justconf

Minimal schema-agnostic configuration library for Python.

Provides simple, composable building blocks for configuration management:

- **Loaders** — fetch config from various sources (environment variables, `.env` files, TOML)
- **Merge** — combine multiple configs with deep merge and priority control
- **Processors** — resolve placeholders from external sources (HashiCorp Vault)

Schema-agnostic: use your preferred validation library (Pydantic, msgspec, dataclasses) or none at all.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Loaders](#loaders)
- [Merge](#merge)
- [Processors](#processors)
- [License](#license)

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

### With Secret Resolution

```python
from justconf import merge, toml_loader, process
from justconf.processor import VaultProcessor, TokenAuth

# Load and merge config
config = merge(
    toml_loader("config.toml"),
    {"db_password": "${vault:secret/db#password}"},  # placeholder for secret
)

# Resolve secrets from Vault
processor = VaultProcessor(
    url="http://vault:8200",
    auth=TokenAuth(token="hvs.xxx"),
)
config = process(config, [processor])
# {"db_password": "actual_password_from_vault", ...}
```

## Loaders

Loaders fetch configuration from various sources and return a dictionary.

- **env_loader(prefix=None, case_sensitive=False)** — loads from environment variables. If `prefix` is set, filters variables by prefix and strips it from keys.
  ```python
  config = env_loader(prefix="APP")
  # APP_DEBUG=true, APP_PORT=8080 -> {"debug": "true", "port": "8080"}
  ```

- **dotenv_loader(path=".env", prefix=None, case_sensitive=False, encoding="utf-8")** — loads from `.env` file. Requires `pip install justconf[dotenv]`. Supports variable interpolation (`${VAR}`).
  ```python
  config = dotenv_loader(".env", prefix="APP")
  ```

- **toml_loader(path="config.toml", encoding="utf-8")** — loads from TOML file using Python's built-in `tomllib`. Native TOML types are preserved (int, float, bool, list, dict, datetime).
  ```python
  config = toml_loader("config.toml")
  ```

### Nested Configuration

Use double underscores (`__`) to create nested structures from flat environment variables:

```bash
export DATABASE__HOST=localhost
export DATABASE__PORT=5432
```

```python
config = env_loader()
# {"database": {"host": "localhost", "port": "5432"}}
```

## Merge

The `merge` function combines multiple dictionaries with deep merge. Later arguments have higher priority.

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

## Processors

Processors resolve placeholders in your configuration, fetching values from external sources.

### Placeholder Syntax

```
${processor:path#key|modifier:value}
```

- `processor` — name of the processor (e.g., `vault`)
- `path` — path to the secret
- `key` — (optional) specific key within the secret
- `modifiers` — (optional) post-processing modifiers

Placeholders can be embedded within strings:

```python
config = {"dsn": "postgres://user:${vault:secret/db#password}@localhost/db"}
```

### VaultProcessor

Fetches secrets from HashiCorp Vault (KV v2).

```python
from justconf import process
from justconf.processor import VaultProcessor, TokenAuth

processor = VaultProcessor(
    url="http://vault:8200",
    auth=TokenAuth(token="hvs.xxx"),
    mount_path="secret",  # KV v2 mount path (default: "secret")
    timeout=30,           # request timeout in seconds
)

config = {"api_key": "${vault:secret/api#key}"}
result = process(config, [processor])
# {"api_key": "actual_key"}
```

### Authentication Methods

VaultProcessor supports multiple [Vault auth methods](https://developer.hashicorp.com/vault/docs/auth):

- **TokenAuth(token)** — direct [token](https://developer.hashicorp.com/vault/docs/auth/token) authentication
- **AppRoleAuth(role_id, secret_id, mount_path="approle")** — for [AppRole](https://developer.hashicorp.com/vault/docs/auth/approle) automated workflows
- **JwtAuth(role, jwt, mount_path="jwt")** — for [JWT/OIDC](https://developer.hashicorp.com/vault/docs/auth/jwt) (GitLab CI/CD, etc.)
- **KubernetesAuth(role, jwt=None, jwt_path="...", mount_path="kubernetes")** — for [Kubernetes](https://developer.hashicorp.com/vault/docs/auth/kubernetes) pods; JWT is read from `/var/run/secrets/kubernetes.io/serviceaccount/token` by default
- **UserpassAuth(username, password, mount_path="userpass")** — [username/password](https://developer.hashicorp.com/vault/docs/auth/userpass) authentication

### Auth Fallback Chain

Pass a list of auth methods to try them in order until one succeeds:

```python
import os

processor = VaultProcessor(
    url="http://vault:8200",
    auth=[
        TokenAuth(token=os.environ.get("VAULT_TOKEN", "")),
        KubernetesAuth(role="myapp"),
        AppRoleAuth(role_id="xxx", secret_id="yyy"),
    ],
)
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

## License

MIT
