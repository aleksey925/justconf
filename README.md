justconf
========

[![license](https://img.shields.io/pypi/l/justconf?style=for-the-badge)](https://pypi.org/project/justconf/)
[![python version](https://img.shields.io/pypi/pyversions/justconf?style=for-the-badge)](https://pypi.org/project/justconf/)
[![version](https://img.shields.io/pypi/v/justconf?style=for-the-badge)](https://pypi.org/project/justconf/)
[![coverage](https://img.shields.io/codecov/c/github/aleksey925/justconf/master?style=for-the-badge)](https://app.codecov.io/gh/aleksey925/justconf)
[![downloads](https://img.shields.io/pypi/dm/justconf?style=for-the-badge)](https://pypi.org/project/justconf/)

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
- [Schema Placeholders](#schema-placeholders)
- [Migration from pydantic-settings](#migration-from-pydantic-settings)
- [Development](#development)
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
from typing import Annotated
from pydantic import BaseModel
from justconf import merge, process, toml_loader, env_loader
from justconf.processor import VaultProcessor, TokenAuth
from justconf.schema import Placeholder, extract_placeholders

# Define schema with secret placeholders
class DatabaseConfig(BaseModel):
    host: str = "localhost"
    port: int = 5432
    password: Annotated[str, Placeholder("${vault:secret/data/db#password}")]

class AppConfig(BaseModel):
    debug: bool = False
    database: DatabaseConfig

# Load and merge (later sources override earlier)
config = merge(
    extract_placeholders(AppConfig),  # schema defaults with placeholders
    toml_loader("config.toml"),       # base config file
    env_loader(prefix="APP"),         # environment overrides
)

# Resolve secrets from Vault
vault = VaultProcessor(
    url="http://vault:8200",
    auth=TokenAuth(token="hvs.xxx"),
)
config = process(config, [vault])

# Validate
app_config = AppConfig(**config)
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
- `path` — full API path to the secret (for Vault KV v2, include `{mount}/data/{secret_path}`)
- `key` — (optional) specific key within the secret
- `modifiers` — (optional) post-processing modifiers

Placeholders can be embedded within strings:

```python
config = {"dsn": "postgres://user:${vault:secret/data/db#password}@localhost/db"}
```

### VaultProcessor

Allows fetching secrets from HashiCorp Vault (KV v2).

```python
from justconf import process
from justconf.processor import VaultProcessor, TokenAuth

processor = VaultProcessor(
    url="http://vault:8200",
    auth=TokenAuth(token="hvs.xxx"),
    timeout=30,           # request timeout in seconds
    verify=True,          # SSL verification (default: True)
)

config = {"db_pass": "${vault:secret/data/db#password}"}
result = process(config, [processor])
# {"db_pass": "secret_value"}
```

> The path from placeholder matches Vault's HTTP API exactly (`GET /v1/{path}`).
> For KV v2, this means `{mount}/data/{secret_path}`.

In the example, `secret/data/db` is the Vault path. The `#password` is the field
name inside the secret. To construct the path from the Vault UI URL, identify the
mount point and secret path:

```
Vault < 1.15:  https://vault.example.com/ui/vault/secrets/secret/show/db
                                                          ~~~~~~     ~~
                                                          mount      secret path

Vault >= 1.15: https://vault.example.com/ui/vault/secrets/secret/kv/db/details
                                                          ~~~~~~    ~~
                                                          mount     secret path

API path:      secret/data/db
```

Regardless of the UI URL format, the placeholder path is always `{mount}/data/{secret_path}`.

Since the full path is specified in the placeholder, you can fetch secrets from
different mount points in a single config (e.g., secret/data/..., team-kv/data/...)
— just ensure your token has access to them.

#### SSL Verification

The `verify` parameter controls SSL certificate verification:

- `verify=True` (default) — use system CA certificates
- `verify=False` — disable SSL verification (not recommended for production)
- `verify="/path/to/ca-bundle.crt"` — use custom CA bundle

```python
# For internal Vault with self-signed certificate
processor = VaultProcessor(
    url="https://vault.internal:8200",
    auth=TokenAuth(token="hvs.xxx"),
    verify="/etc/ssl/certs/internal-ca.crt",
)
```

#### Authentication Methods

VaultProcessor supports multiple [Vault auth methods](https://developer.hashicorp.com/vault/docs/auth):

- **TokenAuth(token)** — direct [token](https://developer.hashicorp.com/vault/docs/auth/token) authentication
- **AppRoleAuth(role_id, secret_id, mount_path="approle")** — for [AppRole](https://developer.hashicorp.com/vault/docs/auth/approle) automated workflows
- **JwtAuth(role, jwt, mount_path="jwt")** — for [JWT/OIDC](https://developer.hashicorp.com/vault/docs/auth/jwt) (GitLab CI/CD, etc.)
- **KubernetesAuth(role, jwt=None, jwt_path="...", mount_path="kubernetes")** — for [Kubernetes](https://developer.hashicorp.com/vault/docs/auth/kubernetes) pods; JWT is read from `/var/run/secrets/kubernetes.io/serviceaccount/token` by default
- **UserpassAuth(username, password, mount_path="userpass")** — [username/password](https://developer.hashicorp.com/vault/docs/auth/userpass) authentication

#### Auth Fallback Chain

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

#### Authentication from Environment Variables

Use `vault_auth_from_env()` to automatically detect credentials from environment variables:

```python
from justconf.processor import VaultProcessor, vault_auth_from_env

# Detect all available auth methods (sorted by priority)
auths = vault_auth_from_env()

# Use first available (like pydantic-settings-vault)
if auths:
    processor = VaultProcessor(
        url="http://vault:8200",
        auth=auths[0],
    )

# Or use fallback chain
processor = VaultProcessor(
    url="http://vault:8200",
    auth=auths,  # VaultProcessor accepts list
)

# Explicit method selection
auths = vault_auth_from_env(method='approle')
```

**Supported environment variables (in order of priority):**

| Auth Method    | Required Variables                   | Mount Path Override                                 |
|----------------|--------------------------------------|-----------------------------------------------------|
| AppRoleAuth    | `VAULT_ROLE_ID` + `VAULT_SECRET_ID`  | `VAULT_APPROLE_MOUNT_PATH`    (default: approle)    |
| KubernetesAuth | `VAULT_KUBERNETES_ROLE`              | `VAULT_KUBERNETES_MOUNT_PATH` (default: kubernetes) |
| TokenAuth      | `VAULT_TOKEN`                        | —                                                   |
| JwtAuth        | `VAULT_JWT_ROLE` + `VAULT_JWT_TOKEN` | `VAULT_JWT_MOUNT_PATH`        (default: jwt)        |
| UserpassAuth   | `VAULT_USERNAME` + `VAULT_PASSWORD`  | `VAULT_USERPASS_MOUNT_PATH`   (default: userpass)   |

#### File Modifier

Write secrets to files instead of keeping them in memory. Useful for certificates and keys:

```python
config = {
    "tls_cert": "${vault:secret/data/tls#cert|file:/etc/ssl/cert.pem}",
    "tls_key": "${vault:secret/data/tls#key|file:/etc/ssl/key.pem|encoding:utf-8}",
}

result = process(config, [processor])
# {"tls_cert": "/etc/ssl/cert.pem", "tls_key": "/etc/ssl/key.pem"}
# Files are created with the secret content
```

If the value is a dict or list, it's serialized as JSON.

## Schema Placeholders

Define default placeholder values directly in your schema using `Placeholder` annotation.
This keeps secret paths co-located with your configuration schema instead of scattered
across config files.

### Basic Usage

```python
from typing import Annotated
from pydantic import BaseModel
from justconf import merge, process, toml_loader
from justconf.schema import Placeholder, extract_placeholders

class DatabaseConfig(BaseModel):
    host: str = "localhost"  # static default
    port: int = 5432
    password: Annotated[str, Placeholder("${vault:secret/data/db/creds#password}")]

class AppConfig(BaseModel):
    database: DatabaseConfig
    api_key: Annotated[str, Placeholder("${vault:secret/data/api#key}")]

# Extract placeholders from schema
schema_defaults = extract_placeholders(AppConfig)
# {'database': {'password': '${vault:secret/data/db/creds#password}'}, 'api_key': '${vault:secret/data/api#key}'}

# Merge with priority: schema defaults < config file < environment
config = merge(
    schema_defaults,
    toml_loader("config.toml"),
)

# Resolve placeholders (vault_processor created as shown in Processors section)
config = process(config, [vault_processor])

# Validate
app_config = AppConfig(**config)
```

### Schema-Agnostic

Works with any class that has type hints:

```python
from dataclasses import dataclass
from typing import Annotated
from justconf.schema import Placeholder, extract_placeholders

@dataclass
class ServiceConfig:
    api_key: Annotated[str, Placeholder("${vault:secret/data/service#key}")]

# Plain classes work too
class PlainConfig:
    token: Annotated[str, Placeholder("${vault:secret/data/auth#token}")]

extract_placeholders(ServiceConfig)  # {'api_key': '${vault:secret/data/service#key}'}
```

### Override Schema Placeholders

Schema placeholders have the lowest priority. Override them in config files or environment:

```toml
# config.toml - overrides schema default
[database]
password = "${vault:secret/data/staging/db#password}"
```

### Override Placeholders for Nested Types

Use `WithPlaceholders` to override placeholders for nested types without modifying the original type.
This is useful when you reuse the same type with different secret sources:

```python
from typing import Annotated
from pydantic import BaseModel
from justconf.schema import Placeholder, WithPlaceholders, extract_placeholders

class DatabaseConfig(BaseModel):
    host: str = "localhost"
    password: Annotated[str, Placeholder("${vault:secret/data/default#password}")]
    username: str = "admin"

class AppConfig(BaseModel):
    # Override placeholders for each instance
    main_db: Annotated[DatabaseConfig, WithPlaceholders({
        'password': '${vault:secret/data/main_db#password}',
        'username': '${vault:secret/data/main_db#username}',
    })]
    replica_db: Annotated[DatabaseConfig, WithPlaceholders({
        'password': '${vault:secret/data/replica_db#password}',
    })]

result = extract_placeholders(AppConfig)
# {
#     'main_db': {
#         'password': '${vault:secret/data/main_db#password}',
#         'username': '${vault:secret/data/main_db#username}',
#     },
#     'replica_db': {
#         'password': '${vault:secret/data/replica_db#password}',
#     },
# }
```

**Behavior:**

- Overrides are merged with placeholders from the nested type (overrides take priority)
- Supports nested dicts for deep structures
- Validates that all keys exist in the target type (raises `PlaceholderError` for invalid keys)
- Works with `Optional[NestedType]` / `NestedType | None`

### Auto-Unpack Entire Value

When a placeholder omits the `#key` part, the processor returns the entire value as a dictionary
instead of extracting a single field. This is useful when all fields of a nested type are stored
together under one path:

```python
from typing import Annotated
from pydantic import BaseModel
from justconf import process
from justconf.schema import Placeholder, extract_placeholders

class DatabaseConfig(BaseModel):
    host: str
    port: int
    username: str
    password: str

class AppConfig(BaseModel):
    db: Annotated[DatabaseConfig, Placeholder("${vault:secret/data/db}")]

config = extract_placeholders(AppConfig)
config = process(config, [vault_processor])
# {'db': {'host': 'db.example.com', 'port': 5432, 'username': 'admin', 'password': 'secret'}}
app_config = AppConfig(**config)
```

## Migration from pydantic-settings

### Basic Settings

**Before (pydantic-settings):**
```python
from pydantic_settings import BaseSettings, SettingsConfigDict

class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP_")

    debug: bool = False
    port: int = 8080

config = AppConfig()
```

**After (justconf):**
```python
from pydantic import BaseModel
from justconf import merge, env_loader

class AppConfig(BaseModel):
    debug: bool = False
    port: int = 8080

config = AppConfig(**merge(env_loader(prefix="APP")))
```

### Nested Settings

**Before (pydantic-settings):**
```python
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

class DatabaseConfig(BaseModel):
    host: str = "localhost"
    port: int = 5432

class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_nested_delimiter="__")

    database: DatabaseConfig = DatabaseConfig()

# Requires: DATABASE__HOST=prod-db DATABASE__PORT=5433
config = AppConfig()
```

**After (justconf):**
```python
from pydantic import BaseModel
from justconf import merge, env_loader

class DatabaseConfig(BaseModel):
    host: str = "localhost"
    port: int = 5432

class AppConfig(BaseModel):
    database: DatabaseConfig = DatabaseConfig()

# Same env vars work: DATABASE__HOST=prod-db DATABASE__PORT=5433
config = AppConfig(**merge(env_loader()))
```

### With Vault Secrets

**Before (pydantic-settings-vault):**
```python
from pydantic import Field
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from pydantic_vault import VaultSettingsSource

class AppConfig(BaseSettings):
    db_password: str = Field(
        json_schema_extra={
            "vault_secret_path": "secret/data/app",
            "vault_secret_key": "db_password",
        },
    )
    api_key: str = Field(
        json_schema_extra={
            "vault_secret_path": "secret/data/app",
            "vault_secret_key": "api_key",
        },
    )

    model_config = {"vault_url": "http://vault:8200"}

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            VaultSettingsSource(settings_cls),
            file_secret_settings,
        )

config = AppConfig()  # auth from VAULT_TOKEN env
```

**After (justconf):**
```python
from typing import Annotated
from pydantic import BaseModel
from justconf import merge, process, env_loader
from justconf.processor import VaultProcessor, vault_auth_from_env
from justconf.schema import Placeholder, extract_placeholders

class AppConfig(BaseModel):
    db_password: Annotated[str, Placeholder("${vault:secret/data/app#db_password}")]
    api_key: Annotated[str, Placeholder("${vault:secret/data/app#api_key}")]

config = merge(extract_placeholders(AppConfig), env_loader())

vault = VaultProcessor(
    url="http://vault:8200",
    auth=vault_auth_from_env(),  # all detected methods as fallback chain
)
config = AppConfig(**process(config, [vault]))
```

### Environment Variable Changes

If you used `pydantic-settings-vault`, note these environment variable differences:

| pydantic-settings-vault  | justconf                      | Notes                                             |
|--------------------------|-------------------------------|---------------------------------------------------|
| `VAULT_AUTH_MOUNT_POINT` | `VAULT_APPROLE_MOUNT_PATH`    | Per-method variable for AppRole                   |
| `VAULT_AUTH_MOUNT_POINT` | `VAULT_KUBERNETES_MOUNT_PATH` | Per-method variable for Kubernetes                |
| `VAULT_AUTH_PATH`        | `VAULT_JWT_MOUNT_PATH`        | Per-method variable for JWT                       |
| `VAULT_ADDR`             | —                             | Pass URL explicitly via `VaultProcessor(url=...)` |
| `VAULT_NAMESPACE`        | —                             | Not supported                                     |
| `VAULT_CA_BUNDLE`        | —                             | Pass explicitly via `VaultProcessor(verify=...)`  |

In `pydantic-settings-vault`, a single `VAULT_AUTH_MOUNT_POINT` variable is shared across all
authentication methods. In `justconf`, each method has its own variable
(`VAULT_APPROLE_MOUNT_PATH`, `VAULT_KUBERNETES_MOUNT_PATH`, `VAULT_JWT_MOUNT_PATH`), which allows
setting different mount paths for different methods in a fallback chain.

The `~/.vault-token` file is not read automatically — the token must be passed explicitly via
`TokenAuth(token=...)` or the `VAULT_TOKEN` environment variable.

Authentication method auto-detection priority also differs: `pydantic-settings-vault` uses
Token → Kubernetes → AppRole → JWT, while `justconf` uses AppRole → Kubernetes → Token → JWT → Userpass.
In practice this rarely matters, since typically only one method is configured.

### Key Differences

| pydantic-settings                 | justconf                                                          |
|-----------------------------------|-------------------------------------------------------------------|
| `BaseSettings` class inheritance  | Plain `BaseModel` + loaders                                       |
| `env_prefix` in model config      | `prefix` parameter in `env_loader()`                              |
| `env_nested_delimiter="__"`       | `__` is the delimiter by default                                  |
| Field-level vault config          | Placeholders in schema or any config source                       |
| Implicit env loading              | Explicit `merge()` of sources                                     |
| `VAULT_AUTH_MOUNT_POINT` (shared) | Per-method mount path env vars (`VAULT_APPROLE_MOUNT_PATH`, etc.) |

## Development

### Debugging with a real Vault server

You can use a real Vault server to debug this project. To make this process
easier, this project includes a `docker-compose.yml` file that can run a
ready-to-use Vault server.

To run the server and set it up, run the following commands:

```shell
docker compose up
make vault
```

After that, you will have a Vault server running at `http://localhost:8200`, where you can authorize in three ways:

- using the root token (which is `token`)
- using the JWT method (role=`jwt_role`, token=[link](./configs/vault/jwt_token.txt))
- using the AppRole method (the values of role_id and secret_id can be found in the logs of the `make vault` command).

## License

MIT
