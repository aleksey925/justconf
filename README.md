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
- [Schema Placeholders](#schema-placeholders)
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

Fetches secrets from HashiCorp Vault (KV v2).

```python
from justconf import process
from justconf.processor import VaultProcessor, TokenAuth

processor = VaultProcessor(
    url="http://vault:8200",
    auth=TokenAuth(token="hvs.xxx"),
    timeout=30,           # request timeout in seconds
    verify=True,          # SSL verification (default: True)
)

config = {"api_key": "${vault:secret/data/myapp/api#key}"}
result = process(config, [processor])
# {"api_key": "actual_key"}
```

#### Vault Path Structure

Specify the **full path** in the placeholder, exactly as it appears in the Vault HTTP API:

```
Placeholder:        ${vault:secret/data/myapp/database#password}
                           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                                          │
                                          └── full path as in Vault API
```

**For KV v2**, the path format is `{mount}/data/{secret_path}`:
- `secret/data/myapp` → mount=`secret`, secret=`myapp`
- `team-kv/data/shared/db` → mount=`team-kv`, secret=`shared/db`

**Benefits of this approach:**
- Copy-paste from Vault UI or CLI works directly
- Use secrets from different mount points in the same config
- No hidden magic — the path is used as-is

**Examples with different mount points:**

```python
config = {
    "app_secret": "${vault:secret/data/myapp#password}",
    "team_secret": "${vault:team-kv/data/shared/api#token}",
    "infra_cert": "${vault:infra/data/tls/cert#value}",
}

processor = VaultProcessor(
    url="http://vault:8200",
    auth=TokenAuth(token="hvs.xxx"),
)
result = process(config, [processor])
```

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
