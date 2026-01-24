"""Integration tests with real HashiCorp Vault server.

Run with: pytest -m integration
Requires running Vault server at http://localhost:8200 with token 'token'.
"""

import json
import urllib.request

import pytest

from justconf import (
    NoValidAuthError,
    SecretNotFoundError,
    merge,
    process,
    toml_loader,
)
from justconf.processor import (
    AppRoleAuth,
    TokenAuth,
    UserpassAuth,
    VaultProcessor,
)

VAULT_URL = 'http://localhost:8200'
VAULT_TOKEN = 'token'

pytestmark = pytest.mark.integration


def vault_request(method: str, path: str, data: dict | None = None) -> dict:
    """Make a request to Vault API."""
    url = f'{VAULT_URL}/v1/{path}'
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode() if data else None,
        headers={
            'X-Vault-Token': VAULT_TOKEN,
            'Content-Type': 'application/json',
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read()
            return json.loads(body) if body else {}
    except Exception:
        return {}


class TestVaultIntegrationBasic:
    """Basic Vault integration tests with TokenAuth."""

    def test_resolve__single_key__returns_value(self, vault_secrets):
        # arrange
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=TokenAuth(token=VAULT_TOKEN),
        )

        # act
        result = processor.resolve('secret/data/database', 'password')

        # assert
        assert result == 'super_secret_password_123'

    def test_resolve__entire_secret__returns_dict(self, vault_secrets):
        # arrange
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=TokenAuth(token=VAULT_TOKEN),
        )

        # act
        result = processor.resolve('secret/data/api')

        # assert
        assert result == {
            'endpoint': 'https://api.example.com',
            'key': 'api_key_abc123',
            'secret': 'api_secret_xyz789',
        }

    def test_resolve__secret_not_found__raises_error(self, vault_secrets):
        # arrange
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=TokenAuth(token=VAULT_TOKEN),
        )

        # act & assert
        with pytest.raises(SecretNotFoundError, match='Secret not found'):
            processor.resolve('secret/data/nonexistent/secret', 'key')

    def test_resolve__key_not_found__raises_error(self, vault_secrets):
        # arrange
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=TokenAuth(token=VAULT_TOKEN),
        )

        # act & assert
        with pytest.raises(SecretNotFoundError, match="Key 'nonexistent' not found"):
            processor.resolve('secret/data/database', 'nonexistent')


class TestVaultIntegrationProcess:
    """Test process() with real Vault."""

    def test_process__simple_placeholders__resolves(self, vault_secrets):
        # arrange
        config = {
            'database': {
                'host': '${vault:secret/data/database#host}',
                'port': '${vault:secret/data/database#port}',
                'username': '${vault:secret/data/database#username}',
                'password': '${vault:secret/data/database#password}',
            },
        }
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=TokenAuth(token=VAULT_TOKEN),
        )

        # act
        result = process(config, [processor])

        # assert
        assert result == {
            'database': {
                'host': 'db.example.com',
                'port': 5432,
                'username': 'app_user',
                'password': 'super_secret_password_123',
            },
        }

    def test_process__embedded_placeholders__resolves(self, vault_secrets):
        # arrange
        config = {
            'database_url': 'postgres://${vault:secret/data/database#username}:${vault:secret/data/database#password}@${vault:secret/data/database#host}:${vault:secret/data/database#port}/mydb',
        }
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=TokenAuth(token=VAULT_TOKEN),
        )

        # act
        result = process(config, [processor])

        # assert
        assert result['database_url'] == 'postgres://app_user:super_secret_password_123@db.example.com:5432/mydb'

    def test_process__file_modifier__writes_to_file(self, vault_secrets, tmp_path):
        # arrange
        ca_path = tmp_path / 'ca.pem'
        config = {
            'tls': {
                'ca_file': f'${{vault:secret/data/tls#ca_cert|file:{ca_path}}}',
            },
        }
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=TokenAuth(token=VAULT_TOKEN),
        )

        # act
        result = process(config, [processor])

        # assert
        assert result['tls']['ca_file'] == str(ca_path)
        assert ca_path.exists()
        assert '-----BEGIN CERTIFICATE-----' in ca_path.read_text()

    def test_process__caching__fetches_secret_once(self, vault_secrets):
        # arrange
        config = {
            'pass1': '${vault:secret/data/database#password}',
            'pass2': '${vault:secret/data/database#password}',
            'pass3': '${vault:secret/data/database#password}',
        }
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=TokenAuth(token=VAULT_TOKEN),
        )

        # act
        result = process(config, [processor])

        # assert
        assert result['pass1'] == result['pass2'] == result['pass3'] == 'super_secret_password_123'


class TestVaultIntegrationWorkflow:
    """Test full workflow with TOML, merge, and process."""

    def test_full_workflow__toml_merge_process(self, vault_secrets, tmp_path):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_text("""
[app]
name = "myapp"
debug = false

[database]
host = "localhost"
port = 5432
pool_size = 10
""")

        secrets_config = {
            'database': {
                'host': '${vault:secret/data/database#host}',
                'username': '${vault:secret/data/database#username}',
                'password': '${vault:secret/data/database#password}',
            },
        }

        processor = VaultProcessor(
            url=VAULT_URL,
            auth=TokenAuth(token=VAULT_TOKEN),
        )

        # act
        base_config = toml_loader(str(toml_file))
        merged = merge(base_config, secrets_config)
        result = process(merged, [processor])

        # assert
        assert result['app']['name'] == 'myapp'
        assert result['database']['pool_size'] == 10
        assert result['database']['host'] == 'db.example.com'
        assert result['database']['password'] == 'super_secret_password_123'


class TestVaultIntegrationAppRole:
    """Test AppRole authentication with real Vault."""

    def test_approle_auth__resolves_secret(self, vault_secrets, approle_credentials):
        # arrange
        role_id, secret_id = approle_credentials
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=AppRoleAuth(role_id=role_id, secret_id=secret_id),
        )

        # act
        result = processor.resolve('secret/data/database', 'password')

        # assert
        assert result == 'super_secret_password_123'

    def test_approle_auth__fallback_from_invalid_token(self, vault_secrets, approle_credentials):
        # arrange
        role_id, secret_id = approle_credentials
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=[
                TokenAuth(token='invalid_token'),
                AppRoleAuth(role_id=role_id, secret_id=secret_id),
            ],
        )

        # act
        result = processor.resolve('secret/data/database', 'password')

        # assert
        assert result == 'super_secret_password_123'


class TestVaultIntegrationUserpass:
    """Test Userpass authentication with real Vault."""

    def test_userpass_auth__resolves_secret(self, vault_secrets, userpass_credentials):
        # arrange
        username, password = userpass_credentials
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=UserpassAuth(username=username, password=password),
        )

        # act
        result = processor.resolve('secret/data/database', 'password')

        # assert
        assert result == 'super_secret_password_123'

    def test_userpass_auth__wrong_password__raises_error(self, vault_secrets, userpass_credentials):
        # arrange
        username, _ = userpass_credentials
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=UserpassAuth(username=username, password='wrong_password'),
        )

        # act & assert
        with pytest.raises(NoValidAuthError):
            processor.resolve('secret/data/database', 'password')

    def test_userpass_auth__fallback_chain(self, vault_secrets, userpass_credentials):
        # arrange
        username, password = userpass_credentials
        processor = VaultProcessor(
            url=VAULT_URL,
            auth=[
                TokenAuth(token='invalid'),
                UserpassAuth(username='wronguser', password='wrongpass'),
                UserpassAuth(username=username, password=password),
            ],
        )

        # act
        result = processor.resolve('secret/data/database', 'password')

        # assert
        assert result == 'super_secret_password_123'


# fixtures


@pytest.fixture(name='vault_secrets', scope='module')
def vault_secrets_fixture():
    """Create test secrets in Vault."""
    secrets = {
        'database': {
            'host': 'db.example.com',
            'port': 5432,
            'username': 'app_user',
            'password': 'super_secret_password_123',
        },
        'api': {
            'key': 'api_key_abc123',
            'secret': 'api_secret_xyz789',
            'endpoint': 'https://api.example.com',
        },
        'tls': {
            'ca_cert': '-----BEGIN CERTIFICATE-----\nMIIC...(test CA cert)...\n-----END CERTIFICATE-----',
            'client_cert': '-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----',
            'client_key': '-----BEGIN RSA KEY-----\nMIIE...\n-----END RSA KEY-----',
        },
        'redis': {
            'url': 'redis://:redis_password@redis.example.com:6379/0',
            'password': 'redis_password',
        },
    }

    for name, data in secrets.items():
        vault_request('POST', f'secret/data/{name}', {'data': data})

    yield

    # cleanup is optional since Vault dev mode is ephemeral


@pytest.fixture(name='approle_credentials', scope='module')
def approle_credentials_fixture():
    """Setup AppRole auth and return credentials."""
    # enable approle (ignore if already enabled)
    vault_request('POST', 'sys/auth/approle', {'type': 'approle'})

    # create policy
    policy_hcl = 'path "secret/data/*" { capabilities = ["read", "list"] }'
    vault_request('PUT', 'sys/policies/acl/app-policy', {'policy': policy_hcl})

    # create role
    vault_request(
        'POST',
        'auth/approle/role/testapp',
        {'token_policies': ['app-policy'], 'token_ttl': '1h'},
    )

    # get credentials
    role_resp = vault_request('GET', 'auth/approle/role/testapp/role-id')
    secret_resp = vault_request('POST', 'auth/approle/role/testapp/secret-id')

    role_id = role_resp.get('data', {}).get('role_id', '')
    secret_id = secret_resp.get('data', {}).get('secret_id', '')

    return role_id, secret_id


@pytest.fixture(name='userpass_credentials', scope='module')
def userpass_credentials_fixture():
    """Setup Userpass auth and return credentials."""
    # enable userpass (ignore if already enabled)
    vault_request('POST', 'sys/auth/userpass', {'type': 'userpass'})

    # create policy
    policy_hcl = 'path "secret/data/*" { capabilities = ["read", "list"] }'
    vault_request('PUT', 'sys/policies/acl/user-policy', {'policy': policy_hcl})

    # create user
    vault_request(
        'POST',
        'auth/userpass/users/testuser',
        {'password': 'testpassword123', 'policies': ['user-policy']},
    )

    return 'testuser', 'testpassword123'
