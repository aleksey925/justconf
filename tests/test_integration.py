"""Integration tests combining loaders, merge, and process."""

from contextlib import contextmanager

from justconf import NoValidAuthError, dotenv_loader, env_loader, merge, process, toml_loader
from justconf.processor.base import Processor


class TestIntegration:
    def test_full_workflow__toml_env_merge_process(self, tmp_path, monkeypatch):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_text(
            """
[database]
host = "localhost"
port = 5432

[server]
debug = false
"""
        )

        monkeypatch.setenv('APP_DATABASE__PORT', '3306')
        monkeypatch.setenv('APP_DATABASE__PASSWORD', '${mock:secret/db#password}')
        monkeypatch.setenv('APP_SERVER__DEBUG', 'true')

        processor = MockProcessor('mock', {'secret/db#password': 'super_secret'})

        # act
        base_config = toml_loader(str(toml_file))
        env_config = env_loader(prefix='APP')
        merged = merge(base_config, env_config)
        result = process(merged, [processor])

        # assert
        assert result == {
            'database': {
                'host': 'localhost',
                'port': '3306',
                'password': 'super_secret',
            },
            'server': {
                'debug': 'true',
            },
        }

    def test_dotenv_toml_merge__overrides_correctly(self, tmp_path):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_text(
            """
name = "myapp"
[logging]
level = "INFO"
format = "%(message)s"
"""
        )

        env_file = tmp_path / '.env'
        env_file.write_text(
            """
NAME=myapp-dev
LOGGING__LEVEL=DEBUG
"""
        )

        # act
        toml_config = toml_loader(str(toml_file))
        env_config = dotenv_loader(str(env_file))
        result = merge(toml_config, env_config)

        # assert
        assert result == {
            'name': 'myapp-dev',
            'logging': {
                'level': 'DEBUG',
                'format': '%(message)s',
            },
        }

    def test_three_sources_merge__priority_order(self, tmp_path, monkeypatch):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_text(
            """
[db]
host = "toml-host"
port = 5432
user = "toml-user"
"""
        )

        env_file = tmp_path / '.env'
        env_file.write_text(
            """
DB__HOST=dotenv-host
DB__PORT=3306
"""
        )

        monkeypatch.setenv('APP_DB__HOST', 'env-host')

        # act (toml < dotenv < env)
        toml_config = toml_loader(str(toml_file))
        dotenv_config = dotenv_loader(str(env_file))
        env_config = env_loader(prefix='APP')
        result = merge(toml_config, dotenv_config, env_config)

        # assert
        assert result == {
            'db': {
                'host': 'env-host',  # from env (highest priority)
                'port': '3306',  # from dotenv (overrides toml)
                'user': 'toml-user',  # from toml (base)
            },
        }

    def test_process_with_file_modifier__writes_to_file(self, tmp_path):
        # arrange
        cert_path = tmp_path / 'certs' / 'ca.pem'
        config = {
            'tls': {
                'ca_cert': f'${{mock:secret/tls#ca|file:{cert_path}}}',
                'enabled': True,
            },
        }
        processor = MockProcessor('mock', {'secret/tls#ca': '-----BEGIN CERTIFICATE-----\nMIIC...'})

        # act
        result = process(config, [processor])

        # assert
        assert result['tls']['ca_cert'] == str(cert_path)
        assert result['tls']['enabled'] is True
        assert cert_path.exists()
        assert cert_path.read_text() == '-----BEGIN CERTIFICATE-----\nMIIC...'

    def test_multiple_processors__different_sources(self, tmp_path):
        # arrange
        config = {
            'api': {
                'key': '${api:keys/main#key}',
                'secret': '${vault:secret/data/api#secret}',
            },
            'db': {
                'password': '${vault:secret/data/db#password}',
            },
        }

        api_processor = MockProcessor('api', {'keys/main#key': 'api_key_123'})
        vault_processor = MockProcessor(
            'vault',
            {
                'secret/data/api#secret': 'api_secret_456',
                'secret/data/db#password': 'db_pass_789',
            },
        )

        # act
        result = process(config, [api_processor, vault_processor])

        # assert
        assert result == {
            'api': {
                'key': 'api_key_123',
                'secret': 'api_secret_456',
            },
            'db': {
                'password': 'db_pass_789',
            },
        }

    def test_env_dotenv_deduplication__env_takes_precedence(self, tmp_path, monkeypatch):
        # arrange
        env_file = tmp_path / '.env'
        env_file.write_text('API_KEY=dotenv_key\n')

        monkeypatch.setenv('API_KEY', 'env_key')

        # act
        dotenv_config = dotenv_loader(str(env_file))
        env_config = env_loader()
        result = merge(dotenv_config, env_config)

        # assert
        assert result['api_key'] == 'env_key'

    def test_nested_merge_with_list__list_replaced(self, tmp_path):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_text(
            """
[app]
hosts = ["host1", "host2"]
ports = [80, 443]
"""
        )

        env_file = tmp_path / '.env'
        env_file.write_text('APP__HOSTS=["host3"]\n')

        # act
        toml_config = toml_loader(str(toml_file))
        env_config = dotenv_loader(str(env_file))
        result = merge(toml_config, env_config)

        # assert (lists are replaced, not merged)
        assert result['app']['hosts'] == '["host3"]'
        assert result['app']['ports'] == [80, 443]

    def test_complex_placeholder_in_connection_string(self, tmp_path):
        # arrange
        config = {
            'database': {
                'url': 'postgres://${mock:secret/db#user}:${mock:secret/db#pass}@${mock:config#host}:5432/mydb',
            },
        }
        processor = MockProcessor(
            'mock',
            {
                'secret/db#user': 'admin',
                'secret/db#pass': 'secret123',
                'config#host': 'db.example.com',
            },
        )

        # act
        result = process(config, [processor])

        # assert
        assert result['database']['url'] == 'postgres://admin:secret123@db.example.com:5432/mydb'

    def test_toml_types_preserved_through_merge(self, tmp_path):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_text(
            """
integer = 42
float_val = 3.14
boolean = true
date = 2024-01-15
nested = { a = 1, b = 2 }
"""
        )

        # act
        config = toml_loader(str(toml_file))
        result = merge({}, config)

        # assert
        assert isinstance(result['integer'], int)
        assert isinstance(result['float_val'], float)
        assert isinstance(result['boolean'], bool)
        assert result['nested'] == {'a': 1, 'b': 2}

    def test_empty_merge_chain__returns_empty(self):
        # act
        result = merge({}, {}, {})

        # assert
        assert result == {}

    def test_process_empty_config__returns_empty(self):
        # act
        result = process({}, [])

        # assert
        assert result == {}


class TestNoValidAuthErrorStructure:
    def test_errors_attribute__contains_all_errors(self):
        # arrange
        errors = [
            ValueError('Error 1'),
            TypeError('Error 2'),
            RuntimeError('Error 3'),
        ]

        # act
        exc = NoValidAuthError(errors)

        # assert
        assert exc.errors == errors
        assert 'ValueError' in str(exc)
        assert 'TypeError' in str(exc)
        assert 'RuntimeError' in str(exc)


# fixtures


class MockProcessor(Processor):
    def __init__(self, name: str, secrets: dict):  # type: ignore[override]
        self.name = name
        self.secrets = secrets
        self._cache: dict | None = None

    def resolve(self, path: str, key: str | None = None):
        cache_key = f'{path}#{key}'

        if self._cache is not None and cache_key in self._cache:
            return self._cache[cache_key]

        value = self.secrets.get(cache_key)
        if value is None:
            raise KeyError(f'Secret not found: {cache_key}')

        if self._cache is not None:
            self._cache[cache_key] = value

        return value

    @contextmanager
    def caching(self):
        self._cache = {}
        try:
            yield
        finally:
            self._cache = None
