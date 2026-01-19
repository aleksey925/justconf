from contextlib import contextmanager

import pytest

from justconf import PlaceholderError, process
from justconf.processor.base import Processor


class TestProcess:
    def test_process__no_placeholders__returns_unchanged(self):
        # arrange
        config = {'key': 'value', 'nested': {'a': 1}}

        # act
        result = process(config, [])

        # assert
        assert result == {'key': 'value', 'nested': {'a': 1}}

    def test_process__simple_placeholder__resolves(self):
        # arrange
        config = {'password': '${mock:secret/db#pass}'}
        processor = MockProcessor('mock', {'secret/db#pass': 'secret123'})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'password': 'secret123'}

    def test_process__placeholder_without_key__resolves(self):
        # arrange
        config = {'data': '${mock:secret/db}'}
        processor = MockProcessor('mock', {'secret/db#None': {'user': 'admin', 'pass': 'secret'}})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'data': {'user': 'admin', 'pass': 'secret'}}

    def test_process__nested_config__resolves_all(self):
        # arrange
        config = {
            'db': {
                'host': 'localhost',
                'password': '${mock:secret/db#pass}',
            },
            'api_key': '${mock:secret/api#key}',
        }
        processor = MockProcessor(
            'mock',
            {
                'secret/db#pass': 'dbpass',
                'secret/api#key': 'apikey123',
            },
        )

        # act
        result = process(config, [processor])

        # assert
        assert result == {
            'db': {'host': 'localhost', 'password': 'dbpass'},
            'api_key': 'apikey123',
        }

    def test_process__list_values__resolves(self):
        # arrange
        config = {'keys': ['${mock:secret/a#k}', '${mock:secret/b#k}']}
        processor = MockProcessor(
            'mock',
            {
                'secret/a#k': 'key_a',
                'secret/b#k': 'key_b',
            },
        )

        # act
        result = process(config, [processor])

        # assert
        assert result == {'keys': ['key_a', 'key_b']}

    def test_process__embedded_placeholder__resolves(self):
        # arrange
        config = {'url': 'postgres://user:${mock:secret/db#pass}@localhost/db'}
        processor = MockProcessor('mock', {'secret/db#pass': 'secret123'})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'url': 'postgres://user:secret123@localhost/db'}

    def test_process__multiple_embedded_placeholders__resolves_all(self):
        # arrange
        config = {'url': '${mock:secret/db#user}:${mock:secret/db#pass}'}
        processor = MockProcessor(
            'mock',
            {
                'secret/db#user': 'admin',
                'secret/db#pass': 'secret',
            },
        )

        # act
        result = process(config, [processor])

        # assert
        assert result == {'url': 'admin:secret'}

    def test_process__unknown_processor__raises_error(self):
        # arrange
        config = {'password': '${unknown:secret/db#pass}'}

        # act & assert
        with pytest.raises(PlaceholderError, match='Unknown processor: unknown'):
            process(config, [])

    def test_process__file_modifier__writes_file_returns_path(self, tmp_path):
        # arrange
        file_path = tmp_path / 'secret.txt'
        config = {'cert': f'${{mock:secret/tls#cert|file:{file_path}}}'}
        processor = MockProcessor('mock', {'secret/tls#cert': '-----BEGIN CERT-----'})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'cert': str(file_path)}
        assert file_path.read_text() == '-----BEGIN CERT-----'

    def test_process__file_modifier_with_encoding__uses_encoding(self, tmp_path):
        # arrange
        file_path = tmp_path / 'secret.txt'
        config = {'data': f'${{mock:secret/data#content|file:{file_path}|encoding:latin-1}}'}
        processor = MockProcessor('mock', {'secret/data#content': 'café'})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'data': str(file_path)}
        assert file_path.read_text(encoding='latin-1') == 'café'

    def test_process__file_modifier__creates_parent_dirs(self, tmp_path):
        # arrange
        file_path = tmp_path / 'subdir' / 'deep' / 'secret.txt'
        config = {'cert': f'${{mock:secret/tls#cert|file:{file_path}}}'}
        processor = MockProcessor('mock', {'secret/tls#cert': 'cert_content'})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'cert': str(file_path)}
        assert file_path.exists()
        assert file_path.read_text() == 'cert_content'

    def test_process__file_modifier_with_dict__writes_json(self, tmp_path):
        # arrange
        file_path = tmp_path / 'secret.json'
        config = {'data': f'${{mock:secret/db|file:{file_path}}}'}
        processor = MockProcessor('mock', {'secret/db#None': {'user': 'admin', 'pass': 'secret'}})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'data': str(file_path)}
        assert file_path.read_text() == '{"user": "admin", "pass": "secret"}'

    def test_process__caching__calls_resolve_once_per_secret(self):
        # arrange
        config = {
            'pass1': '${mock:secret/db#pass}',
            'pass2': '${mock:secret/db#pass}',
            'pass3': '${mock:secret/db#pass}',
        }
        processor = MockProcessor('mock', {'secret/db#pass': 'secret'})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'pass1': 'secret', 'pass2': 'secret', 'pass3': 'secret'}
        assert processor.resolve_count == 1

    def test_process__multiple_processors__uses_correct_one(self):
        # arrange
        config = {
            'vault_secret': '${vault:secret/db#pass}',
            'env_value': '${env:HOME}',
        }
        vault_processor = MockProcessor('vault', {'secret/db#pass': 'vault_secret'})
        env_processor = MockProcessor('env', {'HOME#None': '/home/user'})

        # act
        result = process(config, [vault_processor, env_processor])

        # assert
        assert result == {
            'vault_secret': 'vault_secret',
            'env_value': '/home/user',
        }

    def test_process__non_string_values__unchanged(self):
        # arrange
        config = {
            'count': 42,
            'enabled': True,
            'rate': 3.14,
            'empty': None,
        }

        # act
        result = process(config, [])

        # assert
        assert result == {'count': 42, 'enabled': True, 'rate': 3.14, 'empty': None}

    def test_process__file_modifier_with_list__writes_json(self, tmp_path):
        # arrange
        file_path = tmp_path / 'hosts.json'
        config = {'hosts': f'${{mock:secret/hosts|file:{file_path}}}'}
        processor = MockProcessor('mock', {'secret/hosts#None': ['host1', 'host2', 'host3']})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'hosts': str(file_path)}
        assert file_path.read_text() == '["host1", "host2", "host3"]'

    def test_process__embedded_placeholder_with_modifiers__applies_modifiers(self, tmp_path):
        # arrange
        file_path = tmp_path / 'cert.pem'
        config = {'url': f'https://example.com?cert=${{mock:secret/tls#cert|file:{file_path}}}'}
        processor = MockProcessor('mock', {'secret/tls#cert': '-----BEGIN CERT-----'})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'url': f'https://example.com?cert={file_path}'}
        assert file_path.read_text() == '-----BEGIN CERT-----'

    def test_process__unknown_processor_in_embedded__raises_error(self):
        # arrange
        config = {'url': 'prefix_${unknown:path#key}_suffix'}

        # act & assert
        with pytest.raises(PlaceholderError, match='Unknown processor: unknown'):
            process(config, [])

    def test_process__nested_list_in_dict__resolves_all(self):
        # arrange
        config = {
            'servers': {
                'hosts': ['${mock:host1#name}', '${mock:host2#name}'],
                'primary': '${mock:primary#ip}',
            }
        }
        processor = MockProcessor(
            'mock',
            {
                'host1#name': 'server1.example.com',
                'host2#name': 'server2.example.com',
                'primary#ip': '10.0.0.1',
            },
        )

        # act
        result = process(config, [processor])

        # assert
        assert result == {
            'servers': {
                'hosts': ['server1.example.com', 'server2.example.com'],
                'primary': '10.0.0.1',
            }
        }

    def test_process__empty_config__returns_empty(self):
        # act
        result = process({}, [])

        # assert
        assert result == {}

    def test_process__placeholder_with_special_characters_in_path__resolves(self):
        # arrange
        config = {'secret': '${mock:path/with-dashes/and_underscores#key}'}
        processor = MockProcessor('mock', {'path/with-dashes/and_underscores#key': 'value'})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'secret': 'value'}

    def test_process__processor_resolve_returns_int__preserves_type(self):
        # arrange
        config = {'port': '${mock:config#port}'}
        processor = MockProcessor('mock', {'config#port': 8080})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'port': 8080}
        assert isinstance(result['port'], int)

    def test_process__processor_resolve_returns_bool__preserves_type(self):
        # arrange
        config = {'enabled': '${mock:config#debug}'}
        processor = MockProcessor('mock', {'config#debug': True})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'enabled': True}
        assert isinstance(result['enabled'], bool)

    def test_process__embedded_placeholder_converts_to_string(self):
        # arrange
        config = {'message': 'Port is ${mock:config#port}'}
        processor = MockProcessor('mock', {'config#port': 8080})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'message': 'Port is 8080'}
        assert isinstance(result['message'], str)

    def test_process__file_modifier_no_parent_dir__writes_to_current(self, tmp_path, monkeypatch):
        # arrange
        monkeypatch.chdir(tmp_path)
        config = {'cert': '${mock:secret/tls#cert|file:secret.txt}'}
        processor = MockProcessor('mock', {'secret/tls#cert': 'cert_content'})

        # act
        result = process(config, [processor])

        # assert
        assert result == {'cert': 'secret.txt'}
        assert (tmp_path / 'secret.txt').read_text() == 'cert_content'


# fixtures


class MockProcessor(Processor):
    def __init__(self, name: str, secrets: dict):  # type: ignore[override]
        self.name = name
        self.secrets = secrets
        self.resolve_count = 0
        self._cache: dict | None = None

    def resolve(self, path: str, key: str | None = None):
        cache_key = f'{path}#{key}'

        if self._cache is not None and cache_key in self._cache:
            return self._cache[cache_key]

        self.resolve_count += 1
        value = self.secrets.get(cache_key)
        if value is None:
            raise KeyError(f'Secret not found: {cache_key}')

        if self._cache is not None:
            self._cache[cache_key] = value

        return value

    def caching(self):
        @contextmanager
        def _caching():
            self._cache = {}
            try:
                yield
            finally:
                self._cache = None

        return _caching()
