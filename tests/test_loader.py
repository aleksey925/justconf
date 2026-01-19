import importlib
import sys
from unittest.mock import patch

import pytest

import justconf.loader
from justconf import TomlLoadError, dotenv_loader, env_loader, toml_loader


class TestEnvLoader:
    def test_env_loader__no_prefix__loads_all(self, monkeypatch):
        # arrange
        monkeypatch.setenv('TEST_VAR_A', 'value_a')
        monkeypatch.setenv('TEST_VAR_B', 'value_b')

        # act
        result = env_loader()

        # assert
        assert result['test_var_a'] == 'value_a'
        assert result['test_var_b'] == 'value_b'

    def test_env_loader__with_prefix__filters_and_strips(self, monkeypatch):
        # arrange
        monkeypatch.setenv('APP_DATABASE_HOST', 'localhost')
        monkeypatch.setenv('APP_DEBUG', 'true')
        monkeypatch.setenv('OTHER_VAR', 'ignored')

        # act
        result = env_loader(prefix='APP')

        # assert
        assert result == {'database_host': 'localhost', 'debug': 'true'}

    def test_env_loader__case_sensitive_false__lowercase_keys(self, monkeypatch):
        # arrange
        monkeypatch.setenv('APP_Database_HOST', 'localhost')

        # act
        result = env_loader(prefix='APP', case_sensitive=False)

        # assert
        assert result == {'database_host': 'localhost'}

    def test_env_loader__case_sensitive_true__preserves_case(self, monkeypatch):
        # arrange
        monkeypatch.setenv('APP_Database_HOST', 'localhost')

        # act
        result = env_loader(prefix='APP', case_sensitive=True)

        # assert
        assert result == {'Database_HOST': 'localhost'}

    def test_env_loader__nested_keys__creates_nested_dict(self, monkeypatch):
        # arrange
        monkeypatch.setenv('APP_DATABASE__HOST', 'localhost')
        monkeypatch.setenv('APP_DATABASE__PORT', '5432')

        # act
        result = env_loader(prefix='APP')

        # assert
        assert result == {'database': {'host': 'localhost', 'port': '5432'}}

    def test_env_loader__deeply_nested__creates_deep_structure(self, monkeypatch):
        # arrange
        monkeypatch.setenv('APP_LEVEL1__LEVEL2__LEVEL3', 'deep_value')

        # act
        result = env_loader(prefix='APP')

        # assert
        assert result == {'level1': {'level2': {'level3': 'deep_value'}}}

    def test_env_loader__empty_value__preserved(self, monkeypatch):
        # arrange
        monkeypatch.setenv('APP_DEBUG', '')

        # act
        result = env_loader(prefix='APP')

        # assert
        assert result == {'debug': ''}

    def test_env_loader__prefix_only_var__ignored(self, monkeypatch):
        # arrange
        monkeypatch.setenv('APP_', 'should_be_ignored')
        monkeypatch.setenv('APP_VALID', 'valid_value')

        # act
        result = env_loader(prefix='APP')

        # assert
        assert result == {'valid': 'valid_value'}

    def test_env_loader__no_matching_prefix__returns_empty(self, monkeypatch):
        # arrange
        monkeypatch.setenv('OTHER_VAR', 'value')

        # act
        result = env_loader(prefix='APP')

        # assert
        assert result == {}

    def test_env_loader__prefix_case_insensitive_match(self, monkeypatch):
        # arrange
        monkeypatch.setenv('app_debug', 'true')

        # act
        result = env_loader(prefix='APP', case_sensitive=False)

        # assert
        assert result == {'debug': 'true'}

    def test_env_loader__case_sensitive_true_without_prefix__preserves_case(self, monkeypatch):
        # arrange
        monkeypatch.setenv('MyApp_Config', 'value')

        # act
        result = env_loader(case_sensitive=True)

        # assert
        assert result['MyApp_Config'] == 'value'

    def test_env_loader__nested_keys_case_sensitive__preserves_nested_case(self, monkeypatch):
        # arrange
        monkeypatch.setenv('APP_Database__Host', 'localhost')
        monkeypatch.setenv('APP_Database__Port', '5432')

        # act
        result = env_loader(prefix='APP', case_sensitive=True)

        # assert
        assert result == {'Database': {'Host': 'localhost', 'Port': '5432'}}

    def test_env_loader__prefix_case_sensitive_true__filters_exact_match(self, monkeypatch):
        # arrange
        monkeypatch.setenv('APP_VALUE', 'correct')
        monkeypatch.setenv('app_VALUE', 'ignored')

        # act
        result = env_loader(prefix='APP', case_sensitive=True)

        # assert
        assert result == {'VALUE': 'correct'}

    def test_env_loader__deeply_nested_overwrites_existing_value(self, monkeypatch):
        # arrange
        monkeypatch.setenv('APP_DB', 'simple_value')
        monkeypatch.setenv('APP_DB__HOST', 'localhost')

        # act
        result = env_loader(prefix='APP')

        # assert (nested key overwrites scalar)
        assert result == {'db': {'host': 'localhost'}}


class TestDotenvLoader:
    def test_dotenv_loader__basic_file__loads_values(self, tmp_path):
        # arrange
        env_file = tmp_path / '.env'
        env_file.write_text('FOO=bar\nBAZ=qux\n')

        # act
        result = dotenv_loader(str(env_file))

        # assert
        assert result == {'foo': 'bar', 'baz': 'qux'}

    def test_dotenv_loader__with_prefix__filters_and_strips(self, tmp_path):
        # arrange
        env_file = tmp_path / '.env'
        env_file.write_text('APP_DEBUG=true\nOTHER=ignored\n')

        # act
        result = dotenv_loader(str(env_file), prefix='APP')

        # assert
        assert result == {'debug': 'true'}

    def test_dotenv_loader__case_sensitive_true__preserves_case(self, tmp_path):
        # arrange
        env_file = tmp_path / '.env'
        env_file.write_text('APP_Database=value\n')

        # act
        result = dotenv_loader(str(env_file), prefix='APP', case_sensitive=True)

        # assert
        assert result == {'Database': 'value'}

    def test_dotenv_loader__nested_keys__creates_nested_dict(self, tmp_path):
        # arrange
        env_file = tmp_path / '.env'
        env_file.write_text('DATABASE__HOST=localhost\nDATABASE__PORT=5432\n')

        # act
        result = dotenv_loader(str(env_file))

        # assert
        assert result == {'database': {'host': 'localhost', 'port': '5432'}}

    def test_dotenv_loader__interpolation__works(self, tmp_path):
        # arrange
        env_file = tmp_path / '.env'
        env_file.write_text('BASE_DIR=/app\nDATA_DIR=${BASE_DIR}/data\n')

        # act
        result = dotenv_loader(str(env_file))

        # assert
        assert result == {'base_dir': '/app', 'data_dir': '/app/data'}

    def test_dotenv_loader__file_not_found__raises(self):
        # act & assert
        with pytest.raises(FileNotFoundError):
            dotenv_loader('/nonexistent/path/.env')

    def test_dotenv_loader__empty_file__returns_empty(self, tmp_path):
        # arrange
        env_file = tmp_path / '.env'
        env_file.write_text('')

        # act
        result = dotenv_loader(str(env_file))

        # assert
        assert result == {}

    def test_dotenv_loader__custom_encoding(self, tmp_path):
        # arrange
        env_file = tmp_path / '.env'
        env_file.write_bytes('MESSAGE=привет\n'.encode())

        # act
        result = dotenv_loader(str(env_file), encoding='utf-8')

        # assert
        assert result == {'message': 'привет'}

    def test_dotenv_loader__quoted_values__handled(self, tmp_path):
        # arrange
        env_file = tmp_path / '.env'
        env_file.write_text('FOO="bar baz"\nBAR=\'single\'\n')

        # act
        result = dotenv_loader(str(env_file))

        # assert
        assert result == {'foo': 'bar baz', 'bar': 'single'}

    def test_dotenv_loader__python_dotenv_not_installed__raises_import_error(self, tmp_path):
        # arrange
        env_file = tmp_path / '.env'
        env_file.write_text('FOO=bar\n')

        # act & assert
        with patch.dict(sys.modules, {'dotenv': None}):
            importlib.reload(justconf.loader)

            with pytest.raises(ImportError, match='python-dotenv is required'):
                justconf.loader.dotenv_loader(str(env_file))

            importlib.reload(justconf.loader)

    def test_dotenv_loader__comments_and_empty_lines__handled(self, tmp_path):
        # arrange
        env_file = tmp_path / '.env'
        env_file.write_text(
            """
# This is a comment
FOO=bar

# Another comment
BAZ=qux
"""
        )

        # act
        result = dotenv_loader(str(env_file))

        # assert
        assert result == {'foo': 'bar', 'baz': 'qux'}

    def test_dotenv_loader__nested_keys_case_sensitive__preserves_case(self, tmp_path):
        # arrange
        env_file = tmp_path / '.env'
        env_file.write_text('Database__Host=localhost\nDatabase__Port=5432\n')

        # act
        result = dotenv_loader(str(env_file), case_sensitive=True)

        # assert
        assert result == {'Database': {'Host': 'localhost', 'Port': '5432'}}


class TestTomlLoader:
    def test_toml_loader__basic_file__loads_values(self, tmp_path):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_text('name = "myapp"\ndebug = true\n')

        # act
        result = toml_loader(str(toml_file))

        # assert
        assert result == {'name': 'myapp', 'debug': True}

    def test_toml_loader__nested_tables__preserves_structure(self, tmp_path):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_text(
            """
[database]
host = "localhost"
port = 5432

[database.pool]
size = 10
"""
        )

        # act
        result = toml_loader(str(toml_file))

        # assert
        assert result == {'database': {'host': 'localhost', 'port': 5432, 'pool': {'size': 10}}}

    def test_toml_loader__preserves_types(self, tmp_path):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_text(
            """
string = "hello"
integer = 42
float_val = 3.14
boolean = true
array = [1, 2, 3]
date = 2024-01-15
"""
        )

        # act
        result = toml_loader(str(toml_file))

        # assert
        assert result['string'] == 'hello'
        assert result['integer'] == 42
        assert result['float_val'] == 3.14
        assert result['boolean'] is True
        assert result['array'] == [1, 2, 3]
        assert str(result['date']) == '2024-01-15'

    def test_toml_loader__file_not_found__raises(self):
        # act & assert
        with pytest.raises(FileNotFoundError):
            toml_loader('/nonexistent/config.toml')

    def test_toml_loader__invalid_toml__raises_toml_load_error(self, tmp_path):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_text('invalid = [unclosed\n')

        # act & assert
        with pytest.raises(TomlLoadError) as exc_info:
            toml_loader(str(toml_file))

        assert 'Failed to parse' in str(exc_info.value)

    def test_toml_loader__empty_file__returns_empty(self, tmp_path):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_text('')

        # act
        result = toml_loader(str(toml_file))

        # assert
        assert result == {}

    def test_toml_loader__custom_encoding(self, tmp_path):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_bytes('message = "привет"\n'.encode())

        # act
        result = toml_loader(str(toml_file), encoding='utf-8')

        # assert
        assert result == {'message': 'привет'}

    def test_toml_loader__exception_chain_preserved(self, tmp_path):
        # arrange
        toml_file = tmp_path / 'config.toml'
        toml_file.write_text('invalid = [')

        # act & assert
        with pytest.raises(TomlLoadError) as exc_info:
            toml_loader(str(toml_file))

        assert exc_info.value.__cause__ is not None
