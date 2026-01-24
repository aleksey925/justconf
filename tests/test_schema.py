from dataclasses import dataclass
from typing import Annotated

import msgspec
import pytest
from pydantic import BaseModel

from justconf.schema import Placeholder, extract_placeholders


class TestExtractPlaceholdersPlainClass:
    def test_extract_placeholders__plain_class_with_placeholder__returns_placeholder_value(
        self,
    ):
        # arrange
        class Config:
            password: Annotated[str, Placeholder('${vault:secret/data/db#password}')]

        # act
        result = extract_placeholders(Config)

        # assert
        assert result == {'password': '${vault:secret/data/db#password}'}

    def test_extract_placeholders__deeply_nested_plain_classes__recursive_extraction(self):
        # arrange
        class Inner:
            secret: Annotated[str, Placeholder('${vault:secret/data/inner#secret}')]

        class Middle:
            inner: Inner
            key: Annotated[str, Placeholder('${vault:secret/data/middle#key}')]

        class Outer:
            middle: Middle

        # act
        result = extract_placeholders(Outer)

        # assert
        assert result == {
            'middle': {
                'inner': {'secret': '${vault:secret/data/inner#secret}'},
                'key': '${vault:secret/data/middle#key}',
            },
        }

    def test_extract_placeholders__mixed_fields__only_placeholders_extracted(self):
        # arrange
        class Config:
            host: str = 'localhost'
            port: int = 5432
            password: Annotated[str, Placeholder('${vault:secret/data/db#password}')]
            debug: bool = False

        # act
        result = extract_placeholders(Config)

        # assert
        assert result == {'password': '${vault:secret/data/db#password}'}

    def test_extract_placeholders__multiple_placeholders__all_extracted(self):
        # arrange
        class Config:
            db_password: Annotated[str, Placeholder('${vault:secret/data/db#password}')]
            api_key: Annotated[str, Placeholder('${vault:secret/data/api#key}')]
            token: Annotated[str, Placeholder('${env:AUTH_TOKEN}')]

        # act
        result = extract_placeholders(Config)

        # assert
        assert result == {
            'db_password': '${vault:secret/data/db#password}',
            'api_key': '${vault:secret/data/api#key}',
            'token': '${env:AUTH_TOKEN}',
        }

    def test_extract_placeholders__annotated_without_placeholder__ignored(self):
        # arrange
        class Config:
            name: Annotated[str, 'some other annotation']
            password: Annotated[str, Placeholder('${vault:secret/data/db#password}')]

        # act
        result = extract_placeholders(Config)

        # assert
        assert result == {'password': '${vault:secret/data/db#password}'}

    def test_extract_placeholders__empty_class__returns_empty_dict(self):
        # arrange
        class EmptyConfig:
            pass

        # act
        result = extract_placeholders(EmptyConfig)

        # assert
        assert result == {}


class TestExtractPlaceholdersDataclass:
    def test_extract_placeholders__dataclass_with_placeholder__returns_placeholder_value(
        self,
    ):
        # arrange
        @dataclass
        class Config:
            token: Annotated[str, Placeholder('${vault:secret/data/auth#token}')]

        # act
        result = extract_placeholders(Config)

        # assert
        assert result == {'token': '${vault:secret/data/auth#token}'}

    def test_extract_placeholders__nested_dataclasses__recursive_extraction(self):
        # arrange
        @dataclass
        class DatabaseConfig:
            password: Annotated[str, Placeholder('${vault:secret/data/db/creds#password}')]
            host: str = 'localhost'

        @dataclass
        class AppConfig:
            api_key: Annotated[str, Placeholder('${vault:secret/data/api#key}')]
            database: DatabaseConfig = None  # type: ignore[assignment]

        # act
        result = extract_placeholders(AppConfig)

        # assert
        assert result == {
            'database': {'password': '${vault:secret/data/db/creds#password}'},
            'api_key': '${vault:secret/data/api#key}',
        }

    def test_extract_placeholders__no_placeholders__returns_empty_dict(self):
        # arrange
        @dataclass
        class Config:
            host: str = 'localhost'
            port: int = 5432
            debug: bool = False

        # act
        result = extract_placeholders(Config)

        # assert
        assert result == {}

    def test_extract_placeholders__nested_without_placeholders__not_included(self):
        # arrange
        @dataclass
        class DatabaseConfig:
            host: str = 'localhost'
            port: int = 5432

        @dataclass
        class AppConfig:
            database: DatabaseConfig
            api_key: Annotated[str, Placeholder('${vault:secret/data/api#key}')]

        # act
        result = extract_placeholders(AppConfig)

        # assert
        assert result == {'api_key': '${vault:secret/data/api#key}'}


class TestExtractPlaceholdersPydantic:
    def test_extract_placeholders__pydantic_model_with_placeholder__returns_placeholder_value(
        self,
    ):
        # arrange
        class Config(BaseModel):
            api_key: Annotated[str, Placeholder('${vault:secret/data/api#key}')]

        # act
        result = extract_placeholders(Config)

        # assert
        assert result == {'api_key': '${vault:secret/data/api#key}'}

    def test_extract_placeholders__nested_pydantic_models__recursive_extraction(self):
        # arrange
        class DatabaseConfig(BaseModel):
            host: str = 'localhost'
            password: Annotated[str, Placeholder('${vault:secret/data/db/creds#password}')]

        class AppConfig(BaseModel):
            database: DatabaseConfig
            api_key: Annotated[str, Placeholder('${vault:secret/data/api#key}')]

        # act
        result = extract_placeholders(AppConfig)

        # assert
        assert result == {
            'database': {'password': '${vault:secret/data/db/creds#password}'},
            'api_key': '${vault:secret/data/api#key}',
        }

    def test_extract_placeholders__pydantic_no_placeholders__returns_empty_dict(self):
        # arrange
        class Config(BaseModel):
            host: str = 'localhost'
            port: int = 5432

        # act
        result = extract_placeholders(Config)

        # assert
        assert result == {}

    def test_extract_placeholders__pydantic_mixed_fields__only_placeholders_extracted(self):
        # arrange
        class Config(BaseModel):
            host: str = 'localhost'
            password: Annotated[str, Placeholder('${vault:secret/data/db#password}')]
            debug: bool = False

        # act
        result = extract_placeholders(Config)

        # assert
        assert result == {'password': '${vault:secret/data/db#password}'}


class TestExtractPlaceholdersMsgspec:
    def test_extract_placeholders__msgspec_struct_with_placeholder__returns_placeholder_value(
        self,
    ):
        # arrange
        class Config(msgspec.Struct):
            api_key: Annotated[str, Placeholder('${vault:secret/data/api#key}')]

        # act
        result = extract_placeholders(Config)

        # assert
        assert result == {'api_key': '${vault:secret/data/api#key}'}

    def test_extract_placeholders__nested_msgspec_structs__recursive_extraction(self):
        # arrange
        class DatabaseConfig(msgspec.Struct):
            password: Annotated[str, Placeholder('${vault:secret/data/db/creds#password}')]
            host: str = 'localhost'

        class AppConfig(msgspec.Struct):
            api_key: Annotated[str, Placeholder('${vault:secret/data/api#key}')]
            database: DatabaseConfig = None  # type: ignore[assignment]

        # act
        result = extract_placeholders(AppConfig)

        # assert
        assert result == {
            'database': {'password': '${vault:secret/data/db/creds#password}'},
            'api_key': '${vault:secret/data/api#key}',
        }

    def test_extract_placeholders__msgspec_no_placeholders__returns_empty_dict(self):
        # arrange
        class Config(msgspec.Struct):
            host: str = 'localhost'
            port: int = 5432

        # act
        result = extract_placeholders(Config)

        # assert
        assert result == {}

    def test_extract_placeholders__msgspec_mixed_fields__only_placeholders_extracted(self):
        # arrange
        class Config(msgspec.Struct):
            password: Annotated[str, Placeholder('${vault:secret/data/db#password}')]
            host: str = 'localhost'
            debug: bool = False

        # act
        result = extract_placeholders(Config)

        # assert
        assert result == {'password': '${vault:secret/data/db#password}'}


class TestPlaceholder:
    def test_placeholder__is_frozen(self):
        # arrange
        placeholder = Placeholder('${vault:test#value}')

        # act & assert
        with pytest.raises(AttributeError):
            placeholder.value = 'new value'  # type: ignore[misc]

    def test_placeholder__equality(self):
        # arrange
        placeholder1 = Placeholder('${vault:test#value}')
        placeholder2 = Placeholder('${vault:test#value}')
        placeholder3 = Placeholder('${vault:other#value}')

        # assert
        assert placeholder1 == placeholder2
        assert placeholder1 != placeholder3

    def test_placeholder__hashable(self):
        # arrange
        placeholder1 = Placeholder('${vault:test#value}')
        placeholder2 = Placeholder('${vault:test#value}')

        # act
        result = {placeholder1, placeholder2}

        # assert
        assert len(result) == 1
