import json
from http import HTTPStatus
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest

from justconf import AuthenticationError, NoValidAuthError, SecretNotFoundError
from justconf.processor import (
    AppRoleAuth,
    JwtAuth,
    KubernetesAuth,
    TokenAuth,
    UserpassAuth,
    VaultProcessor,
)


class TestTokenAuth:
    def test_authenticate__valid_token__returns_token_and_ttl(self):
        # arrange
        auth = TokenAuth(token='hvs.test_token')
        mock_response = {
            'data': {'ttl': 7200},
        }

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            token, ttl = auth.authenticate('http://vault:8200')

        # assert
        assert token == 'hvs.test_token'
        assert ttl == 7200

    def test_authenticate__empty_token__raises_error(self):
        # arrange
        auth = TokenAuth(token='')

        # act & assert
        with pytest.raises(AuthenticationError, match='Token is empty'):
            auth.authenticate('http://vault:8200')

    def test_authenticate__invalid_token__raises_error(self):
        # arrange
        auth = TokenAuth(token='invalid')

        # act & assert
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = create_http_error(HTTPStatus.FORBIDDEN)
            with pytest.raises(AuthenticationError, match='Invalid token'):
                auth.authenticate('http://vault:8200')


class TestAppRoleAuth:
    def test_authenticate__valid_credentials__returns_token(self):
        # arrange
        auth = AppRoleAuth(role_id='role123', secret_id='secret456')
        mock_response = {
            'auth': {
                'client_token': 'hvs.new_token',
                'lease_duration': 3600,
            },
        }

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            token, ttl = auth.authenticate('http://vault:8200')

        # assert
        assert token == 'hvs.new_token'
        assert ttl == 3600

    def test_authenticate__empty_credentials__raises_error(self):
        # arrange
        auth = AppRoleAuth(role_id='', secret_id='')

        # act & assert
        with pytest.raises(AuthenticationError, match='role_id and secret_id are required'):
            auth.authenticate('http://vault:8200')

    def test_authenticate__custom_mount_path__uses_path(self):
        # arrange
        auth = AppRoleAuth(role_id='role', secret_id='secret', mount_path='custom-approle')
        mock_response = {'auth': {'client_token': 'token', 'lease_duration': 3600}}

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            auth.authenticate('http://vault:8200')

            # assert
            call_args = mock_urlopen.call_args[0][0]
            assert '/auth/custom-approle/login' in call_args.full_url


class TestJwtAuth:
    def test_authenticate__valid_jwt__returns_token(self):
        # arrange
        auth = JwtAuth(role='myproject', jwt='eyJ...')
        mock_response = {
            'auth': {
                'client_token': 'hvs.jwt_token',
                'lease_duration': 1800,
            },
        }

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            token, ttl = auth.authenticate('http://vault:8200')

        # assert
        assert token == 'hvs.jwt_token'
        assert ttl == 1800

    def test_authenticate__empty_jwt__raises_error(self):
        # arrange
        auth = JwtAuth(role='myproject', jwt='')

        # act & assert
        with pytest.raises(AuthenticationError, match='JWT token is empty'):
            auth.authenticate('http://vault:8200')


class TestKubernetesAuth:
    def test_authenticate__with_jwt_param__uses_jwt(self):
        # arrange
        auth = KubernetesAuth(role='myapp', jwt='sa_token_content')
        mock_response = {
            'auth': {
                'client_token': 'hvs.k8s_token',
                'lease_duration': 3600,
            },
        }

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            token, ttl = auth.authenticate('http://vault:8200')

        # assert
        assert token == 'hvs.k8s_token'
        assert ttl == 3600

    def test_authenticate__jwt_from_file__reads_file(self, tmp_path):
        # arrange
        jwt_file = tmp_path / 'token'
        jwt_file.write_text('file_token_content')
        auth = KubernetesAuth(role='myapp', jwt_path=str(jwt_file))
        mock_response = {'auth': {'client_token': 'hvs.token', 'lease_duration': 3600}}

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            auth.authenticate('http://vault:8200')

            # assert
            call_args = mock_urlopen.call_args[0][0]
            body = json.loads(call_args.data)
            assert body['jwt'] == 'file_token_content'

    def test_jwt_property__file_not_found__raises_error(self):
        # arrange
        auth = KubernetesAuth(role='myapp', jwt_path='/nonexistent/token')

        # act & assert
        with pytest.raises(AuthenticationError, match='Kubernetes SA token not found'):
            _ = auth.jwt


class TestUserpassAuth:
    def test_authenticate__valid_credentials__returns_token(self):
        # arrange
        auth = UserpassAuth(username='admin', password='secret')
        mock_response = {
            'auth': {
                'client_token': 'hvs.userpass_token',
                'lease_duration': 3600,
            },
        }

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            token, ttl = auth.authenticate('http://vault:8200')

        # assert
        assert token == 'hvs.userpass_token'
        assert ttl == 3600

    def test_authenticate__empty_credentials__raises_error(self):
        # arrange
        auth = UserpassAuth(username='', password='')

        # act & assert
        with pytest.raises(AuthenticationError, match='Username and password are required'):
            auth.authenticate('http://vault:8200')


class TestVaultProcessor:
    def test_resolve__simple_secret__returns_value(self):
        # arrange
        processor = create_processor_with_mock_auth()
        mock_secret_response = {
            'data': {
                'data': {'password': 'secret123'},
            },
        }

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
                mock_secret_response
            ).encode()
            result = processor.resolve('secret/db', 'password')

        # assert
        assert result == 'secret123'

    def test_resolve__without_key__returns_all_data(self):
        # arrange
        processor = create_processor_with_mock_auth()
        mock_secret_response = {
            'data': {
                'data': {'user': 'admin', 'pass': 'secret'},
            },
        }

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
                mock_secret_response
            ).encode()
            result = processor.resolve('secret/db')

        # assert
        assert result == {'user': 'admin', 'pass': 'secret'}

    def test_resolve__secret_not_found__raises_error(self):
        # arrange
        processor = create_processor_with_mock_auth()

        def side_effect(*args, **kwargs):
            url = args[0].full_url if hasattr(args[0], 'full_url') else str(args[0])
            if 'lookup-self' in url:
                mock = MagicMock()
                mock.__enter__.return_value.read.return_value = json.dumps({'data': {'ttl': 3600}}).encode()
                return mock
            raise create_http_error(HTTPStatus.NOT_FOUND)

        # act & assert
        with patch('urllib.request.urlopen', side_effect=side_effect):
            with pytest.raises(SecretNotFoundError, match='Secret not found'):
                processor.resolve('secret/nonexistent', 'key')

    def test_resolve__key_not_found__raises_error(self):
        # arrange
        processor = create_processor_with_mock_auth()
        mock_secret_response = {
            'data': {
                'data': {'other_key': 'value'},
            },
        }

        # act & assert
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
                mock_secret_response
            ).encode()
            with pytest.raises(SecretNotFoundError, match="Key 'password' not found"):
                processor.resolve('secret/db', 'password')

    def test_resolve__caching_enabled__returns_cached_value(self):
        # arrange
        processor = create_processor_with_mock_auth()
        mock_secret_response = {
            'data': {'data': {'password': 'secret'}},
        }
        call_count = 0

        def mock_urlopen_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock = MagicMock()
            mock.__enter__.return_value.read.return_value = json.dumps(mock_secret_response).encode()
            return mock

        # act
        with patch('urllib.request.urlopen', side_effect=mock_urlopen_side_effect):
            with processor.caching():
                processor.resolve('secret/db', 'password')
                processor.resolve('secret/db', 'password')
                processor.resolve('secret/db', 'password')

        # assert (1 auth call + 1 secret call = 2, not 4)
        assert call_count == 2

    def test_auth_fallback__first_fails_second_succeeds__uses_second(self):
        # arrange
        failing_auth = TokenAuth(token='')
        succeeding_auth = TokenAuth(token='valid_token')
        processor = VaultProcessor(
            url='http://vault:8200',
            auth=[failing_auth, succeeding_auth],
        )

        mock_token_response = {'data': {'ttl': 3600}}
        mock_secret_response = {'data': {'data': {'key': 'value'}}}

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
                mock_token_response
            ).encode()

            # first call is token lookup, second is secret fetch
            def side_effect(*args, **kwargs):
                mock = MagicMock()
                # determine if this is auth or secret request
                url = args[0].full_url if hasattr(args[0], 'full_url') else str(args[0])
                if 'lookup-self' in url:
                    mock.__enter__.return_value.read.return_value = json.dumps(mock_token_response).encode()
                else:
                    mock.__enter__.return_value.read.return_value = json.dumps(mock_secret_response).encode()
                return mock

            mock_urlopen.side_effect = side_effect
            result = processor.resolve('secret/test', 'key')

        # assert
        assert result == 'value'

    def test_auth_fallback__all_fail__raises_no_valid_auth_error(self):
        # arrange
        processor = VaultProcessor(
            url='http://vault:8200',
            auth=[
                TokenAuth(token=''),
                AppRoleAuth(role_id='', secret_id=''),
            ],
        )

        # act & assert
        with pytest.raises(NoValidAuthError, match='All authentication methods failed'):
            processor.resolve('secret/test', 'key')

    def test_token_caching__reuses_token_within_ttl(self):
        # arrange
        processor = create_processor_with_mock_auth()
        mock_secret_response = {'data': {'data': {'key': 'value'}}}
        auth_call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal auth_call_count
            mock = MagicMock()
            url = args[0].full_url if hasattr(args[0], 'full_url') else str(args[0])
            if 'lookup-self' in url:
                auth_call_count += 1
                mock.__enter__.return_value.read.return_value = json.dumps({'data': {'ttl': 3600}}).encode()
            else:
                mock.__enter__.return_value.read.return_value = json.dumps(mock_secret_response).encode()
            return mock

        # act
        with patch('urllib.request.urlopen', side_effect=side_effect):
            processor.resolve('secret/a', 'key')
            processor.resolve('secret/b', 'key')
            processor.resolve('secret/c', 'key')

        # assert (only 1 auth call, not 3)
        assert auth_call_count == 1


# fixtures and helpers


def create_processor_with_mock_auth():
    return VaultProcessor(
        url='http://vault:8200',
        auth=TokenAuth(token='test_token'),
    )


def create_http_error(status_code):
    return HTTPError(
        url='http://vault:8200',
        code=status_code,
        msg=str(status_code),
        hdrs={},
        fp=None,
    )
