import json
import ssl
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
    vault_auth_from_env,
)
from justconf.processor.vault import (
    _create_ssl_context,
    _detect_approle_auth,
    _detect_jwt_auth,
    _detect_kubernetes_auth,
    _detect_token_auth,
    _detect_userpass_auth,
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

    def test_authenticate__http_error__raises_auth_error(self):
        # arrange
        auth = AppRoleAuth(role_id='role', secret_id='secret')

        # act & assert
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = create_http_error(HTTPStatus.FORBIDDEN)
            with pytest.raises(AuthenticationError, match='AppRole authentication failed'):
                auth.authenticate('http://vault:8200')

    def test_authenticate__invalid_response__raises_auth_error(self):
        # arrange
        auth = AppRoleAuth(role_id='role', secret_id='secret')
        mock_response = {'auth': {}}  # missing client_token

        # act & assert
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            with pytest.raises(AuthenticationError, match='Invalid response'):
                auth.authenticate('http://vault:8200')


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

    def test_authenticate__custom_mount_path__uses_path(self):
        # arrange
        auth = JwtAuth(role='myproject', jwt='eyJ...', mount_path='oidc')
        mock_response = {'auth': {'client_token': 'token', 'lease_duration': 3600}}

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            auth.authenticate('http://vault:8200')

            # assert
            call_args = mock_urlopen.call_args[0][0]
            assert '/auth/oidc/login' in call_args.full_url

    def test_authenticate__http_error__raises_auth_error(self):
        # arrange
        auth = JwtAuth(role='myproject', jwt='invalid')

        # act & assert
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = create_http_error(HTTPStatus.FORBIDDEN)
            with pytest.raises(AuthenticationError, match='JWT authentication failed'):
                auth.authenticate('http://vault:8200')

    def test_authenticate__invalid_response__raises_auth_error(self):
        # arrange
        auth = JwtAuth(role='myproject', jwt='valid')
        mock_response = {'auth': {}}  # missing client_token

        # act & assert
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            with pytest.raises(AuthenticationError, match='Invalid response'):
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

    def test_authenticate__custom_mount_path__uses_path(self):
        # arrange
        auth = KubernetesAuth(role='myapp', jwt='token', mount_path='k8s-cluster')
        mock_response = {'auth': {'client_token': 'token', 'lease_duration': 3600}}

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            auth.authenticate('http://vault:8200')

            # assert
            call_args = mock_urlopen.call_args[0][0]
            assert '/auth/k8s-cluster/login' in call_args.full_url

    def test_authenticate__http_error__raises_auth_error(self):
        # arrange
        auth = KubernetesAuth(role='myapp', jwt='token')

        # act & assert
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = create_http_error(HTTPStatus.FORBIDDEN)
            with pytest.raises(AuthenticationError, match='Kubernetes authentication failed'):
                auth.authenticate('http://vault:8200')

    def test_authenticate__invalid_response__raises_auth_error(self):
        # arrange
        auth = KubernetesAuth(role='myapp', jwt='token')
        mock_response = {'auth': {}}  # missing client_token

        # act & assert
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            with pytest.raises(AuthenticationError, match='Invalid response'):
                auth.authenticate('http://vault:8200')

    def test_jwt_property__with_jwt_param__returns_param(self):
        # arrange
        auth = KubernetesAuth(role='myapp', jwt='direct_token')

        # act & assert
        assert auth.jwt == 'direct_token'


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

    def test_authenticate__custom_mount_path__uses_path(self):
        # arrange
        auth = UserpassAuth(username='admin', password='secret', mount_path='ldap')
        mock_response = {'auth': {'client_token': 'token', 'lease_duration': 3600}}

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            auth.authenticate('http://vault:8200')

            # assert
            call_args = mock_urlopen.call_args[0][0]
            assert '/auth/ldap/login/admin' in call_args.full_url

    def test_authenticate__http_error__raises_auth_error(self):
        # arrange
        auth = UserpassAuth(username='admin', password='wrong')

        # act & assert
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = create_http_error(HTTPStatus.FORBIDDEN)
            with pytest.raises(AuthenticationError, match='Userpass authentication failed'):
                auth.authenticate('http://vault:8200')

    def test_authenticate__invalid_response__raises_auth_error(self):
        # arrange
        auth = UserpassAuth(username='admin', password='secret')
        mock_response = {'auth': {}}  # missing client_token

        # act & assert
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            with pytest.raises(AuthenticationError, match='Invalid response'):
                auth.authenticate('http://vault:8200')


class TestVaultProcessor:
    def test_init__invalid_url_scheme__raises_error(self):
        # act & assert
        with pytest.raises(ValueError, match='Invalid Vault URL scheme'):
            VaultProcessor(
                url='ftp://vault:8200',
                auth=TokenAuth(token='test'),
            )

    def test_init__missing_host__raises_error(self):
        # act & assert
        with pytest.raises(ValueError, match=r'Invalid Vault URL.*missing host'):
            VaultProcessor(
                url='http://',
                auth=TokenAuth(token='test'),
            )

    def test_init__url_trailing_slash__stripped(self):
        # act
        processor = VaultProcessor(
            url='http://vault:8200/',
            auth=TokenAuth(token='test'),
        )

        # assert
        assert processor.url == 'http://vault:8200'

    def test_init__full_path_used_in_requests(self):
        # arrange
        processor = VaultProcessor(
            url='http://vault:8200',
            auth=TokenAuth(token='test_token'),
        )
        mock_token_response = {'data': {'ttl': 3600}}
        mock_secret_response = {'data': {'data': {'key': 'value'}}}

        def side_effect(*args, **kwargs):
            mock = MagicMock()
            url = args[0].full_url if hasattr(args[0], 'full_url') else str(args[0])
            if 'lookup-self' in url:
                mock.__enter__.return_value.read.return_value = json.dumps(mock_token_response).encode()
            else:
                # verify full path is used as-is
                assert '/v1/kv/data/secret/test' in url
                mock.__enter__.return_value.read.return_value = json.dumps(mock_secret_response).encode()
            return mock

        # act
        with patch('urllib.request.urlopen', side_effect=side_effect):
            result = processor.resolve('kv/data/secret/test', 'key')

        # assert
        assert result == 'value'

    def test_init__custom_timeout__stored(self):
        # act
        processor = VaultProcessor(
            url='http://vault:8200',
            auth=TokenAuth(token='test'),
            timeout=60,
        )

        # assert
        assert processor.timeout == 60

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
            result = processor.resolve('secret/data/db', 'password')

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
            result = processor.resolve('secret/data/db')

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
                processor.resolve('secret/data/nonexistent', 'key')

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
                processor.resolve('secret/data/db', 'password')

    def test_resolve__path_with_trailing_slash__normalized(self):
        # arrange
        processor = create_processor_with_mock_auth()
        mock_secret_response = {'data': {'data': {'password': 'secret123'}}}

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
                mock_secret_response
            ).encode()
            result = processor.resolve('secret/data/database/', 'password')

            # assert
            call_args = mock_urlopen.call_args[0][0]
            assert '/v1/secret/data/database' in call_args.full_url
            assert '/v1/secret/data/database/' not in call_args.full_url
            assert result == 'secret123'

    def test_resolve__path_with_leading_slash__normalized(self):
        # arrange
        processor = create_processor_with_mock_auth()
        mock_secret_response = {'data': {'data': {'password': 'secret123'}}}

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
                mock_secret_response
            ).encode()
            result = processor.resolve('/secret/data/database', 'password')

            # assert
            call_args = mock_urlopen.call_args[0][0]
            assert '/v1/secret/data/database' in call_args.full_url
            assert '//secret' not in call_args.full_url
            assert result == 'secret123'

    def test_resolve__path_with_both_slashes__normalized(self):
        # arrange
        processor = create_processor_with_mock_auth()
        mock_secret_response = {'data': {'data': {'password': 'secret123'}}}

        # act
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
                mock_secret_response
            ).encode()
            result = processor.resolve('/secret/data/database/', 'password')

            # assert
            call_args = mock_urlopen.call_args[0][0]
            assert '/v1/secret/data/database' in call_args.full_url
            assert result == 'secret123'

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
                processor.resolve('secret/data/db', 'password')
                processor.resolve('secret/data/db', 'password')
                processor.resolve('secret/data/db', 'password')

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
            result = processor.resolve('secret/data/test', 'key')

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
            processor.resolve('secret/data/test', 'key')

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
            processor.resolve('secret/data/a', 'key')
            processor.resolve('secret/data/b', 'key')
            processor.resolve('secret/data/c', 'key')

        # assert (only 1 auth call, not 3)
        assert auth_call_count == 1

    def test_verify_false__disables_ssl_verification(self):
        # arrange
        processor = VaultProcessor(
            url='https://vault:8200',
            auth=TokenAuth(token='test'),
            verify=False,
        )

        # assert
        assert processor._ssl_context is not None
        assert processor._ssl_context.verify_mode == ssl.CERT_NONE
        assert processor._ssl_context.check_hostname is False

    def test_verify_custom_ca__uses_ca_bundle(self):
        # arrange
        mock_context = MagicMock(spec=ssl.SSLContext)

        # act
        with patch('ssl.create_default_context', return_value=mock_context) as mock_create:
            processor = VaultProcessor(
                url='https://vault:8200',
                auth=TokenAuth(token='test'),
                verify='/path/to/ca.crt',
            )

            # assert
            mock_create.assert_called_once_with(cafile='/path/to/ca.crt')
            assert processor._ssl_context is mock_context

    def test_verify_nonexistent_ca__raises_error(self):
        # act & assert
        with pytest.raises(FileNotFoundError, match='CA bundle file not found'):
            VaultProcessor(
                url='https://vault:8200',
                auth=TokenAuth(token='test'),
                verify='/nonexistent/ca.crt',
            )

    def test_ssl_context_passed_to_urlopen(self):
        # arrange
        processor = VaultProcessor(
            url='https://vault:8200',
            auth=TokenAuth(token='test'),
            verify=False,
        )
        mock_response = {'data': {'data': {'key': 'value'}}}

        def side_effect(*args, **kwargs):
            mock = MagicMock()
            url = args[0].full_url if hasattr(args[0], 'full_url') else str(args[0])
            if 'lookup-self' in url:
                mock.__enter__.return_value.read.return_value = json.dumps({'data': {'ttl': 3600}}).encode()
            else:
                mock.__enter__.return_value.read.return_value = json.dumps(mock_response).encode()
            return mock

        # act
        with patch('urllib.request.urlopen', side_effect=side_effect) as mock_urlopen:
            processor.resolve('secret/data/test', 'key')

            # assert
            for call in mock_urlopen.call_args_list:
                assert call.kwargs.get('context') is processor._ssl_context

    def test_resolve__token_expired_during_request__retries_with_new_token(self):
        # arrange
        processor = create_processor_with_mock_auth()
        mock_token_response = {'data': {'ttl': 3600}}
        mock_secret_response = {'data': {'data': {'key': 'value'}}}
        request_count = 0

        def side_effect(*args, **kwargs):
            nonlocal request_count
            request_count += 1
            mock = MagicMock()
            url = args[0].full_url if hasattr(args[0], 'full_url') else str(args[0])

            if 'lookup-self' in url:
                mock.__enter__.return_value.read.return_value = json.dumps(mock_token_response).encode()
            elif '/data/' in url:
                # first request fails with auth error, second succeeds
                if request_count == 2:
                    raise create_http_error(HTTPStatus.FORBIDDEN)
                mock.__enter__.return_value.read.return_value = json.dumps(mock_secret_response).encode()
            return mock

        # act
        with patch('urllib.request.urlopen', side_effect=side_effect):
            result = processor.resolve('secret/data/test', 'key')

        # assert
        assert result == 'value'
        # should have made: 1 token lookup, 1 failed secret request, 1 token re-auth, 1 successful secret request
        assert request_count == 4

    def test_resolve__multiple_auth_methods__tries_in_order(self):
        # arrange
        auth1 = AppRoleAuth(role_id='', secret_id='')  # will fail
        auth2 = TokenAuth(token='')  # will fail
        auth3 = TokenAuth(token='valid')  # will succeed

        processor = VaultProcessor(
            url='http://vault:8200',
            auth=[auth1, auth2, auth3],
        )

        mock_token_response = {'data': {'ttl': 3600}}
        mock_secret_response = {'data': {'data': {'key': 'value'}}}

        def side_effect(*args, **kwargs):
            mock = MagicMock()
            url = args[0].full_url if hasattr(args[0], 'full_url') else str(args[0])
            if 'lookup-self' in url:
                mock.__enter__.return_value.read.return_value = json.dumps(mock_token_response).encode()
            else:
                mock.__enter__.return_value.read.return_value = json.dumps(mock_secret_response).encode()
            return mock

        # act
        with patch('urllib.request.urlopen', side_effect=side_effect):
            result = processor.resolve('secret/data/test', 'key')

        # assert
        assert result == 'value'

    def test_caching__outside_context__does_not_cache(self):
        # arrange
        processor = create_processor_with_mock_auth()
        mock_secret_response = {'data': {'data': {'password': 'secret'}}}
        call_count = 0

        def mock_urlopen_side_effect(*args, **kwargs):
            nonlocal call_count
            mock = MagicMock()
            url = args[0].full_url if hasattr(args[0], 'full_url') else str(args[0])
            if '/data/' in url:
                call_count += 1
            if 'lookup-self' in url:
                mock.__enter__.return_value.read.return_value = json.dumps({'data': {'ttl': 3600}}).encode()
            else:
                mock.__enter__.return_value.read.return_value = json.dumps(mock_secret_response).encode()
            return mock

        # act (without caching context)
        with patch('urllib.request.urlopen', side_effect=mock_urlopen_side_effect):
            processor.resolve('secret/data/db', 'password')
            processor.resolve('secret/data/db', 'password')
            processor.resolve('secret/data/db', 'password')

        # assert (each call fetches secret)
        assert call_count == 3

    def test_name_property__returns_vault(self):
        # arrange
        processor = VaultProcessor(
            url='http://vault:8200',
            auth=TokenAuth(token='test'),
        )

        # assert
        assert processor.name == 'vault'


class TestCreateSslContext:
    def test_verify_true__returns_none(self):
        # act
        result = _create_ssl_context(True)

        # assert
        assert result is None

    def test_verify_false__returns_context_with_disabled_verification(self):
        # act
        result = _create_ssl_context(False)

        # assert
        assert isinstance(result, ssl.SSLContext)
        assert result.verify_mode == ssl.CERT_NONE
        assert result.check_hostname is False

    def test_verify_path__returns_context_with_custom_ca(self):
        # arrange
        mock_context = MagicMock(spec=ssl.SSLContext)

        # act
        with patch('ssl.create_default_context', return_value=mock_context) as mock_create:
            result = _create_ssl_context('/path/to/ca.crt')

        # assert
        mock_create.assert_called_once_with(cafile='/path/to/ca.crt')
        assert result is mock_context

    def test_verify_nonexistent_path__raises_file_not_found(self):
        # act & assert
        with pytest.raises(FileNotFoundError, match='CA bundle file not found'):
            _create_ssl_context('/nonexistent/ca.crt')


class TestDetectTokenAuth:
    def test_token_present__returns_token_auth(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_TOKEN', 'hvs.test_token')

        # act
        result = _detect_token_auth()

        # assert
        assert isinstance(result, TokenAuth)
        assert result.token == 'hvs.test_token'

    def test_token_absent__returns_none(self, monkeypatch):
        # arrange
        monkeypatch.delenv('VAULT_TOKEN', raising=False)

        # act
        result = _detect_token_auth()

        # assert
        assert result is None


class TestDetectAppRoleAuth:
    def test_both_credentials_present__returns_approle_auth(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_ROLE_ID', 'role123')
        monkeypatch.setenv('VAULT_SECRET_ID', 'secret456')

        # act
        result = _detect_approle_auth()

        # assert
        assert isinstance(result, AppRoleAuth)
        assert result.role_id == 'role123'
        assert result.secret_id == 'secret456'
        assert result.mount_path == 'approle'

    def test_custom_mount_path__uses_env_value(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_ROLE_ID', 'role123')
        monkeypatch.setenv('VAULT_SECRET_ID', 'secret456')
        monkeypatch.setenv('VAULT_APPROLE_MOUNT_PATH', 'custom-approle')

        # act
        result = _detect_approle_auth()

        # assert
        assert result.mount_path == 'custom-approle'

    def test_only_role_id__returns_none(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_ROLE_ID', 'role123')
        monkeypatch.delenv('VAULT_SECRET_ID', raising=False)

        # act
        result = _detect_approle_auth()

        # assert
        assert result is None

    def test_only_secret_id__returns_none(self, monkeypatch):
        # arrange
        monkeypatch.delenv('VAULT_ROLE_ID', raising=False)
        monkeypatch.setenv('VAULT_SECRET_ID', 'secret456')

        # act
        result = _detect_approle_auth()

        # assert
        assert result is None


class TestDetectKubernetesAuth:
    def test_role_present__returns_kubernetes_auth(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_KUBERNETES_ROLE', 'myapp')

        # act
        result = _detect_kubernetes_auth()

        # assert
        assert isinstance(result, KubernetesAuth)
        assert result.role == 'myapp'
        assert result.mount_path == 'kubernetes'

    def test_custom_mount_path__uses_env_value(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_KUBERNETES_ROLE', 'myapp')
        monkeypatch.setenv('VAULT_KUBERNETES_MOUNT_PATH', 'k8s-cluster')

        # act
        result = _detect_kubernetes_auth()

        # assert
        assert result.mount_path == 'k8s-cluster'

    def test_no_role__returns_none(self, monkeypatch):
        # arrange
        monkeypatch.delenv('VAULT_KUBERNETES_ROLE', raising=False)

        # act
        result = _detect_kubernetes_auth()

        # assert
        assert result is None


class TestDetectJwtAuth:
    def test_both_credentials_present__returns_jwt_auth(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_JWT_ROLE', 'myproject')
        monkeypatch.setenv('VAULT_JWT_TOKEN', 'eyJ...')

        # act
        result = _detect_jwt_auth()

        # assert
        assert isinstance(result, JwtAuth)
        assert result.role == 'myproject'
        assert result.jwt == 'eyJ...'
        assert result.mount_path == 'jwt'

    def test_custom_mount_path__uses_env_value(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_JWT_ROLE', 'myproject')
        monkeypatch.setenv('VAULT_JWT_TOKEN', 'eyJ...')
        monkeypatch.setenv('VAULT_JWT_MOUNT_PATH', 'oidc')

        # act
        result = _detect_jwt_auth()

        # assert
        assert result.mount_path == 'oidc'

    def test_only_role__returns_none(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_JWT_ROLE', 'myproject')
        monkeypatch.delenv('VAULT_JWT_TOKEN', raising=False)

        # act
        result = _detect_jwt_auth()

        # assert
        assert result is None

    def test_only_jwt__returns_none(self, monkeypatch):
        # arrange
        monkeypatch.delenv('VAULT_JWT_ROLE', raising=False)
        monkeypatch.setenv('VAULT_JWT_TOKEN', 'eyJ...')

        # act
        result = _detect_jwt_auth()

        # assert
        assert result is None


class TestDetectUserpassAuth:
    def test_both_credentials_present__returns_userpass_auth(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_USERNAME', 'admin')
        monkeypatch.setenv('VAULT_PASSWORD', 'secret')

        # act
        result = _detect_userpass_auth()

        # assert
        assert isinstance(result, UserpassAuth)
        assert result.username == 'admin'
        assert result.password == 'secret'
        assert result.mount_path == 'userpass'

    def test_custom_mount_path__uses_env_value(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_USERNAME', 'admin')
        monkeypatch.setenv('VAULT_PASSWORD', 'secret')
        monkeypatch.setenv('VAULT_USERPASS_MOUNT_PATH', 'ldap')

        # act
        result = _detect_userpass_auth()

        # assert
        assert result.mount_path == 'ldap'

    def test_only_username__returns_none(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_USERNAME', 'admin')
        monkeypatch.delenv('VAULT_PASSWORD', raising=False)

        # act
        result = _detect_userpass_auth()

        # assert
        assert result is None

    def test_only_password__returns_none(self, monkeypatch):
        # arrange
        monkeypatch.delenv('VAULT_USERNAME', raising=False)
        monkeypatch.setenv('VAULT_PASSWORD', 'secret')

        # act
        result = _detect_userpass_auth()

        # assert
        assert result is None


class TestVaultAuthFromEnv:
    def test_no_credentials__returns_empty_list(self, monkeypatch):
        # arrange
        monkeypatch.delenv('VAULT_TOKEN', raising=False)
        monkeypatch.delenv('VAULT_ROLE_ID', raising=False)
        monkeypatch.delenv('VAULT_SECRET_ID', raising=False)
        monkeypatch.delenv('VAULT_KUBERNETES_ROLE', raising=False)
        monkeypatch.delenv('VAULT_JWT_ROLE', raising=False)
        monkeypatch.delenv('VAULT_JWT_TOKEN', raising=False)
        monkeypatch.delenv('VAULT_USERNAME', raising=False)
        monkeypatch.delenv('VAULT_PASSWORD', raising=False)

        # act
        result = vault_auth_from_env()

        # assert
        assert result == []

    def test_multiple_credentials__returns_sorted_by_priority(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_USERNAME', 'admin')
        monkeypatch.setenv('VAULT_PASSWORD', 'secret')
        monkeypatch.setenv('VAULT_TOKEN', 'hvs.xxx')
        monkeypatch.delenv('VAULT_ROLE_ID', raising=False)
        monkeypatch.delenv('VAULT_SECRET_ID', raising=False)
        monkeypatch.delenv('VAULT_KUBERNETES_ROLE', raising=False)
        monkeypatch.delenv('VAULT_JWT_ROLE', raising=False)
        monkeypatch.delenv('VAULT_JWT_TOKEN', raising=False)

        # act
        result = vault_auth_from_env()

        # assert
        assert len(result) == 2
        assert isinstance(result[0], TokenAuth)
        assert isinstance(result[1], UserpassAuth)

    def test_method_token__only_checks_token(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_TOKEN', 'hvs.xxx')
        monkeypatch.setenv('VAULT_USERNAME', 'admin')
        monkeypatch.setenv('VAULT_PASSWORD', 'secret')

        # act
        result = vault_auth_from_env(method='token')

        # assert
        assert len(result) == 1
        assert isinstance(result[0], TokenAuth)

    def test_method_approle__only_checks_approle(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_TOKEN', 'hvs.xxx')
        monkeypatch.setenv('VAULT_ROLE_ID', 'role123')
        monkeypatch.setenv('VAULT_SECRET_ID', 'secret456')

        # act
        result = vault_auth_from_env(method='approle')

        # assert
        assert len(result) == 1
        assert isinstance(result[0], AppRoleAuth)

    def test_method_not_found__returns_empty_list(self, monkeypatch):
        # arrange
        monkeypatch.delenv('VAULT_TOKEN', raising=False)

        # act
        result = vault_auth_from_env(method='token')

        # assert
        assert result == []

    def test_all_methods_available__returns_in_priority_order(self, monkeypatch):
        # arrange
        monkeypatch.setenv('VAULT_TOKEN', 'hvs.xxx')
        monkeypatch.setenv('VAULT_ROLE_ID', 'role123')
        monkeypatch.setenv('VAULT_SECRET_ID', 'secret456')
        monkeypatch.setenv('VAULT_KUBERNETES_ROLE', 'myapp')
        monkeypatch.setenv('VAULT_JWT_ROLE', 'myproject')
        monkeypatch.setenv('VAULT_JWT_TOKEN', 'eyJ...')
        monkeypatch.setenv('VAULT_USERNAME', 'admin')
        monkeypatch.setenv('VAULT_PASSWORD', 'secret')

        # act
        result = vault_auth_from_env()

        # assert (order: approle, kubernetes, token, jwt, userpass)
        assert len(result) == 5
        assert isinstance(result[0], AppRoleAuth)
        assert isinstance(result[1], KubernetesAuth)
        assert isinstance(result[2], TokenAuth)
        assert isinstance(result[3], JwtAuth)
        assert isinstance(result[4], UserpassAuth)


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
