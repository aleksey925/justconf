import json
import logging
import os
import ssl
import time
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http import HTTPStatus
from typing import Any, Literal, cast
from urllib.error import HTTPError, URLError

from justconf.exception import (
    AccessDeniedError,
    AuthenticationError,
    NoValidAuthError,
    SecretNotFoundError,
)
from justconf.processor.base import Processor

DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.5
RETRYABLE_HTTP_STATUS_CODES: frozenset[int] = frozenset({500, 502, 503, 504})
TOKEN_REFRESH_BUFFER_SECONDS = 30
KUBERNETES_SA_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'  # noqa: S105

AuthMethod = Literal['token', 'approle', 'kubernetes', 'jwt', 'userpass']

DEFAULT_AUTH_ORDER: tuple[AuthMethod, ...] = (
    'approle',
    'kubernetes',
    'token',
    'jwt',
    'userpass',
)

logger = logging.getLogger(__name__)


def _create_ssl_context(verify: bool | str) -> ssl.SSLContext | None:
    """Create SSL context based on verify parameter.

    Args:
        verify: True for default CA verification, False to disable,
                or path to CA bundle file.

    Returns:
        SSLContext or None (for default behavior when verify=True).

    Raises:
        FileNotFoundError: If verify is a path and the file does not exist.
    """
    if verify is True:
        return None
    if verify is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    # verify is a path to CA bundle
    try:
        return ssl.create_default_context(cafile=verify)
    except FileNotFoundError:
        raise FileNotFoundError(f'CA bundle file not found: {verify}') from None


def _extract_vault_errors(e: HTTPError) -> list[str]:
    try:
        body = e.read().decode(errors='replace')
    except Exception as exc:
        return [f'failed to read response body: {exc}']

    if not body:
        return [f'empty response body (HTTP {e.code})']

    try:
        data = json.loads(body)
        errors = cast(list[str], data.get('errors', []))
        if not errors:
            errors = ['Unable to find error list in response body']
            logger.warning('Error message not found in response: %s', body)
        return errors
    except (json.JSONDecodeError, AttributeError):
        logger.error('Failed to decode response from vault with error message: %s', body, exc_info=True)
        return ['Failed to parse response body']


def _urlopen_with_retry(
    request: urllib.request.Request,
    timeout: int = DEFAULT_TIMEOUT,
    ssl_context: ssl.SSLContext | None = None,
    retries: int = DEFAULT_RETRIES,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
) -> Any:
    max_attempts = 1 + retries
    for attempt in range(max_attempts):
        try:
            return urllib.request.urlopen(request, timeout=timeout, context=ssl_context)
        except URLError as e:
            if isinstance(e, HTTPError) and e.code not in RETRYABLE_HTTP_STATUS_CODES:
                raise
            if attempt == max_attempts - 1:
                raise
            delay = backoff_factor * 2**attempt
            detail = f'HTTP {e.code}' if isinstance(e, HTTPError) else str(e)
            logger.warning(
                'Vault request to %s failed with %s, retrying in %.1fs (attempt %d/%d)',
                request.full_url,
                detail,
                delay,
                attempt + 1,
                max_attempts,
            )
            time.sleep(delay)


class VaultAuth(ABC):
    """Base class for Vault authentication methods."""

    @abstractmethod
    def authenticate(
        self,
        vault_url: str,
        timeout: int = DEFAULT_TIMEOUT,
        ssl_context: ssl.SSLContext | None = None,
        retries: int = DEFAULT_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    ) -> tuple[str, int]:
        """Authenticate with Vault and return token with TTL.

        Args:
            vault_url: Base URL of the Vault server.
            timeout: Request timeout in seconds.
            ssl_context: SSL context for HTTPS connections.
            retries: Number of retries for transient HTTP errors.
            backoff_factor: Multiplier for exponential backoff between retries.

        Returns:
            Tuple of (token, ttl_seconds).

        Raises:
            AuthenticationError: If authentication fails.
        """
        ...


class TokenAuth(VaultAuth):
    """Direct token authentication."""

    def __init__(self, token: str):
        self.token = token

    def __repr__(self) -> str:
        return f'{type(self).__name__}(token="***")'

    def authenticate(
        self,
        vault_url: str,
        timeout: int = DEFAULT_TIMEOUT,
        ssl_context: ssl.SSLContext | None = None,
        retries: int = DEFAULT_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    ) -> tuple[str, int]:
        if not self.token:
            raise AuthenticationError('Token is empty')

        # lookup token to get TTL
        try:
            req = urllib.request.Request(
                f'{vault_url}/v1/auth/token/lookup-self',
                headers={'X-Vault-Token': self.token},
            )
            with _urlopen_with_retry(
                req, timeout=timeout, ssl_context=ssl_context, retries=retries, backoff_factor=backoff_factor
            ) as resp:
                data = json.loads(resp.read())
                ttl = data.get('data', {}).get('ttl', 3600)
                return self.token, ttl
        except HTTPError as e:
            raise AuthenticationError(
                'Token authentication failed',
                detail=_extract_vault_errors(e),
            ) from e


class AppRoleAuth(VaultAuth):
    """AppRole authentication."""

    def __init__(
        self,
        role_id: str,
        secret_id: str,
        mount_path: str = 'approle',
    ):
        self.role_id = role_id
        self.secret_id = secret_id
        self.mount_path = mount_path

    def __repr__(self) -> str:
        return f'{type(self).__name__}(role_id="***", mount_path={self.mount_path!r})'

    def authenticate(
        self,
        vault_url: str,
        timeout: int = DEFAULT_TIMEOUT,
        ssl_context: ssl.SSLContext | None = None,
        retries: int = DEFAULT_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    ) -> tuple[str, int]:
        if not self.role_id or not self.secret_id:
            raise AuthenticationError('role_id and secret_id are required')

        payload = json.dumps(
            {
                'role_id': self.role_id,
                'secret_id': self.secret_id,
            }
        ).encode()

        try:
            req = urllib.request.Request(
                f'{vault_url}/v1/auth/{self.mount_path}/login',
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            with _urlopen_with_retry(
                req, timeout=timeout, ssl_context=ssl_context, retries=retries, backoff_factor=backoff_factor
            ) as resp:
                data = json.loads(resp.read())
                auth = data.get('auth', {})
                return auth['client_token'], auth.get('lease_duration', 3600)
        except HTTPError as e:
            raise AuthenticationError(
                'AppRole authentication failed',
                detail=_extract_vault_errors(e),
            ) from e
        except KeyError as e:
            raise AuthenticationError(f'Invalid response from Vault: {e}') from e


class JwtAuth(VaultAuth):
    """JWT authentication (GitLab CI/CD, etc.)."""

    def __init__(
        self,
        role: str,
        jwt: str,
        mount_path: str = 'jwt',
    ):
        self.role = role
        self.jwt = jwt
        self.mount_path = mount_path

    def __repr__(self) -> str:
        return f'{type(self).__name__}(role={self.role!r}, mount_path={self.mount_path!r})'

    def authenticate(
        self,
        vault_url: str,
        timeout: int = DEFAULT_TIMEOUT,
        ssl_context: ssl.SSLContext | None = None,
        retries: int = DEFAULT_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    ) -> tuple[str, int]:
        if not self.jwt:
            raise AuthenticationError('JWT token is empty')

        payload = json.dumps(
            {
                'role': self.role,
                'jwt': self.jwt,
            }
        ).encode()

        try:
            req = urllib.request.Request(
                f'{vault_url}/v1/auth/{self.mount_path}/login',
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            with _urlopen_with_retry(
                req, timeout=timeout, ssl_context=ssl_context, retries=retries, backoff_factor=backoff_factor
            ) as resp:
                data = json.loads(resp.read())
                auth = data.get('auth', {})
                return auth['client_token'], auth.get('lease_duration', 3600)
        except HTTPError as e:
            raise AuthenticationError(
                'JWT authentication failed',
                detail=_extract_vault_errors(e),
            ) from e
        except KeyError as e:
            raise AuthenticationError(f'Invalid response from Vault: {e}') from e


class KubernetesAuth(VaultAuth):
    """Kubernetes Service Account authentication."""

    def __init__(
        self,
        role: str,
        jwt: str | None = None,
        jwt_path: str = KUBERNETES_SA_TOKEN_PATH,
        mount_path: str = 'kubernetes',
    ):
        self.role = role
        self._jwt = jwt
        self.jwt_path = jwt_path
        self.mount_path = mount_path

    def __repr__(self) -> str:
        return f'{type(self).__name__}(role={self.role!r}, mount_path={self.mount_path!r})'

    @property
    def jwt(self) -> str:
        if self._jwt:
            return self._jwt
        try:
            with open(self.jwt_path) as f:
                return f.read().strip()
        except FileNotFoundError as e:
            raise AuthenticationError(f'Kubernetes SA token not found at {self.jwt_path}') from e

    def authenticate(
        self,
        vault_url: str,
        timeout: int = DEFAULT_TIMEOUT,
        ssl_context: ssl.SSLContext | None = None,
        retries: int = DEFAULT_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    ) -> tuple[str, int]:
        payload = json.dumps(
            {
                'role': self.role,
                'jwt': self.jwt,
            }
        ).encode()

        try:
            req = urllib.request.Request(
                f'{vault_url}/v1/auth/{self.mount_path}/login',
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            with _urlopen_with_retry(
                req, timeout=timeout, ssl_context=ssl_context, retries=retries, backoff_factor=backoff_factor
            ) as resp:
                data = json.loads(resp.read())
                auth = data.get('auth', {})
                return auth['client_token'], auth.get('lease_duration', 3600)
        except HTTPError as e:
            raise AuthenticationError(
                'Kubernetes authentication failed',
                detail=_extract_vault_errors(e),
            ) from e
        except KeyError as e:
            raise AuthenticationError(f'Invalid response from Vault: {e}') from e


class UserpassAuth(VaultAuth):
    """Username/password authentication."""

    def __init__(
        self,
        username: str,
        password: str,
        mount_path: str = 'userpass',
    ):
        self.username = username
        self.password = password
        self.mount_path = mount_path

    def __repr__(self) -> str:
        return f'{type(self).__name__}(username={self.username!r}, mount_path={self.mount_path!r})'

    def authenticate(
        self,
        vault_url: str,
        timeout: int = DEFAULT_TIMEOUT,
        ssl_context: ssl.SSLContext | None = None,
        retries: int = DEFAULT_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    ) -> tuple[str, int]:
        if not self.username or not self.password:
            raise AuthenticationError('Username and password are required')

        payload = json.dumps({'password': self.password}).encode()

        try:
            req = urllib.request.Request(
                f'{vault_url}/v1/auth/{self.mount_path}/login/{self.username}',
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            with _urlopen_with_retry(
                req, timeout=timeout, ssl_context=ssl_context, retries=retries, backoff_factor=backoff_factor
            ) as resp:
                data = json.loads(resp.read())
                auth = data.get('auth', {})
                return auth['client_token'], auth.get('lease_duration', 3600)
        except HTTPError as e:
            raise AuthenticationError(
                'Userpass authentication failed',
                detail=_extract_vault_errors(e),
            ) from e
        except KeyError as e:
            raise AuthenticationError(f'Invalid response from Vault: {e}') from e


class VaultProcessor(Processor):
    """Processor for HashiCorp Vault secrets (KV v2).

    Uses full paths in placeholders: {mount}/data/{secret_path}.

    Example placeholders:
        ${vault:secret/data/myapp#password}  # KV v2 at 'secret' mount
        ${vault:kv/data/db#user}             # KV v2 at 'kv' mount
    """

    name = 'vault'

    def __init__(
        self,
        url: str,
        auth: VaultAuth | list[VaultAuth],
        timeout: int = DEFAULT_TIMEOUT,
        verify: bool | str = True,
        retries: int = DEFAULT_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    ):
        """Initialize VaultProcessor.

        Args:
            url: Base URL of the Vault server.
            auth: Authentication method or list of methods (fallback chain).
            timeout: Request timeout in seconds.
            verify: SSL certificate verification. True (default) uses system CA,
                    False disables verification, or path to CA bundle file.
            retries: Number of retries for transient HTTP errors (500, 502, 503, 504).
            backoff_factor: Multiplier for exponential backoff between retries.

        Raises:
            ValueError: If URL is invalid.
        """
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f'Invalid Vault URL scheme: {parsed.scheme!r}. Must be http or https.')
        if not parsed.netloc:
            raise ValueError(f'Invalid Vault URL: missing host in {url!r}')

        self.url = url.rstrip('/')
        self.auth_methods = auth if isinstance(auth, list) else [auth]
        self.timeout = timeout
        self.retries = retries
        self.backoff_factor = backoff_factor
        self._ssl_context = _create_ssl_context(verify)

        # token cache
        self._token: str | None = None
        self._token_expires_at: float = 0

        # secrets cache (active only during caching() context)
        self._secrets_cache: dict[str, Any] | None = None

    def _authenticate(self) -> tuple[str, int]:
        """Try all auth methods until one succeeds."""
        if not self.auth_methods:
            raise AuthenticationError('No authentication methods provided')

        errors: dict[VaultAuth, Exception] = {}

        for auth in self.auth_methods:
            try:
                return auth.authenticate(
                    self.url, self.timeout, self._ssl_context, retries=self.retries, backoff_factor=self.backoff_factor
                )
            except AuthenticationError as e:
                logger.warning('Authentication through "%s" failed with errors: [%s]', auth, '; '.join(e.detail))
                errors[auth] = e

        raise NoValidAuthError(errors)

    def _ensure_token(self) -> str:
        """Get valid token, re-authenticate if needed."""
        now = time.time()

        if self._token and self._token_expires_at > now + TOKEN_REFRESH_BUFFER_SECONDS:
            return self._token

        # need new token
        self._token, ttl = self._authenticate()
        self._token_expires_at = now + ttl
        return self._token

    def _do_request(self, path: str, token: str) -> dict[str, Any]:
        """Make request to Vault."""
        req = urllib.request.Request(
            f'{self.url}/v1/{path}',
            headers={'X-Vault-Token': token},
        )
        try:
            with _urlopen_with_retry(
                req,
                timeout=self.timeout,
                ssl_context=self._ssl_context,
                retries=self.retries,
                backoff_factor=self.backoff_factor,
            ) as resp:
                return cast(dict[str, Any], json.loads(resp.read()))
        except HTTPError as e:
            errors = _extract_vault_errors(e)
            detail = '; '.join(errors)
            if e.code == HTTPStatus.NOT_FOUND:
                raise SecretNotFoundError(f'Secret not found: {path}: {detail}') from e
            if e.code == HTTPStatus.UNAUTHORIZED:
                raise AuthenticationError(
                    'Token is invalid or expired',
                    detail=errors,
                ) from e
            if e.code == HTTPStatus.FORBIDDEN:
                raise AccessDeniedError(f'Access denied for {path}: {detail}') from e
            raise

    def _fetch_secret(self, path: str, key: str | None = None) -> Any:
        """Fetch secret from Vault with automatic retry on auth failure."""
        token = self._ensure_token()

        try:
            data = self._do_request(path, token)
        except AuthenticationError:
            # token revoked or expired earlier than TTL — retry
            self._token = None
            token = self._ensure_token()
            data = self._do_request(path, token)

        secret_data = data.get('data', {}).get('data', {})

        if key:
            if key not in secret_data:
                raise SecretNotFoundError(f"Key '{key}' not found in secret '{path}'")
            return secret_data[key]

        return secret_data

    def resolve(self, path: str, key: str | None = None) -> Any:
        """Resolve secret from Vault."""
        path = path.strip('/')
        cache_key = f'{path}#{key}'

        if self._secrets_cache is not None and cache_key in self._secrets_cache:
            return self._secrets_cache[cache_key]

        value = self._fetch_secret(path, key)

        if self._secrets_cache is not None:
            self._secrets_cache[cache_key] = value

        return value

    @contextmanager
    def caching(self) -> Iterator[None]:
        """Enable secrets caching for the duration of the context."""
        self._secrets_cache = {}
        try:
            yield
        finally:
            self._secrets_cache = None


def _detect_token_auth() -> TokenAuth | None:
    """Detect TokenAuth from VAULT_TOKEN environment variable."""
    token = os.environ.get('VAULT_TOKEN')
    return TokenAuth(token=token) if token else None


def _detect_approle_auth() -> AppRoleAuth | None:
    """Detect AppRoleAuth from VAULT_ROLE_ID and VAULT_SECRET_ID environment variables."""
    role_id = os.environ.get('VAULT_ROLE_ID')
    secret_id = os.environ.get('VAULT_SECRET_ID')
    if role_id and secret_id:
        return AppRoleAuth(
            role_id=role_id,
            secret_id=secret_id,
            mount_path=os.environ.get('VAULT_APPROLE_MOUNT_PATH', 'approle'),
        )
    return None


def _detect_kubernetes_auth() -> KubernetesAuth | None:
    """Detect KubernetesAuth from VAULT_KUBERNETES_ROLE environment variable."""
    role = os.environ.get('VAULT_KUBERNETES_ROLE')
    if role:
        return KubernetesAuth(
            role=role,
            mount_path=os.environ.get('VAULT_KUBERNETES_MOUNT_PATH', 'kubernetes'),
        )
    return None


def _detect_jwt_auth() -> JwtAuth | None:
    """Detect JwtAuth from VAULT_JWT_ROLE and VAULT_JWT_TOKEN environment variables."""
    role = os.environ.get('VAULT_JWT_ROLE')
    jwt = os.environ.get('VAULT_JWT_TOKEN')
    if role and jwt:
        return JwtAuth(
            role=role,
            jwt=jwt,
            mount_path=os.environ.get('VAULT_JWT_MOUNT_PATH', 'jwt'),
        )
    return None


def _detect_userpass_auth() -> UserpassAuth | None:
    """Detect UserpassAuth from VAULT_USERNAME and VAULT_PASSWORD environment variables."""
    username = os.environ.get('VAULT_USERNAME')
    password = os.environ.get('VAULT_PASSWORD')
    if username and password:
        return UserpassAuth(
            username=username,
            password=password,
            mount_path=os.environ.get('VAULT_USERPASS_MOUNT_PATH', 'userpass'),
        )
    return None


_DETECTORS: dict[AuthMethod, Callable[[], VaultAuth | None]] = {
    'token': _detect_token_auth,
    'approle': _detect_approle_auth,
    'kubernetes': _detect_kubernetes_auth,
    'jwt': _detect_jwt_auth,
    'userpass': _detect_userpass_auth,
}


def vault_auth_from_env(
    method: AuthMethod | None = None,
) -> list[VaultAuth]:
    """Detect Vault credentials from environment variables.

    Args:
        method: If specified, only check for this auth method.
                If None, check all methods and return sorted by priority.

    Returns:
        List of VaultAuth instances (possibly empty), sorted by priority.
    """
    if method is not None:
        detector = _DETECTORS[method]
        auth = detector()
        return [auth] if auth else []

    result = []
    for method_name in DEFAULT_AUTH_ORDER:
        auth = _DETECTORS[method_name]()
        if auth is not None:
            result.append(auth)
    return result
