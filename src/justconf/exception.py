from typing import Any


class LoaderError(Exception):
    """Base exception for all loader errors."""


class TomlLoadError(LoaderError):
    """Error loading/parsing TOML file."""


class ProcessorError(Exception):
    """Base exception for all processor errors."""


class PlaceholderError(ProcessorError):
    """Error resolving placeholder."""


class SecretNotFoundError(ProcessorError):
    """Secret not found in the source."""


class AuthenticationError(ProcessorError):
    """Authentication failed."""


class AccessDeniedError(ProcessorError):
    """Access to the secret is denied by Vault policy."""


class NoValidAuthError(AuthenticationError):
    """All authentication methods failed."""

    def __init__(self, errors: dict[Any, Exception]):
        self.errors = errors
        methods = ', '.join(type(auth_method).__name__ for auth_method in errors.keys())
        super().__init__(f'All authentication methods failed: {methods}')
