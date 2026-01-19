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


class NoValidAuthError(AuthenticationError):
    """All authentication methods failed."""

    def __init__(self, errors: list[Exception]):
        self.errors = errors
        methods = ', '.join(type(e).__name__ for e in errors)
        super().__init__(f'All authentication methods failed: {methods}')
