class LoaderError(Exception):
    """Base exception for all loader errors."""


class TomlLoadError(LoaderError):
    """Error loading/parsing TOML file."""
