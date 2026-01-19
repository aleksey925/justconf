from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


class Processor(ABC):
    """Base class for config value processors."""

    name: str

    @abstractmethod
    def resolve(self, path: str, key: str | None = None) -> Any:
        """Resolve placeholder to actual value.

        Args:
            path: Path to the secret/value.
            key: Optional key within the secret.

        Returns:
            Resolved value.
        """
        ...

    @contextmanager
    def caching(self) -> Iterator[None]:
        """Context manager to enable caching during processing.

        Default implementation does nothing. Override in subclasses
        that support caching.
        """
        yield
