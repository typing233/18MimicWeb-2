"""Storage package for request logging."""

from .base import StorageBackend, LogEntry
from .local import LocalStorage

__all__ = ["StorageBackend", "LogEntry", "LocalStorage"]
