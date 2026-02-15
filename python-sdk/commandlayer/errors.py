from __future__ import annotations

from typing import Any


class CommandLayerError(Exception):
    """Top-level SDK error with optional HTTP metadata."""

    def __init__(self, message: str, status_code: int | None = None, details: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details
