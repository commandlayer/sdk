# python-sdk/src/commandlayer/__init__.py

"""
CommandLayer Python SDK.

Semantic verbs. Typed schemas. Signed receipts.
"""

from .client import CommandLayerClient, create_client
from .errors import CommandLayerError
from .types import Receipt, VerifyResult

__all__ = [
    "CommandLayerClient",
    "create_client",
    "CommandLayerError",
    "Receipt",
    "VerifyResult",
]

__version__ = "1.0.0"
