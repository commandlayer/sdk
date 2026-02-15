import pytest

from commandlayer.client import CommandLayerClient
from commandlayer.errors import CommandLayerError


def test_call_rejects_unsupported_verb():
    client = CommandLayerClient()
    with pytest.raises(CommandLayerError):
        client.call("unknown", {})


def test_verify_config_required_when_enabled():
    client = CommandLayerClient(verify_receipts=True)
    with pytest.raises(CommandLayerError):
        client._ensure_verify_config_if_enabled()
