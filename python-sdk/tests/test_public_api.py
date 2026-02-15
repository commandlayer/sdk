from __future__ import annotations

from commandlayer import CommandLayerClient, create_client


def test_create_client_factory() -> None:
    client = create_client(actor="api-user")
    assert isinstance(client, CommandLayerClient)
    assert client.actor == "api-user"
    client.close()
