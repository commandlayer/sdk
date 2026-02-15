from __future__ import annotations

import json

import httpx
import pytest

from commandlayer.client import CommandLayerClient
from commandlayer.errors import CommandLayerError


def test_call_rejects_unsupported_verb() -> None:
    client = CommandLayerClient(
        http_client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200)))
    )
    with pytest.raises(CommandLayerError, match="Unsupported verb"):
        client.call("unknown", {})


def test_verify_config_required_when_enabled() -> None:
    client = CommandLayerClient(verify_receipts=True)
    with pytest.raises(CommandLayerError, match="verification key config"):
        client._ensure_verify_config_if_enabled()


def test_client_posts_expected_payload() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["json"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "status": "success",
                "x402": {"verb": "summarize"},
                "metadata": {"proof": {"alg": "ed25519-sha256", "canonical": "cl-stable-json-v1"}},
            },
        )

    http = httpx.Client(transport=httpx.MockTransport(handler))
    client = CommandLayerClient(
        runtime="https://runtime.commandlayer.org", actor="tester", http_client=http
    )

    client.summarize(content="hello", style="bullet_points")

    assert captured["url"] == "https://runtime.commandlayer.org/summarize/v1.0.0"
    sent = captured["json"]
    assert isinstance(sent, dict)
    assert sent["actor"] == "tester"
    assert sent["x402"]["verb"] == "summarize"


def test_client_surfaces_error_message() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"error": {"message": "bad input"}})

    client = CommandLayerClient(http_client=httpx.Client(transport=httpx.MockTransport(handler)))

    with pytest.raises(CommandLayerError, match="bad input") as exc:
        client.summarize(content="x")

    assert exc.value.status_code == 422


def test_client_verify_receipts_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "success", "metadata": {"proof": {}}})

    monkeypatch.setattr(
        "commandlayer.client.verify_receipt",
        lambda *_args, **_kwargs: {
            "ok": False,
            "checks": {},
            "values": {},
            "errors": {"signature_error": "boom", "ens_error": None, "verify_error": None},
        },
    )

    client = CommandLayerClient(
        verify_receipts=True,
        verify={"public_key": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(CommandLayerError, match="Receipt verification failed"):
        client.summarize(content="x")
