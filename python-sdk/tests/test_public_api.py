from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import httpx

from commandlayer import (
    CommandLayerClient,
    canonicalize_stable_json_v1,
    create_client,
    normalize_command_response,
    recompute_receipt_hash_sha256,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test_vectors"
EXPECTED_EXPORTS = {
    "CommandLayerClient": CommandLayerClient,
    "create_client": create_client,
    "verify_receipt": verify_receipt,
    "normalize_command_response": normalize_command_response,
    "canonicalize_stable_json_v1": canonicalize_stable_json_v1,
    "recompute_receipt_hash_sha256": recompute_receipt_hash_sha256,
}
EXPECTED_VERBS = [
    "summarize",
    "analyze",
    "classify",
    "clean",
    "convert",
    "describe",
    "explain",
    "format",
    "parse",
    "fetch",
]


def load_fixture(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((VECTORS / name).read_text(encoding="utf-8")))


def load_pubkey() -> str:
    return f"ed25519:{(VECTORS / 'public_key_base64.txt').read_text(encoding='utf-8').strip()}"


def test_expected_symbols_are_importable() -> None:
    for export_name, export_value in EXPECTED_EXPORTS.items():
        assert export_value is not None, export_name



def test_create_client_accepts_basic_configuration() -> None:
    client = create_client(
        actor="api-user",
        runtime="https://runtime.example",
        timeout_ms=12_345,
        headers={"X-Test": "1"},
        verify_receipts=False,
    )

    assert isinstance(client, CommandLayerClient)
    assert client.actor == "api-user"
    assert client.runtime == "https://runtime.example"
    assert client.timeout_ms == 12_345
    assert client.default_headers["X-Test"] == "1"
    client.close()



def test_public_client_verbs_exist_and_are_callable() -> None:
    client = create_client(actor="verb-check")
    try:
        for verb in EXPECTED_VERBS:
            method = getattr(client, verb)
            assert callable(method), verb
    finally:
        client.close()



def test_mocked_client_response_matches_public_envelope_shape() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "receipt": {
                    "status": "success",
                    "result": {"summary": "done"},
                    "metadata": {
                        "proof": {
                            "alg": "ed25519-sha256",
                            "canonical": "cl-stable-json-v1",
                        }
                    },
                },
                "runtime_metadata": {"duration_ms": 7, "provider": "mock-runtime"},
            },
        )

    client = create_client(
        actor="shape-check",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    try:
        response = client.summarize(content="Hello", style="bullet_points")
    finally:
        client.close()

    assert set(response.keys()) == {"receipt", "runtime_metadata"}
    assert response["receipt"]["result"]["summary"] == "done"
    assert response["runtime_metadata"]["duration_ms"] == 7



def test_verify_receipt_is_importable_callable_and_matches_vector_contract() -> None:
    receipt = load_fixture("receipt_valid.json")

    result = verify_receipt(receipt, public_key=load_pubkey())

    assert callable(verify_receipt)
    assert result["ok"] is True
    assert result["values"]["recomputed_hash"] == recompute_receipt_hash_sha256(
        receipt
    )["hash_sha256"]
    assert result["values"]["signer_id"] == "runtime.commandlayer.eth"
    assert result["errors"]["verify_error"] is None



def test_mocked_end_to_end_flow_uses_vector_shaped_response() -> None:
    receipt = load_fixture("receipt_valid.json")

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "receipt": receipt,
                "runtime_metadata": {"duration_ms": 11, "provider": "mock-runtime"},
            },
        )

    client = create_client(
        actor="vector-flow",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    try:
        response = client.analyze(content="vector-backed", goal="parity")
    finally:
        client.close()

    assert response["receipt"] == receipt
    assert response["runtime_metadata"]["provider"] == "mock-runtime"
    verification = verify_receipt(response["receipt"], public_key=load_pubkey())
    assert verification["ok"] is True
