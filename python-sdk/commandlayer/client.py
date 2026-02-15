from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any

import httpx

from .errors import CommandLayerError
from .types import Receipt, VerifyOptions
from .verify import verify_receipt

VERSION = "1.0.0"

VERBS = {
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
}


def _normalize_base(url: str) -> str:
    return str(url or "").rstrip("/")


class CommandLayerClient:
    """Synchronous CommandLayer client for Commons verbs."""

    def __init__(
        self,
        runtime: str = "https://runtime.commandlayer.org",
        actor: str = "sdk-user",
        timeout_ms: int = 30_000,
        headers: Mapping[str, str] | None = None,
        retries: int = 0,
        verify_receipts: bool = False,
        verify: VerifyOptions | None = None,
        http_client: httpx.Client | None = None,
    ):
        self.runtime = _normalize_base(runtime)
        self.actor = actor
        self.timeout_ms = timeout_ms
        self.retries = max(0, retries)
        self.verify_receipts = verify_receipts is True
        self.verify_defaults: VerifyOptions = verify or {}

        self.default_headers = {
            "Content-Type": "application/json",
            "User-Agent": f"commandlayer-py/{VERSION}",
        }
        if headers:
            self.default_headers.update(dict(headers))

        self._http = http_client or httpx.Client(timeout=self.timeout_ms / 1000)

    def _ensure_verify_config_if_enabled(self) -> None:
        if not self.verify_receipts:
            return

        explicit_public_key = self.verify_defaults.get("public_key") or self.verify_defaults.get(
            "publicKey"
        )
        has_explicit = bool(str(explicit_public_key or "").strip())

        ens = self.verify_defaults.get("ens") or {}
        has_ens = bool(ens.get("name") and (ens.get("rpcUrl") or ens.get("rpc_url")))

        if not has_explicit and not has_ens:
            raise CommandLayerError(
                "verify_receipts is enabled but no verification key config provided. "
                "Set verify.public_key (or verify.publicKey) or verify.ens {name, rpcUrl}.",
                400,
            )

    def summarize(
        self,
        *,
        content: str,
        style: str | None = None,
        format: str | None = None,
        max_tokens: int = 1000,
    ) -> Receipt:
        return self.call(
            "summarize",
            {
                "input": {
                    "content": content,
                    "summary_style": style,
                    "format_hint": format,
                },
                "limits": {"max_output_tokens": max_tokens},
            },
        )

    def analyze(
        self,
        *,
        content: str,
        goal: str | None = None,
        hints: list[str] | None = None,
        max_tokens: int = 1000,
    ) -> Receipt:
        payload: dict[str, Any] = {
            "input": content,
            "limits": {"max_output_tokens": max_tokens},
        }
        if goal:
            payload["goal"] = goal
        if hints:
            payload["hints"] = hints
        return self.call("analyze", payload)

    def classify(self, *, content: str, max_labels: int = 5, max_tokens: int = 1000) -> Receipt:
        return self.call(
            "classify",
            {
                "actor": self.actor,
                "input": {"content": content},
                "limits": {"max_labels": max_labels, "max_output_tokens": max_tokens},
            },
        )

    def clean(
        self,
        *,
        content: str,
        operations: list[str] | None = None,
        max_tokens: int = 1000,
    ) -> Receipt:
        return self.call(
            "clean",
            {
                "input": {
                    "content": content,
                    "operations": operations
                    or ["normalize_newlines", "collapse_whitespace", "trim"],
                },
                "limits": {"max_output_tokens": max_tokens},
            },
        )

    def convert(
        self,
        *,
        content: str,
        from_format: str,
        to_format: str,
        max_tokens: int = 1000,
    ) -> Receipt:
        return self.call(
            "convert",
            {
                "input": {
                    "content": content,
                    "source_format": from_format,
                    "target_format": to_format,
                },
                "limits": {"max_output_tokens": max_tokens},
            },
        )

    def describe(
        self,
        *,
        subject: str,
        audience: str = "general",
        detail: str = "medium",
        max_tokens: int = 1000,
    ) -> Receipt:
        return self.call(
            "describe",
            {
                "input": {
                    "subject": (subject or "")[:140],
                    "audience": audience,
                    "detail_level": detail,
                },
                "limits": {"max_output_tokens": max_tokens},
            },
        )

    def explain(
        self,
        *,
        subject: str,
        audience: str = "general",
        style: str = "step-by-step",
        detail: str = "medium",
        max_tokens: int = 1000,
    ) -> Receipt:
        return self.call(
            "explain",
            {
                "input": {
                    "subject": (subject or "")[:140],
                    "audience": audience,
                    "style": style,
                    "detail_level": detail,
                },
                "limits": {"max_output_tokens": max_tokens},
            },
        )

    def format(self, *, content: str, to: str, max_tokens: int = 1000) -> Receipt:
        return self.call(
            "format",
            {
                "input": {"content": content, "target_style": to},
                "limits": {"max_output_tokens": max_tokens},
            },
        )

    def parse(
        self,
        *,
        content: str,
        content_type: str = "text",
        mode: str = "best_effort",
        target_schema: str | None = None,
        max_tokens: int = 1000,
    ) -> Receipt:
        payload: dict[str, Any] = {
            "input": {
                "content": content,
                "content_type": content_type,
                "mode": mode,
            },
            "limits": {"max_output_tokens": max_tokens},
        }
        if target_schema:
            payload["input"]["target_schema"] = target_schema
        return self.call("parse", payload)

    def fetch(
        self,
        *,
        source: str,
        query: str | None = None,
        include_metadata: bool | None = None,
        max_tokens: int = 1000,
    ) -> Receipt:
        input_obj: dict[str, Any] = {"source": source}
        if query is not None:
            input_obj["query"] = query
        if include_metadata is not None:
            input_obj["include_metadata"] = include_metadata

        return self.call(
            "fetch",
            {"input": input_obj, "limits": {"max_output_tokens": max_tokens}},
        )

    def _build_payload(self, verb: str, body: dict[str, Any]) -> dict[str, Any]:
        return {
            "x402": {
                "verb": verb,
                "version": VERSION,
                "entry": f"x402://{verb}agent.eth/{verb}/v{VERSION}",
            },
            "actor": body.get("actor", self.actor),
            **body,
        }

    def _request(self, verb: str, payload: dict[str, Any]) -> httpx.Response:
        url = f"{self.runtime}/{verb}/v{VERSION}"

        attempt = 0
        while True:
            try:
                return self._http.post(url, headers=self.default_headers, json=payload)
            except httpx.TimeoutException as err:
                if attempt >= self.retries:
                    raise CommandLayerError("Request timed out", 408) from err
            except httpx.HTTPError as err:
                if attempt >= self.retries:
                    raise CommandLayerError(f"HTTP transport error: {err}") from err

            attempt += 1
            time.sleep(min(0.2 * attempt, 1.0))

    def call(self, verb: str, body: dict[str, Any]) -> Receipt:
        if verb not in VERBS:
            raise CommandLayerError(f"Unsupported verb: {verb}", 400)

        self._ensure_verify_config_if_enabled()
        payload = self._build_payload(verb, body)
        response = self._request(verb, payload)

        try:
            data: Any = response.json()
        except json.JSONDecodeError:
            data = {}

        if not response.is_success:
            message = (
                (data.get("message") if isinstance(data, dict) else None)
                or (
                    (data.get("error") or {}).get("message")
                    if isinstance(data, dict) and isinstance(data.get("error"), dict)
                    else None
                )
                or f"HTTP {response.status_code}"
            )
            raise CommandLayerError(str(message), response.status_code, data)

        if not isinstance(data, dict):
            raise CommandLayerError(
                "Runtime response must be a JSON object", response.status_code, data
            )

        if self.verify_receipts:
            verify_result = verify_receipt(
                data,
                public_key=self.verify_defaults.get("public_key")
                or self.verify_defaults.get("publicKey"),
                ens=self.verify_defaults.get("ens"),
            )
            if not verify_result["ok"]:
                raise CommandLayerError("Receipt verification failed", 422, verify_result)

        return data

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> CommandLayerClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def create_client(**kwargs: Any) -> CommandLayerClient:
    return CommandLayerClient(**kwargs)
