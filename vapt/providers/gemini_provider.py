"""Google Gemini via the google-genai SDK."""

from __future__ import annotations

import os

from .base import (
    REPORT_SYSTEM,
    TRIAGE_SYSTEM,
    TriagedFinding,
    TriageProvider,
    parse_batch,
    triage_user_prompt,
)
from .schema import BATCH_SCHEMA

# USD per million tokens (input, output).
_PRICING = {
    "gemini-2.5-pro": (1.25, 10.00),
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.5-flash-lite": (0.10, 0.40),
}

_KEY_VARS = ("GEMINI_API_KEY", "GOOGLE_API_KEY")


class GeminiProvider(TriageProvider):
    key = "gemini"
    label = "Google Gemini"
    description = "Flash tiers are the cheapest cloud option for triaging large scans."
    default_model = "gemini-2.5-flash"
    models = tuple(_PRICING)
    requires_key = "GEMINI_API_KEY"

    def __init__(self, model: str | None = None) -> None:
        super().__init__(model)
        price_in, price_out = _PRICING.get(self.model, _PRICING[self.default_model])
        self.usage.price_in = price_in
        self.usage.price_out = price_out
        self.usage.price_cache_read = price_in * 0.25
        self._client = None

    @classmethod
    def available(cls) -> tuple[bool, str]:
        try:
            from google import genai  # noqa: F401
        except ImportError:
            return False, "pip install google-genai"
        if not any(os.getenv(v) for v in _KEY_VARS):
            return False, "GEMINI_API_KEY is not set"
        return True, ""

    @property
    def client(self):
        if self._client is None:
            from google import genai

            api_key = next((os.getenv(v) for v in _KEY_VARS if os.getenv(v)), None)
            self._client = genai.Client(api_key=api_key)
        return self._client

    def triage_batch(self, payload: list[dict], indices: set[int]) -> list[TriagedFinding]:
        response = self.client.models.generate_content(
            model=self.model,
            contents=triage_user_prompt(payload),
            config={
                "system_instruction": TRIAGE_SYSTEM,
                "response_mime_type": "application/json",
                "response_schema": BATCH_SCHEMA,
                "temperature": 0.0,
            },
        )
        self._record(response)
        return parse_batch(response.text or "", indices)

    def narrative(self, prompt: str) -> str:
        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
            config={"system_instruction": REPORT_SYSTEM},
        )
        self._record(response)
        return (response.text or "").strip()

    def _record(self, response) -> None:
        meta = getattr(response, "usage_metadata", None)
        if meta is None:
            self.usage.add()
            return
        cached = getattr(meta, "cached_content_token_count", 0) or 0
        self.usage.add(
            input_tokens=max(0, (getattr(meta, "prompt_token_count", 0) or 0) - cached),
            output_tokens=getattr(meta, "candidates_token_count", 0) or 0,
            cache_read=cached,
        )
