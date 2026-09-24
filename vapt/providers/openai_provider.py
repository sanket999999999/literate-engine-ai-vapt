"""OpenAI GPT models via the Chat Completions API."""

from __future__ import annotations

import os

from .base import (
    REPORT_SYSTEM,
    TRIAGE_SYSTEM,
    TriagedFinding,
    TriageError,
    TriageProvider,
    parse_batch,
    triage_user_prompt,
)
from .schema import BATCH_SCHEMA

# USD per million tokens (input, output).
_PRICING = {
    "gpt-5": (1.25, 10.00),
    "gpt-5-mini": (0.25, 2.00),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "o4-mini": (1.10, 4.40),
}


class OpenAIProvider(TriageProvider):
    key = "openai"
    label = "OpenAI"
    description = "GPT models with strict JSON schema output. Mini tiers are cheap for bulk."
    default_model = "gpt-5"
    models = tuple(_PRICING)
    requires_key = "OPENAI_API_KEY"

    def __init__(self, model: str | None = None) -> None:
        super().__init__(model)
        price_in, price_out = _PRICING.get(self.model, _PRICING[self.default_model])
        self.usage.price_in = price_in
        self.usage.price_out = price_out
        # Cached input is billed at a discount; OpenAI reports it separately.
        self.usage.price_cache_read = price_in * 0.1
        self._client = None

    @classmethod
    def available(cls) -> tuple[bool, str]:
        try:
            import openai  # noqa: F401
        except ImportError:
            return False, "pip install openai"
        if not os.getenv("OPENAI_API_KEY"):
            return False, "OPENAI_API_KEY is not set"
        return True, ""

    @property
    def client(self):
        if self._client is None:
            import openai

            self._client = openai.OpenAI()
        return self._client

    def triage_batch(self, payload: list[dict], indices: set[int]) -> list[TriagedFinding]:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": TRIAGE_SYSTEM},
                {"role": "user", "content": triage_user_prompt(payload)},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "triage_batch",
                    "strict": True,
                    "schema": BATCH_SCHEMA,
                },
            },
        )
        self._record(response.usage)

        choice = response.choices[0]
        if getattr(choice.message, "refusal", None):
            raise TriageError("model refused: {}".format(choice.message.refusal))
        return parse_batch(choice.message.content or "", indices)

    def narrative(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": REPORT_SYSTEM},
                {"role": "user", "content": prompt},
            ],
        )
        self._record(response.usage)
        return (response.choices[0].message.content or "").strip()

    def _record(self, usage) -> None:
        if usage is None:
            return
        details = getattr(usage, "prompt_tokens_details", None)
        cached = getattr(details, "cached_tokens", 0) or 0
        self.usage.add(
            # prompt_tokens includes cached tokens; don't bill them twice.
            input_tokens=max(0, (getattr(usage, "prompt_tokens", 0) or 0) - cached),
            output_tokens=getattr(usage, "completion_tokens", 0) or 0,
            cache_read=cached,
        )
