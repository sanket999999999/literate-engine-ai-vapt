"""Anthropic Claude - the default triage backend."""

from __future__ import annotations

import os

from .base import (
    REPORT_SYSTEM,
    TRIAGE_SYSTEM,
    TriagedFinding,
    TriageBatch,
    TriageError,
    TriageProvider,
    triage_user_prompt,
)

# USD per million tokens, by model. Cache writes cost 1.25x input, reads 0.1x.
_PRICING = {
    "claude-opus-5": (5.00, 25.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-haiku-4-5": (1.00, 5.00),
}


class AnthropicProvider(TriageProvider):
    key = "anthropic"
    label = "Anthropic Claude"
    description = "Strongest triage quality. Opus 5 for depth, Haiku 4.5 for bulk scans."
    default_model = "claude-opus-5"
    models = ("claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5")
    requires_key = "ANTHROPIC_API_KEY"

    def __init__(self, model: str | None = None) -> None:
        super().__init__(model)
        price_in, price_out = _PRICING.get(self.model, _PRICING[self.default_model])
        self.usage.price_in = price_in
        self.usage.price_out = price_out
        self.usage.price_cache_write = price_in * 1.25
        self.usage.price_cache_read = price_in * 0.1
        self._client = None

    @classmethod
    def available(cls) -> tuple[bool, str]:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False, "pip install anthropic"
        if not os.getenv("ANTHROPIC_API_KEY"):
            return False, "ANTHROPIC_API_KEY is not set"
        return True, ""

    @property
    def client(self):
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic()
        return self._client

    def triage_batch(self, payload: list[dict], indices: set[int]) -> list[TriagedFinding]:
        response = self.client.messages.parse(
            model=self.model,
            max_tokens=16000,
            system=[
                {
                    "type": "text",
                    "text": TRIAGE_SYSTEM,
                    # The system prompt is identical on every batch and every
                    # scan, so this is a cache hit after the first request.
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            thinking={"type": "adaptive"},
            messages=[{"role": "user", "content": triage_user_prompt(payload)}],
            output_format=TriageBatch,
        )
        self._record(response.usage)

        parsed = response.parsed_output
        if parsed is None:
            raise TriageError("model returned no structured output")
        return [f for f in parsed.findings if f.index in indices]

    def narrative(self, prompt: str) -> str:
        # Streamed so a long narrative cannot hit the request timeout.
        with self.client.messages.stream(
            model=self.model,
            max_tokens=8000,
            system=[
                {
                    "type": "text",
                    "text": REPORT_SYSTEM,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            thinking={"type": "adaptive"},
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            message = stream.get_final_message()

        self._record(message.usage)
        return "".join(b.text for b in message.content if b.type == "text").strip()

    def _record(self, usage) -> None:
        self.usage.add(
            input_tokens=getattr(usage, "input_tokens", 0),
            output_tokens=getattr(usage, "output_tokens", 0),
            cache_read=getattr(usage, "cache_read_input_tokens", 0),
            cache_write=getattr(usage, "cache_creation_input_tokens", 0),
        )
