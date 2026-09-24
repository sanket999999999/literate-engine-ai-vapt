"""Triage provider registry.

`none` is a first-class choice, not the absence of one: it runs the scanners,
deduplicates and reports, with raw scanner severities and no narrative.
"""

from __future__ import annotations

from typing import Type

from .anthropic_provider import AnthropicProvider
from .base import (
    ProviderUnavailable,
    TriageBatch,
    TriagedFinding,
    TriageError,
    TriageProvider,
    Usage,
)
from .gemini_provider import GeminiProvider
from .ollama_provider import OllamaProvider
from .openai_provider import OpenAIProvider

NONE = "none"

PROVIDER_CLASSES: tuple[Type[TriageProvider], ...] = (
    AnthropicProvider,
    OpenAIProvider,
    GeminiProvider,
    OllamaProvider,
)

_BY_KEY = {cls.key: cls for cls in PROVIDER_CLASSES}


def get_provider(key: str, model: str | None = None) -> TriageProvider | None:
    """Build a provider, or None for `none`/empty. Raises if it is unusable."""
    key = (key or NONE).strip().lower()
    if key in (NONE, ""):
        return None

    cls = _BY_KEY.get(key)
    if cls is None:
        raise ProviderUnavailable(
            "Unknown provider '{}'. Available: {}".format(key, ", ".join(_BY_KEY))
        )

    usable, reason = cls.available()
    if not usable:
        raise ProviderUnavailable("{} is not usable: {}".format(cls.label, reason))

    if model and model not in cls.models and not _accepts_any_model(cls):
        raise ProviderUnavailable(
            "{} does not offer model '{}'. Available: {}".format(
                cls.label, model, ", ".join(cls.models)
            )
        )
    return cls(model=model)


def _accepts_any_model(cls: Type[TriageProvider]) -> bool:
    """Ollama serves whatever the user has pulled, so its list is advisory."""
    return cls is OllamaProvider


def default_provider_key() -> str:
    """First configured provider, preferring Claude. `none` when nothing is."""
    for cls in PROVIDER_CLASSES:
        usable, _ = cls.available()
        if usable:
            return cls.key
    return NONE


def provider_status() -> list[dict]:
    """Everything the UI needs to render the provider picker."""
    entries = [
        {
            "key": NONE,
            "label": "No AI",
            "description": "Scanners only - raw severities, deduplicated, no narrative.",
            "available": True,
            "reason": "",
            "models": [],
            "default_model": "",
            "requires_key": "",
            "local": True,
        }
    ]
    for cls in PROVIDER_CLASSES:
        usable, reason = cls.available()
        info = {
            "key": cls.key,
            "label": cls.label,
            "description": cls.description,
            "available": usable,
            "reason": reason,
            "models": list(cls.models),
            "default_model": cls.default_model,
            "requires_key": cls.requires_key,
            "local": cls.local,
        }
        if cls is OllamaProvider and usable:
            # Offer what is actually pulled rather than our suggested list.
            pulled = OllamaProvider.installed_models()
            if pulled:
                info["models"] = pulled
                info["default_model"] = (
                    cls.default_model if cls.default_model in pulled else pulled[0]
                )
        entries.append(info)
    return entries


__all__ = [
    "NONE",
    "PROVIDER_CLASSES",
    "ProviderUnavailable",
    "TriageBatch",
    "TriageError",
    "TriageProvider",
    "TriagedFinding",
    "Usage",
    "default_provider_key",
    "get_provider",
    "provider_status",
]
