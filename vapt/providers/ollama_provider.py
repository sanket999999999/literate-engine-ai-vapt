"""Ollama - local models. No API key, no cost, nothing leaves the machine."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .base import (
    REPORT_SYSTEM,
    TRIAGE_SYSTEM,
    TriagedFinding,
    TriageError,
    TriageProvider,
    parse_batch,
    triage_user_prompt,
)
from .schema import BATCH_SCHEMA, schema_hint

DEFAULT_HOST = "http://127.0.0.1:11434"


def _host() -> str:
    return os.getenv("OLLAMA_HOST", DEFAULT_HOST).rstrip("/")


def _num_ctx() -> int:
    """Context window to allocate. Larger costs prefill time on CPU."""
    return int(os.getenv("VAPT_OLLAMA_NUM_CTX", "8192"))


def _timeout() -> int:
    return int(os.getenv("VAPT_OLLAMA_TIMEOUT", "900"))


def _post(path: str, body: dict, timeout: int) -> dict:
    request = urllib.request.Request(
        _host() + path,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise TriageError("ollama returned {}: {}".format(exc.code, detail)) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise TriageError("could not reach ollama at {}: {}".format(_host(), exc)) from exc


class OllamaProvider(TriageProvider):
    key = "ollama"
    label = "Ollama (local)"
    description = "Runs on this machine. Free and offline - no code is sent anywhere."
    default_model = "qwen2.5-coder:7b"
    models = (
        "qwen2.5-coder:7b",
        "qwen2.5-coder:14b",
        "llama3.1:8b",
        "deepseek-coder-v2:16b",
        "mistral-nemo:12b",
    )
    requires_key = ""      # nothing to configure
    local = True
    # A 7B model tracking twelve findings at once drifts badly and is slow;
    # four keeps each request short enough to stay coherent.
    batch_size = 4

    def __init__(self, model: str | None = None) -> None:
        super().__init__(model)
        # Local inference costs nothing, so every price stays at zero.

    @classmethod
    def available(cls) -> tuple[bool, str]:
        try:
            with urllib.request.urlopen(_host() + "/api/tags", timeout=3) as response:
                tags = json.loads(response.read().decode("utf-8", errors="replace"))
        except Exception:
            return False, "no Ollama server at {} - start it with `ollama serve`".format(_host())
        if not (tags.get("models") or []):
            return False, "Ollama is running but has no models - try `ollama pull qwen2.5-coder:7b`"
        return True, ""

    @classmethod
    def installed_models(cls) -> list[str]:
        """Models actually pulled locally, so the UI can offer the real list."""
        try:
            with urllib.request.urlopen(_host() + "/api/tags", timeout=3) as response:
                tags = json.loads(response.read().decode("utf-8", errors="replace"))
        except Exception:
            return []
        return [m["name"] for m in tags.get("models") or [] if m.get("name")]

    def triage_batch(self, payload: list[dict], indices: set[int]) -> list[TriagedFinding]:
        data = _post(
            "/api/chat",
            {
                "model": self.model,
                "messages": [
                    # Small local models drift from the schema, so it is restated
                    # in the prompt as well as passed in `format`.
                    {"role": "system", "content": TRIAGE_SYSTEM + "\n\n" + schema_hint()},
                    {"role": "user", "content": triage_user_prompt(payload)},
                ],
                "stream": False,
                "format": BATCH_SCHEMA,
                "options": {"temperature": 0.0, "num_ctx": _num_ctx()},
            },
            timeout=_timeout(),
        )
        self._record(data)
        return parse_batch((data.get("message") or {}).get("content", ""), indices)

    def narrative(self, prompt: str) -> str:
        data = _post(
            "/api/chat",
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": REPORT_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "options": {"temperature": 0.2, "num_ctx": _num_ctx()},
            },
            timeout=_timeout(),
        )
        self._record(data)
        return ((data.get("message") or {}).get("content", "") or "").strip()

    def _record(self, data: dict) -> None:
        self.usage.add(
            input_tokens=data.get("prompt_eval_count", 0) or 0,
            output_tokens=data.get("eval_count", 0) or 0,
        )
