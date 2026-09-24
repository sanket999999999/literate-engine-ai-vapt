"""One hand-written JSON Schema for the triage batch.

Pydantic's generated schema uses `$defs`/`$ref`, which several providers'
strict structured-output modes reject. This is the same shape as
`base.TriageBatch`, inlined and closed (`additionalProperties: false`, every
property required) so it satisfies OpenAI strict mode and Gemini alike.
"""

from __future__ import annotations

from typing import Any

FINDING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "index": {
            "type": "integer",
            "description": "The finding's index exactly as given in the input list.",
        },
        "verdict": {
            "type": "string",
            "enum": ["true_positive", "false_positive", "needs_review"],
            "description": (
                "true_positive when the flaw is real and reachable; false_positive when "
                "the rule misfired; needs_review when the deciding context was missing."
            ),
        },
        "confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
        },
        "severity": {
            "type": "string",
            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            "description": "Severity in this codebase's context, not the scanner's default.",
        },
        "attack_scenario": {
            "type": "string",
            "description": (
                "Two or three sentences: who can reach this, what they send, what they "
                "get. Empty string for a false positive."
            ),
        },
        "remediation": {
            "type": "string",
            "description": "The specific fix, naming the function or setting to change.",
        },
        "rationale": {
            "type": "string",
            "description": "One or two sentences justifying the verdict.",
        },
    },
    "required": [
        "index", "verdict", "confidence", "severity",
        "attack_scenario", "remediation", "rationale",
    ],
    "additionalProperties": False,
}

BATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "description": "One entry per input finding, in any order.",
            "items": FINDING_SCHEMA,
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}


def schema_hint() -> str:
    """Prose description of the shape, for providers with no schema support."""
    return (
        "Reply with ONLY a JSON object, no prose and no code fence, shaped exactly:\n"
        '{"findings": [{"index": <int>, "verdict": "true_positive"|"false_positive"'
        '|"needs_review", "confidence": "high"|"medium"|"low", "severity": "CRITICAL"'
        '|"HIGH"|"MEDIUM"|"LOW"|"INFO", "attack_scenario": "<string>", '
        '"remediation": "<string>", "rationale": "<string>"}]}\n'
        "Include one entry for every finding you were given."
    )
