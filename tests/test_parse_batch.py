"""Response parsing for providers without hard schema enforcement.

Local and older models wrap their JSON in reasoning blocks, code fences or a
sentence of preamble. Anything that still contains the verdicts must parse;
anything that does not must raise rather than silently return nothing.

Run with `python tests/test_parse_batch.py` (no pytest required).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vapt.providers.base import TriageError, parse_batch  # noqa: E402

GOOD = """{"findings":[{"index":0,"verdict":"true_positive","confidence":"high",
"severity":"CRITICAL","attack_scenario":"Unauthenticated SQL injection.",
"remediation":"Parameterize the query in find().","rationale":"User input reaches execute()."}]}"""

CASES: list[tuple[str, str, int]] = [
    ("plain json", GOOD, 1),
    ("fenced json", "```json\n" + GOOD + "\n```", 1),
    ("bare fence", "```\n" + GOOD + "\n```", 1),
    ("preamble prose", "Here are my verdicts:\n\n" + GOOD, 1),
    ("trailing prose", GOOD + "\n\nLet me know if you need more detail.", 1),
    ("reasoning block", "<think>\nThe query is built with %s...\n</think>\n" + GOOD, 1),
    ("bare array", GOOD.split('"findings":')[1].rsplit("}", 1)[0], 1),
    ("synonym key", GOOD.replace('"findings"', '"results"'), 1),
    # Index 7 was never sent, so it must be dropped rather than trusted.
    ("unknown index dropped", GOOD.replace('"index":0', '"index":7'), 0),
]

FAILURES: list[tuple[str, str]] = [
    ("empty", ""),
    ("prose only", "I could not analyse these findings."),
    ("wrong shape", '{"findings": [{"index": 0, "verdict": "maybe"}]}'),
    ("truncated", '{"findings":[{"index":0,"verdict":"true_pos'),
]


def main() -> int:
    failed = 0

    for name, text, expected in CASES:
        try:
            got = parse_batch(text, {0})
        except TriageError as exc:
            print(f"  FAIL  {name}: raised {exc}")
            failed += 1
            continue
        if len(got) != expected:
            print(f"  FAIL  {name}: expected {expected} verdict(s), got {len(got)}")
            failed += 1
        else:
            print(f"  ok    {name}")

    for name, text in FAILURES:
        try:
            parse_batch(text, {0})
        except TriageError:
            print(f"  ok    rejects {name}")
        else:
            print(f"  FAIL  rejects {name}: should have raised")
            failed += 1

    # A valid response must survive the round trip with its fields intact.
    verdict = parse_batch(GOOD, {0})[0]
    assert verdict.verdict == "true_positive", verdict.verdict
    assert verdict.severity == "CRITICAL", verdict.severity
    assert "Parameterize" in verdict.remediation
    print("  ok    fields preserved")

    print("\n{} failure(s)".format(failed) if failed else "\nall parse cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
