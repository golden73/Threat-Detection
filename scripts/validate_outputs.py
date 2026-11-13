"""
Validate that the committed output artifacts exist and have the expected
structure. Run in CI so a broken regeneration step can't slip through, and
useful locally after a pipeline run.

Exits non-zero on the first missing/malformed artifact.
"""
import json
from pathlib import Path

OUT = Path("outputs")

# artifact -> required keys
REQUIRED = {
    "metrics.json": {"precision", "recall", "f1", "false_positive_rate"},
    "metrics_with_port.json": {"precision", "recall", "f1"},
    "alerts.json": None,          # any valid JSON list/dict
    "incidents.json": None,
    "hard_eval.json": {"chronological", "leave_one_attack_out", "cross_capture"},
    "hard_eval_with_port.json": {"chronological"},
}


def check(name: str, keys: set | None) -> None:
    path = OUT / name
    if not path.exists():
        raise SystemExit(f"MISSING: outputs/{name}")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise SystemExit(f"INVALID JSON: outputs/{name}: {e}")
    if keys:
        missing = keys - set(data)
        if missing:
            raise SystemExit(f"outputs/{name} missing keys: {sorted(missing)}")
    print(f"ok: outputs/{name}")


def main() -> None:
    for name, keys in REQUIRED.items():
        check(name, keys)
    reports = sorted((OUT / "reports").glob("*.md"))
    if not reports:
        raise SystemExit("MISSING: outputs/reports/*.md")
    print(f"ok: outputs/reports/ ({len(reports)} reports)")
    if not (OUT / "demo.html").exists():
        raise SystemExit("MISSING: outputs/demo.html")
    print("ok: outputs/demo.html")
    print("\nAll output artifacts valid.")


if __name__ == "__main__":
    main()
