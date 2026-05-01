"""Generate adversarial test fixtures from BRIDGE-bench source documents.

Feeds the 10-exploit catalogue (benchmarks/bridge_exploits.py) into DeepEval's
Synthesizer, capturing each evolution strategy (in-breadth / in-depth /
comparative / hypothetical) as a separate JSON fixture.

This is intentionally a one-shot generator. Outputs are committed to
ai-security/evals/fixtures/ so downstream metric runs are deterministic.

Run:
    DEEPEVAL_TELEMETRY_OPT_OUT=true python -m evals.synthesize_fixtures

Cost: ~1 judge call per evolution per source document. Default budget = 4
strategies × 1 attempt × 10 documents ≈ 40 judge calls.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Ensure deepeval telemetry is off before any deepeval import.
os.environ.setdefault("DEEPEVAL_TELEMETRY_OPT_OUT", "true")

from deepeval.synthesizer import Synthesizer  # noqa: E402
from deepeval.synthesizer.config import EvolutionConfig, Evolution  # noqa: E402

from evals.judge_factory import make_judge  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "evals" / "fixtures"

# Map decision-doc strategy names to DeepEval's actual Evolution enum.
# DeepEval 3.9.x exposes: REASONING, MULTICONTEXT, CONCRETIZING, CONSTRAINED,
# COMPARATIVE, HYPOTHETICAL, IN_BREADTH. The decision doc's "in-depth" maps to
# REASONING (depth-deepening evolution).
EVOLUTION_STRATEGIES = {
    "in_breadth": Evolution.IN_BREADTH,
    "in_depth": Evolution.REASONING,
    "comparative": Evolution.COMPARATIVE,
    "hypothetical": Evolution.HYPOTHETICAL,
}


def load_exploit_corpus() -> list[str]:
    """Render bridge_exploits.py metadata into prose source documents."""
    sys.path.insert(0, str(REPO_ROOT))
    from benchmarks.fixtures.bridge_exploits import BRIDGE_EXPLOITS  # type: ignore

    docs: list[str] = []
    for exploit in BRIDGE_EXPLOITS:
        loss = exploit.get("loss_usd", 0)
        docs.append(
            f"Exploit: {exploit.get('name', 'unknown')}\n"
            f"Date: {exploit.get('date', 'unknown')}\n"
            f"Chain: {exploit.get('chain', 'unknown')}\n"
            f"Loss (USD): {loss:,}\n"
            f"Category: {exploit.get('category', 'unknown')}\n"
            f"Vulnerability type: {exploit.get('vuln_type', 'unknown')}\n"
            f"Description: {exploit.get('description', '')}"
        )
    return docs


def synthesize(strategies: list[str], per_document: int) -> dict[str, list[dict]]:
    judge = make_judge()
    docs = load_exploit_corpus()
    out: dict[str, list[dict]] = {}

    for label in strategies:
        evolution = EVOLUTION_STRATEGIES[label]
        synthesizer = Synthesizer(
            model=judge,
            evolution_config=EvolutionConfig(
                evolutions={evolution: 1.0},
                num_evolutions=per_document,
            ),
        )
        goldens = synthesizer.generate_goldens_from_contexts(
            contexts=[[d] for d in docs],
            max_goldens_per_context=per_document,
        )
        out[label] = [g.dict() if hasattr(g, "dict") else dict(g) for g in goldens]
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--strategy",
        choices=list(EVOLUTION_STRATEGIES) + ["all"],
        default="all",
    )
    parser.add_argument("--per-document", type=int, default=1)
    args = parser.parse_args()

    strategies = list(EVOLUTION_STRATEGIES) if args.strategy == "all" else [args.strategy]

    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    results = synthesize(strategies, args.per_document)

    for label, goldens in results.items():
        path = FIXTURES_DIR / f"synthesized_{label}.json"
        path.write_text(json.dumps(goldens, indent=2, default=str))
        print(f"wrote {len(goldens)} goldens → {path.relative_to(REPO_ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
