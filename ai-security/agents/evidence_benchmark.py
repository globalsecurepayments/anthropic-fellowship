"""
Evidence Ladder benchmark runner.

Wraps the existing agent_v2_bridge analyzer with evidence-level tagging
and a reporting gate, then measures ΔF1 against the ungated baseline.

This is Phase 1 — measurement + reporting gate. No adversarial verifier.

Usage:
    cd ai-security && USE_BIFROST=1 python -m agents.evidence_benchmark

HARD ABORT if recall drops > 5pp vs 87.7% baseline.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmarks.fixtures.bridge_contracts_v2 import ALL_CONTRACTS
from agents.agent_v2_bridge import analyze_with_agent_v2, AgentV2Finding
from agents.static_analyzer_v2 import analyze_static
from agents.benchmark_v2_runner import run_benchmark, evaluate_contract
from agents.evidence_ladder import (
    cross_check_static,
    apply_reporting_gate,
    MIN_EVIDENCE_LEVEL,
)


# ---------------------------------------------------------------------------
# V3 baseline (from RESULTS.md — 29 contracts, but dataset has 22)
# Using the 22-contract baseline from the critique ablation run.
# ---------------------------------------------------------------------------

BASELINE = {
    "f1": 0.552,
    "precision": 0.409,
    "recall": 0.849,
}

# Abort if recall drops more than 5pp
RECALL_FLOOR = BASELINE["recall"] - 0.05  # 0.799


# ---------------------------------------------------------------------------
# Evidence-gated analyzer
# ---------------------------------------------------------------------------

def analyze_with_evidence_gate(
    source_code: str,
    contract_name: str = "Unknown",
) -> list[AgentV2Finding]:
    """Run agent_v2_bridge + static cross-check + evidence reporting gate.

    Returns only findings that pass the reporting gate (>= MIN_EVIDENCE_LEVEL).
    Suspicion-only findings are excluded from scored output but would be
    retained in a full pipeline for raw logging.
    """
    # 1. Run the LLM analyzer (unchanged — same prompt, same model)
    all_findings = analyze_with_agent_v2(source_code, contract_name)

    # 2. Run the static analyzer for cross-checking
    static_findings = analyze_static(source_code)

    # 3. Convert AgentV2Finding dataclasses to dicts for tagging
    finding_dicts = [
        {
            "vuln_type": f.vuln_type,
            "severity": f.severity,
            "location": f.location,
            "description": f.description,
            "exploit_scenario": f.exploit_scenario,
            "confidence": f.confidence,
        }
        for f in all_findings
    ]

    # 4. Tag evidence levels via static cross-check
    tagged = cross_check_static(finding_dicts, static_findings, source_code)

    # 5. Apply reporting gate — split into reported vs below-threshold
    reported, below = apply_reporting_gate(tagged)

    # 6. Convert back to AgentV2Finding for compatibility with benchmark runner
    gated_findings = [
        AgentV2Finding(
            vuln_type=f["vuln_type"],
            severity=f["severity"],
            location=f["location"],
            description=f["description"],
            exploit_scenario=f.get("exploit_scenario", ""),
            confidence=f.get("confidence", 0.5),
        )
        for f in reported
    ]

    return gated_findings


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

def run_evidence_benchmark():
    """Single-run evidence tagging: run LLM once, compare ALL vs GATED findings.

    This eliminates LLM run-to-run variance by using the same LLM output
    for both baseline and gated measurements.
    """

    if os.environ.get("USE_BIFROST") != "1":
        print("Requires USE_BIFROST=1. Run:")
        print("  USE_BIFROST=1 python -m agents.evidence_benchmark")
        return

    print("=" * 70)
    print("EVIDENCE LADDER — Phase 1: Tagging + Reporting Gate")
    print(f"MIN_EVIDENCE_LEVEL: {MIN_EVIDENCE_LEVEL}")
    print("=" * 70)

    # --- Single LLM pass: run analyzer once, tag, then split ---
    print("\n--- Running agent v2 + static cross-check (single pass) ---")
    baseline_results = []
    gated_results = []
    total_suspicion = 0
    total_corroborated = 0

    for name, data in ALL_CONTRACTS.items():
        source = data["source"]
        gt = data["ground_truth"]

        # Run LLM analyzer ONCE
        all_findings = analyze_with_agent_v2(source, name)

        # Run static analyzer for cross-check
        static_findings = analyze_static(source)

        # Convert to dicts for tagging
        finding_dicts = [
            {
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "location": f.location,
                "description": f.description,
                "exploit_scenario": f.exploit_scenario,
                "confidence": f.confidence,
            }
            for f in all_findings
        ]

        # Tag evidence levels
        tagged = cross_check_static(finding_dicts, static_findings, source)

        # Count evidence levels
        for f in tagged:
            if f.get("evidence_level") == "suspicion":
                total_suspicion += 1
            else:
                total_corroborated += 1

        # Baseline: ALL findings (ungated)
        baseline_findings = [
            AgentV2Finding(
                vuln_type=f["vuln_type"], severity=f["severity"],
                location=f["location"], description=f["description"],
                exploit_scenario=f.get("exploit_scenario", ""),
                confidence=f.get("confidence", 0.5),
            )
            for f in tagged
        ]

        # Gated: only findings passing the evidence threshold
        reported, below = apply_reporting_gate(tagged)
        gated_findings = [
            AgentV2Finding(
                vuln_type=f["vuln_type"], severity=f["severity"],
                location=f["location"], description=f["description"],
                exploit_scenario=f.get("exploit_scenario", ""),
                confidence=f.get("confidence", 0.5),
            )
            for f in reported
        ]

        # Evaluate both against ground truth
        b_result = evaluate_contract(name, source, gt, lambda s, n=None: baseline_findings)
        g_result = evaluate_contract(name, source, gt, lambda s, n=None: gated_findings)

        baseline_results.append(b_result)
        gated_results.append(g_result)

        gt_count = len(g_result["gt"])
        print(f"  {name:<25} GT={gt_count}  "
              f"All: TP={b_result['tp']} FP={b_result['fp']} FN={b_result['fn']}  |  "
              f"Gated: TP={g_result['tp']} FP={g_result['fp']} FN={g_result['fn']}  "
              f"(filtered {len(below)})")

    print(f"\n  Evidence level distribution: "
          f"{total_suspicion} suspicion, {total_corroborated} corroborated")

    # Compute aggregate metrics
    def aggregate(results):
        tp = sum(r["tp"] for r in results)
        fp = sum(r["fp"] for r in results)
        fn = sum(r["fn"] for r in results)
        p = tp / (tp + fp) if (tp + fp) > 0 else 0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
        return {"precision": p, "recall": r, "f1": f1, "tp": tp, "fp": fp, "fn": fn}

    baseline_metrics = aggregate(baseline_results)
    gated_metrics = aggregate(gated_results)

    # --- Comparison ---
    print("\n" + "=" * 70)
    print("COMPARISON")
    print("=" * 70)
    print(f"{'Metric':<20} {'Baseline':>12} {'+ Evidence':>14} {'Delta':>10}")
    print("-" * 58)
    for key, label in [("precision", "Precision"), ("recall", "Recall"), ("f1", "F1")]:
        b = baseline_metrics[key]
        t = gated_metrics[key]
        delta = t - b
        sign = "+" if delta >= 0 else ""
        print(f"{label:<20} {b:>11.1%} {t:>13.1%} {sign}{delta:>9.1%}")

    print(f"\n{'TP':<20} {baseline_metrics['tp']:>12} {gated_metrics['tp']:>14}")
    print(f"{'FP':<20} {baseline_metrics['fp']:>12} {gated_metrics['fp']:>14}")
    print(f"{'FN':<20} {baseline_metrics['fn']:>12} {gated_metrics['fn']:>14}")

    # --- Recall guardrail ---
    delta_recall = gated_metrics["recall"] - baseline_metrics["recall"]
    delta_f1 = gated_metrics["f1"] - baseline_metrics["f1"]
    delta_precision = gated_metrics["precision"] - baseline_metrics["precision"]

    print("\n" + "=" * 70)
    if gated_metrics["recall"] < RECALL_FLOOR:
        print(f"ABORT: Recall {gated_metrics['recall']:.1%} < floor {RECALL_FLOOR:.1%}")
        print(f"  Recall dropped {abs(delta_recall):.1%} — exceeds 5pp guardrail")
        print("  File NO-GO decision per decision record protocol.")
    elif delta_recall < -0.05:
        print(f"ABORT: Recall delta {delta_recall:.1%} exceeds -5pp guardrail")
    elif delta_precision >= 0.05 and delta_recall >= -0.03:
        print(f"SUCCESS: Precision +{delta_precision:.1%}, Recall {delta_recall:+.1%}")
        print(f"  Evidence Ladder Phase 1 meets success criteria.")
        print(f"  Proceed to Phase 2 (Adversarial Verifier).")
    elif delta_f1 >= 0:
        print(f"NEUTRAL: F1 improved +{delta_f1:.1%} but precision gain < +5pp")
        print(f"  Evidence Ladder helps but below threshold for Phase 2.")
    else:
        print(f"NEGATIVE: F1 regressed {delta_f1:.1%}")
    print("=" * 70)

    # --- Save results ---
    results_path = Path(__file__).parent.parent / "results_evidence_ladder.json"
    with open(results_path, "w") as f:
        json.dump({
            "phase": 1,
            "min_evidence_level": MIN_EVIDENCE_LEVEL,
            "baseline": {
                k: v for k, v in baseline_metrics.items() if k != "results"
            },
            "evidence_gated": {
                k: v for k, v in gated_metrics.items() if k != "results"
            },
            "delta_f1": delta_f1,
            "delta_precision": delta_precision,
            "delta_recall": delta_recall,
            "recall_floor": RECALL_FLOOR,
            "abort": gated_metrics["recall"] < RECALL_FLOOR or delta_recall < -0.05,
        }, f, indent=2)
    print(f"\nResults saved to {results_path}")


if __name__ == "__main__":
    run_evidence_benchmark()
