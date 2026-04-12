"""
BRIDGE-bench: Cross-Chain Bridge Vulnerability Detection Benchmark

Runs static analysis (v2) against the full test contract suite and
produces evaluation metrics. When ANTHROPIC_API_KEY is set, also
runs Claude analysis and produces comparison metrics.

This is the core evaluation artifact for the AI Security Fellowship
application. The key question: does Claude find the compositional
vulnerabilities that static analysis misses?

Usage:
    python benchmark_runner.py                  # static only
    ANTHROPIC_API_KEY=sk-... python benchmark_runner.py  # static + Claude
"""

import os
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.static_analyzer_v2 import analyze_static, StaticFinding
from benchmarks.test_contracts import TEST_CONTRACTS


# Fuzzy type matching for evaluation
TYPE_EQUIVALENCES = {
    "unprotected_admin_function": ["unprotected_admin_function", "missing_access_control"],
    "untrusted_external_call": ["untrusted_external_call", "signature_verification_bypass"],
    "unused_signature_parameter": ["missing_signature_verification"],
    "missing_signature_verification": ["missing_signature_verification", "unused_signature_parameter"],
    "missing_reentrancy_guard": ["reentrancy"],
    "reentrancy": ["reentrancy", "missing_reentrancy_guard"],
    "spot_price_oracle": ["spot_price_oracle", "flash_loan_exploitable"],
    "flash_loan_exploitable": ["flash_loan_exploitable", "spot_price_oracle"],
    "unprotected_initializer": ["unprotected_initializer"],
    "reinitializable": ["reinitializable"],
    "zero_root_acceptance": ["zero_root_acceptance"],
    "no_rate_limiting": ["no_rate_limiting"],
    "low_validator_threshold": ["low_validator_threshold"],
    "duplicate_signature_acceptance": ["duplicate_signature_acceptance"],
    "no_withdrawal_delay": ["no_withdrawal_delay"],
    "missing_proof_link": ["missing_proof_link"],
}


def fuzzy_match(finding_type: str, gt_type: str) -> bool:
    f, g = finding_type.lower(), gt_type.lower()
    if f == g:
        return True
    return g in TYPE_EQUIVALENCES.get(f, [f])


def evaluate_findings(findings: list, gt_vulns: list) -> dict:
    gt_matched = set()
    finding_matched = set()

    for fi, f in enumerate(findings):
        ftype = f.vuln_type if isinstance(f, StaticFinding) else f.get("type", "")
        for gi, g in enumerate(gt_vulns):
            if gi not in gt_matched and fuzzy_match(ftype, g["type"]):
                gt_matched.add(gi)
                finding_matched.add(fi)
                break

    tp = len(gt_matched)
    fp = len(findings) - len(finding_matched)
    fn = len(gt_vulns) - len(gt_matched)
    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

    missed = [g["type"] for i, g in enumerate(gt_vulns) if i not in gt_matched]
    false_pos_types = []
    for i, f in enumerate(findings):
        if i not in finding_matched:
            false_pos_types.append(f.vuln_type if isinstance(f, StaticFinding) else f.get("type", ""))

    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": p, "recall": r, "f1": f1,
        "missed": missed, "false_positives": false_pos_types,
    }


def run_static_benchmark() -> dict:
    print("BRIDGE-bench: Static Analysis (v2)")
    print("=" * 60)

    results = {}
    totals = {"tp": 0, "fp": 0, "fn": 0}

    for name, data in TEST_CONTRACTS.items():
        findings = analyze_static(data["source"])
        gt = data["ground_truth"]["vulnerabilities"]
        metrics = evaluate_findings(findings, gt)

        results[name] = {
            "metrics": metrics,
            "n_findings": len(findings),
            "n_gt": len(gt),
            "findings": [{"type": f.vuln_type, "severity": f.severity, "confidence": f.confidence} for f in findings],
        }

        for k in ["tp", "fp", "fn"]:
            totals[k] += metrics[k]

        print(f"\n{name}: P={metrics['precision']:.0%} R={metrics['recall']:.0%} F1={metrics['f1']:.0%}")
        if metrics["missed"]:
            print(f"  MISSED: {metrics['missed']}")
        if metrics["false_positives"]:
            print(f"  FALSE+: {metrics['false_positives']}")

    p = totals["tp"] / (totals["tp"] + totals["fp"]) if (totals["tp"] + totals["fp"]) > 0 else 0
    r = totals["tp"] / (totals["tp"] + totals["fn"]) if (totals["tp"] + totals["fn"]) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

    print(f"\n{'=' * 60}")
    print(f"STATIC v2 OVERALL: P={p:.0%} R={r:.0%} F1={f1:.0%}")
    print(f"  {totals['tp']} true positives, {totals['fp']} false positives, {totals['fn']} missed")
    print()

    # What static CAN'T find (the gap Claude should fill)
    all_missed = []
    for name, r in results.items():
        for m in r["metrics"]["missed"]:
            all_missed.append(f"{name}: {m}")

    print("VULNERABILITIES STATIC ANALYSIS CANNOT DETECT:")
    print("(These require compositional reasoning — the Claude agent thesis)")
    for m in all_missed:
        print(f"  • {m}")

    return {
        "method": "static_v2",
        "overall": {"precision": p, "recall": r, "f1": f1, **totals},
        "per_contract": results,
        "systematic_gaps": all_missed,
    }


def run_claude_benchmark() -> dict | None:
    if not os.environ.get("ANTHROPIC_API_KEY") and os.environ.get("USE_BIFROST") != "1":
        print("\nSkipping Claude analysis (set ANTHROPIC_API_KEY or USE_BIFROST=1 to enable)")
        return None

    from agents.claude_analyzer import analyze_with_claude, static_prescreen

    print(f"\n{'=' * 60}")
    print("BRIDGE-bench: Claude Analysis")
    print("=" * 60)

    results = {}
    totals = {"tp": 0, "fp": 0, "fn": 0}

    for name, data in TEST_CONTRACTS.items():
        static = static_prescreen(data["source"])
        report = analyze_with_claude(data["source"], name, static)
        gt = data["ground_truth"]["vulnerabilities"]

        ai_findings = [{"type": v.type, "severity": v.severity} for v in report.vulnerabilities]
        metrics = evaluate_findings(ai_findings, gt)

        results[name] = {"metrics": metrics, "n_findings": len(ai_findings)}
        for k in ["tp", "fp", "fn"]:
            totals[k] += metrics[k]

        print(f"\n{name}: P={metrics['precision']:.0%} R={metrics['recall']:.0%} F1={metrics['f1']:.0%}")

    p = totals["tp"] / (totals["tp"] + totals["fp"]) if (totals["tp"] + totals["fp"]) > 0 else 0
    r = totals["tp"] / (totals["tp"] + totals["fn"]) if (totals["tp"] + totals["fn"]) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

    print(f"\n{'=' * 60}")
    print(f"CLAUDE OVERALL: P={p:.0%} R={r:.0%} F1={f1:.0%}")

    return {
        "method": "claude",
        "overall": {"precision": p, "recall": r, "f1": f1, **totals},
        "per_contract": results,
    }


if __name__ == "__main__":
    static_results = run_static_benchmark()

    claude_results = run_claude_benchmark()

    if claude_results:
        print(f"\n{'=' * 60}")
        print("COMPARISON: Static v2 vs Claude")
        print("=" * 60)
        s = static_results["overall"]
        c = claude_results["overall"]
        print(f"  Static v2:  P={s['precision']:.0%}  R={s['recall']:.0%}  F1={s['f1']:.0%}")
        print(f"  Claude:     P={c['precision']:.0%}  R={c['recall']:.0%}  F1={c['f1']:.0%}")
        delta = c["f1"] - s["f1"]
        print(f"  Delta F1:   {delta:+.0%}")

    # Save results
    output = {
        "static": static_results,
        "claude": claude_results,
        "benchmark_info": {
            "n_contracts": len(TEST_CONTRACTS),
            "n_vulns": sum(len(d["ground_truth"]["vulnerabilities"]) for d in TEST_CONTRACTS.values()),
            "contracts": list(TEST_CONTRACTS.keys()),
        },
    }
    output_path = Path(__file__).parent.parent / "results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to {output_path}")
