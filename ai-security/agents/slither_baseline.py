"""
Slither Baseline: Run Slither against all 20 BRIDGE-bench v2 contracts
and compare detection rates with our static analyzer.

Slither is Trail of Bits' state-of-the-art static analysis tool for Solidity.
It uses AST analysis + data flow + taint tracking, which is much more
sophisticated than our regex-based static_analyzer_v2.py.

Usage:
    cd ai-security && python agents/slither_baseline.py
"""

import json
import subprocess
import sys
import tempfile
import os
from pathlib import Path
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmarks.fixtures.bridge_contracts_v2 import ALL_CONTRACTS
from agents.benchmark_v2_runner import fuzzy_match, evaluate_contract


@dataclass
class SlitherFinding:
    vuln_type: str
    severity: str
    location: str
    description: str
    confidence: float = 0.5


# Map Slither detector names to our vulnerability taxonomy
SLITHER_TO_VULN_MAP = {
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy",
    "uninitialized-state": "unprotected_initializer",
    "uninitialized-local": "unprotected_initializer",
    "arbitrary-send-eth": "arbitrary_external_call",
    "arbitrary-send-erc20": "approval_drain",
    "controlled-delegatecall": "delegatecall_to_user_input",
    "delegatecall-loop": "delegatecall_to_user_input",
    "suicidal": "selfdestruct_risk",
    "unprotected-upgrade": "unprotected_upgrade",
    "unchecked-transfer": "unchecked_transfer_return",
    "unchecked-lowlevel": "unchecked_transfer_return",
    "unchecked-send": "unchecked_transfer_return",
    "tx-origin": "tx_origin",
    "shadowing-state": "shadowing",
    "shadowing-local": "shadowing",
    "missing-zero-check": "missing_input_validation",
    "calls-loop": "unbounded_loop_dos",
    "msg-value-loop": "unbounded_loop_dos",
    "locked-ether": "locked_ether",
    "incorrect-equality": "incorrect_equality",
    "unused-return": "unchecked_transfer_return",
    "erc20-interface": "erc20_interface",
    "events-access": "missing_event_emission",
    "events-maths": "missing_event_emission",
    "low-level-calls": "low_level_call",
    "missing-inheritance": "missing_inheritance",
}

SEVERITY_MAP = {
    "High": "critical",
    "Medium": "high",
    "Low": "medium",
    "Informational": "informational",
    "Optimization": "informational",
}


def run_slither_on_source(source_code: str, contract_name: str) -> list[SlitherFinding]:
    """Run Slither on a Solidity source string, return findings."""
    findings = []

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write source file
        sol_file = Path(tmpdir) / f"{contract_name}.sol"
        sol_file.write_text(source_code)

        try:
            result = subprocess.run(
                [
                    "slither", str(sol_file),
                    "--json", "-",
                    "--solc-disable-warnings",
                ],
                capture_output=True, text=True, timeout=60,
                env={**os.environ, "PATH": f"/root/.local/bin:{os.environ.get('PATH', '')}"},
            )

            # Parse JSON output
            if result.stdout.strip():
                data = json.loads(result.stdout)
                for detector in data.get("results", {}).get("detectors", []):
                    check = detector.get("check", "unknown")
                    impact = detector.get("impact", "Medium")
                    desc = detector.get("description", "")

                    # Map to our taxonomy
                    vuln_type = SLITHER_TO_VULN_MAP.get(check, check)
                    severity = SEVERITY_MAP.get(impact, "medium")

                    # Get location
                    elements = detector.get("elements", [])
                    location = "unknown"
                    if elements:
                        elem = elements[0]
                        location = elem.get("name", elem.get("type", "unknown"))

                    findings.append(SlitherFinding(
                        vuln_type=vuln_type,
                        severity=severity,
                        location=location,
                        description=desc[:200],
                        confidence=0.7 if impact in ("High", "Medium") else 0.4,
                    ))

        except subprocess.TimeoutExpired:
            findings.append(SlitherFinding(
                vuln_type="timeout",
                severity="informational",
                location="",
                description="Slither timed out after 60s",
            ))
        except json.JSONDecodeError:
            # Slither may output non-JSON (compilation errors, etc.)
            pass
        except FileNotFoundError:
            print("ERROR: Slither not installed. Run: pip install slither-analyzer")
            sys.exit(1)

    return findings


def slither_analyzer(source: str) -> list[SlitherFinding]:
    """Adapter function matching the benchmark_v2_runner interface."""
    return run_slither_on_source(source, "Contract")


def run_comparison():
    """Run Slither against all contracts and compare with static analyzer."""
    from agents.static_analyzer_v2 import analyze_static
    from agents.benchmark_v2_runner import run_benchmark

    print("=" * 70)
    print("SLITHER vs STATIC ANALYZER — Head-to-Head Comparison")
    print("=" * 70)

    # Run static analyzer
    print("\n--- Static Analyzer v2 ---")
    static_metrics = run_benchmark(analyze_static, verbose=False)

    # Run Slither
    print("\n--- Slither ---")
    slither_results = []
    total_tp, total_fp, total_fn = 0, 0, 0

    for name, data in ALL_CONTRACTS.items():
        findings = run_slither_on_source(data["source"], name)

        # Filter to high/critical only (skip informational noise)
        findings = [f for f in findings if f.severity in ("critical", "high", "medium")]

        result = evaluate_contract(name, data["source"], data["ground_truth"],
                                    lambda src, n=name, f=findings: f)
        slither_results.append(result)
        total_tp += result["tp"]
        total_fp += result["fp"]
        total_fn += result["fn"]

        gt_count = len(result["gt"])
        found_count = len(result["findings"])
        status = "PERFECT" if result["tp"] == gt_count and result["fp"] == 0 else ""
        if result["tp"] == 0 and gt_count > 0:
            status = "MISS"
        print(f"  {name:<25} GT={gt_count}  Found={found_count}  "
              f"TP={result['tp']} FP={result['fp']} FN={result['fn']}  {status}")

    # Slither metrics
    s_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    s_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    s_f1 = 2 * s_precision * s_recall / (s_precision + s_recall) if (s_precision + s_recall) > 0 else 0

    # Comparison table
    print("\n" + "=" * 70)
    print("COMPARISON")
    print("=" * 70)
    print(f"{'Metric':<20} {'Static v2':>12} {'Slither':>12}")
    print("-" * 46)
    print(f"{'Precision':<20} {static_metrics['precision']:>11.1%} {s_precision:>11.1%}")
    print(f"{'Recall':<20} {static_metrics['recall']:>11.1%} {s_recall:>11.1%}")
    print(f"{'F1':<20} {static_metrics['f1']:>11.1%} {s_f1:>11.1%}")
    print(f"{'True Positives':<20} {static_metrics['tp']:>12} {total_tp:>12}")
    print(f"{'False Positives':<20} {static_metrics['fp']:>12} {total_fp:>12}")
    print(f"{'False Negatives':<20} {static_metrics['fn']:>12} {total_fn:>12}")

    print(f"\nThe LLM agent target is to beat BOTH baselines.")
    print(f"Key advantage of LLMs: compositional reasoning about cross-contract")
    print(f"interactions that neither static tool can capture.")

    return {
        "static": static_metrics,
        "slither": {"precision": s_precision, "recall": s_recall, "f1": s_f1,
                     "tp": total_tp, "fp": total_fp, "fn": total_fn},
    }


if __name__ == "__main__":
    run_comparison()
