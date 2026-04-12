"""
Gate 5 — Monotonic score gate (auto-harness pattern).

Rejects any APO variant that scores below the v3 baseline on the held-out
regression suite. No overnight run may start without this gate live.

Baselines (from critique ablation head-to-head run, 2026-04-11):
  Held-out (6 contracts, 21 vulns):  P=37.2% R=76.2% F1=50.0%
  Train    (16 contracts, 32 vulns): P=33.3% R=81.2% F1=47.3%

Abort criterion (from decision record):
  Any recall drop > 5pp vs baseline triggers immediate stop.
  Held-out recall floor: 76.2% - 5pp = 71.2%

Decision: ~/Annunaki/Agent Vault/decisions/Adopt agent-lightning APO experiment.md
Pattern: ~/Annunaki/Agent Vault/research/repos/auto-harness.md (monotonic gate)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).parent.parent))

from apo.reward import (
    HELD_OUT_CONTRACTS,
    TRAIN_CONTRACTS,
    compute_contract_reward,
    compute_aggregate_reward,
)
from agents.benchmark_v2_runner import evaluate_contract


# ---------------------------------------------------------------------------
# Baseline metrics (from the 2026-04-11 critique ablation head-to-head run)
# ---------------------------------------------------------------------------

HELD_OUT_BASELINE = {
    "f1": 0.500,
    "precision": 0.372,
    "recall": 0.762,
    "tp": 16, "fp": 27, "fn": 5,
}

# Abort criterion: recall must not drop more than 5pp below baseline
RECALL_FLOOR = HELD_OUT_BASELINE["recall"] - 0.05  # 0.712


# ---------------------------------------------------------------------------
# Regression gate
# ---------------------------------------------------------------------------

def run_regression_gate(
    analyzer_fn: Callable[[str, str], list[Any]],
    *,
    label: str = "APO variant",
    verbose: bool = True,
) -> dict[str, Any]:
    """Run the analyzer on the held-out set and gate against the baseline.

    Args:
        analyzer_fn: callable(source_code, contract_name) -> list[Finding]
            Each Finding must have a 'vuln_type' or 'type' attribute/key.
        label: human-readable name for this variant.
        verbose: print per-contract breakdown.

    Returns:
        dict with 'passed', 'metrics', 'violations' keys.
        'passed' is True only if ALL gate conditions are met:
          1. F1 >= baseline F1 (monotonic — never regress)
          2. Recall >= RECALL_FLOOR (abort criterion)
    """
    per_contract = []
    for name, data in HELD_OUT_CONTRACTS.items():
        result = evaluate_contract(
            name, data["source"], data["ground_truth"], analyzer_fn
        )
        per_contract.append(result)

        if verbose:
            gt_count = len(result["gt"])
            print(
                f"  {name:<25} GT={gt_count}  "
                f"TP={result['tp']} FP={result['fp']} FN={result['fn']}"
            )

    metrics = compute_aggregate_reward(per_contract)
    violations = []

    # Gate 1: monotonic F1
    if metrics["f1"] < HELD_OUT_BASELINE["f1"]:
        violations.append(
            f"F1 regression: {metrics['f1']:.1%} < baseline {HELD_OUT_BASELINE['f1']:.1%}"
        )

    # Gate 2: recall floor (abort criterion)
    if metrics["recall"] < RECALL_FLOOR:
        violations.append(
            f"ABORT: Recall {metrics['recall']:.1%} < floor {RECALL_FLOOR:.1%} "
            f"(baseline {HELD_OUT_BASELINE['recall']:.1%} - 5pp)"
        )

    passed = len(violations) == 0

    if verbose:
        print(f"\n  {label}:")
        print(f"    P={metrics['precision']:.1%}  R={metrics['recall']:.1%}  F1={metrics['f1']:.1%}")
        print(f"    Baseline:  P={HELD_OUT_BASELINE['precision']:.1%}  "
              f"R={HELD_OUT_BASELINE['recall']:.1%}  F1={HELD_OUT_BASELINE['f1']:.1%}")
        print(f"    Recall floor: {RECALL_FLOOR:.1%}")
        if passed:
            print(f"    GATE: PASS")
        else:
            for v in violations:
                print(f"    GATE VIOLATION: {v}")

    return {
        "passed": passed,
        "metrics": metrics,
        "violations": violations,
        "per_contract": per_contract,
    }


# ---------------------------------------------------------------------------
# Dry-run: verify the gate passes on the current v3 baseline analyzer
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os

    print("=" * 60)
    print("GATE 5 — Monotonic score gate dry-run")
    print("=" * 60)

    print(f"\n  Baseline F1 (held-out): {HELD_OUT_BASELINE['f1']:.1%}")
    print(f"  Recall floor:           {RECALL_FLOOR:.1%}")
    print(f"  Held-out contracts:     {len(HELD_OUT_CONTRACTS)}")
    print(f"  Held-out vulns:         {sum(len(d['ground_truth']['vulnerabilities']) for d in HELD_OUT_CONTRACTS.values())}")

    # Use a mock analyzer that returns exactly the baseline's known results
    # to verify the gate logic without making LLM calls.
    #
    # The baseline results (from results_critique_ablation.json) are:
    # RoninStyle: TP=4 FP=4 FN=1 → matched 4 of 5 GT vulns
    # OracleManipulation: TP=2 FP=5 FN=0 → perfect recall
    # PolyNetworkStyle: TP=1 FP=4 FN=2 → 1 of 3
    # MalleableSig: TP=2 FP=3 FN=0 → perfect recall
    # DriftStyle: TP=4 FP=6 FN=1 → 4 of 5
    # CCTPStyle: TP=3 FP=5 FN=1 → 3 of 4

    from dataclasses import dataclass

    @dataclass
    class MockFinding:
        vuln_type: str
        severity: str = "high"
        location: str = "mock"
        description: str = "mock finding"
        confidence: float = 0.8

    # Build mock findings that reproduce the baseline TP/FP counts
    MOCK_RESULTS = {
        "RoninStyle": {
            "matched": ["low_validator_threshold", "duplicate_signature_acceptance",
                        "no_rate_limiting", "unprotected_admin_function"],
            "fps": ["cross_chain_replay", "missing_nonce", "input_validation_missing",
                     "unprotected_admin_function"],
        },
        "OracleManipulation": {
            "matched": ["spot_price_oracle", "flash_loan_exploitable"],
            "fps": ["arbitrary_calldata", "reentrancy", "input_validation_missing",
                     "zero_value_deposit", "front_running"],
        },
        "PolyNetworkStyle": {
            "matched": ["unrestricted_cross_chain_call"],
            "fps": ["arbitrary_calldata", "unprotected_admin_function",
                     "missing_signature_verification", "arbitrary_execution"],
        },
        "MalleableSig": {
            "matched": ["signature_malleability"],
            "fps": ["missing_nonce", "cross_chain_replay", "input_validation_missing"],
        },
        "DriftStyle": {
            "matched": ["low_validator_threshold", "zero_timelock",
                        "oracle_manipulation_fake_token", "unprotected_admin_function"],
            "fps": ["missing_signature_verification", "reentrancy",
                     "cross_chain_replay", "missing_nonce", "forced_eth_reception",
                     "input_validation_missing"],
        },
        "CCTPStyle": {
            "matched": ["no_rate_limiting", "centralization_risk", "zero_timelock"],
            "fps": ["missing_input_validation", "cross_chain_replay",
                     "signature_malleability", "missing_event_emission",
                     "arbitrary_execution"],
        },
    }

    def mock_analyzer(source: str, contract_name: str = "Unknown") -> list[MockFinding]:
        """Mock analyzer reproducing baseline held-out performance."""
        if contract_name in MOCK_RESULTS:
            mock = MOCK_RESULTS[contract_name]
            findings = []
            for vt in mock["matched"]:
                findings.append(MockFinding(vuln_type=vt))
            for vt in mock["fps"]:
                findings.append(MockFinding(vuln_type=vt))
            return findings
        return []

    print(f"\n  Running gate with mock baseline analyzer ...\n")

    # The benchmark_v2_runner.evaluate_contract calls analyzer_fn(source)
    # but we need contract_name. Use a wrapper that captures name from the loop.
    result = run_regression_gate(
        lambda src, name="Unknown": mock_analyzer(src, name),
        label="Mock baseline (expected: PASS)",
        verbose=True,
    )

    print()
    if result["passed"]:
        print("  GATE 5: PASS — dry-run confirms gate logic accepts baseline performance")
    else:
        print("  GATE 5: FAIL — gate logic error, investigate violations above")
        for v in result["violations"]:
            print(f"    {v}")
    print("=" * 60)
