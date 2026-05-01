"""
Gate 4 — Ground-truth reward function + held-out split.

Deterministic reward computed from BRIDGE-bench v3 ground truth labels.
NO self-assessment. The critique ablation (2026-04-11, ΔF1 = −38.9pp)
proved self-assessment rewards destroy recall-strong baselines. The reward
function here is independent of the model being optimized.

Decision: ~/Annunaki/Agent Vault/decisions/Adopt agent-lightning APO experiment.md
Lesson: ~/Annunaki/Agent Vault/decisions/Do-not-promote critique pattern — BRIDGE-bench ablation 2026-04-11.md
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmarks.fixtures.bridge_contracts_v2 import ALL_CONTRACTS
from agents.benchmark_v2_runner import fuzzy_match


# ---------------------------------------------------------------------------
# Held-out split
# ---------------------------------------------------------------------------
# 22 contracts total. 16 train (used in APO reward), 6 held-out (regression
# gate only — never seen by APO). Held-out includes the two hardest contracts
# (DriftStyle, CCTPStyle) plus four diverse mid-difficulty contracts to prevent
# overfitting to easy patterns.

HELD_OUT_NAMES = frozenset({
    "DriftStyle",       # 5 vulns, hardest multi-class contract
    "CCTPStyle",        # 4 vulns, centralization + rate limiting
    "RoninStyle",       # 5 vulns, validator governance
    "OracleManipulation",  # 2 vulns, flash loan + oracle
    "PolyNetworkStyle", # 3 vulns, arbitrary execution
    "MalleableSig",     # 2 vulns, crypto-specific
})

TRAIN_CONTRACTS = {
    name: data for name, data in ALL_CONTRACTS.items()
    if name not in HELD_OUT_NAMES
}

HELD_OUT_CONTRACTS = {
    name: data for name, data in ALL_CONTRACTS.items()
    if name in HELD_OUT_NAMES
}

assert len(TRAIN_CONTRACTS) + len(HELD_OUT_CONTRACTS) == len(ALL_CONTRACTS), (
    f"Split error: {len(TRAIN_CONTRACTS)} train + {len(HELD_OUT_CONTRACTS)} held-out "
    f"!= {len(ALL_CONTRACTS)} total"
)


# ---------------------------------------------------------------------------
# Per-contract reward function
# ---------------------------------------------------------------------------

def compute_contract_reward(
    findings: list[dict[str, Any]],
    ground_truth: dict[str, Any],
) -> float:
    """Compute a deterministic F1-based reward for one contract.

    Args:
        findings: list of dicts with at least a 'vuln_type' or 'type' key.
        ground_truth: dict with 'vulnerabilities' key containing list of
            dicts with 'type' key (from bridge_contracts_v2.ALL_CONTRACTS).

    Returns:
        F1 score for this contract (0.0 to 1.0).
        Returns 0.0 when there are no ground truth vulns AND no findings.
        Returns 0.0 when TP = 0 (no correct detections).
    """
    gt_vulns = ground_truth["vulnerabilities"]
    gt_types = [v["type"] for v in gt_vulns]

    # Match findings to ground truth using the same fuzzy_match from
    # benchmark_v2_runner — ensures reward is consistent with eval metrics.
    matched_gt: set[int] = set()
    matched_findings: set[int] = set()

    for i, finding in enumerate(findings):
        f_type = (
            finding.get("vuln_type")
            or finding.get("type")
            or getattr(finding, "vuln_type", "unknown")
        )
        for j, gt_type in enumerate(gt_types):
            if j not in matched_gt and fuzzy_match(f_type, gt_type):
                matched_gt.add(j)
                matched_findings.add(i)
                break

    tp = len(matched_gt)
    fp = len(findings) - len(matched_findings)
    fn = len(gt_vulns) - len(matched_gt)

    # F1 = 2*TP / (2*TP + FP + FN)
    denom = 2 * tp + fp + fn
    if denom == 0:
        return 0.0
    return (2 * tp) / denom


def compute_aggregate_reward(
    per_contract_results: list[dict[str, Any]],
) -> dict[str, float]:
    """Compute aggregate P/R/F1 from per-contract TP/FP/FN counts.

    Args:
        per_contract_results: list of dicts with 'tp', 'fp', 'fn' keys.

    Returns:
        dict with 'precision', 'recall', 'f1' keys.
    """
    total_tp = sum(r["tp"] for r in per_contract_results)
    total_fp = sum(r["fp"] for r in per_contract_results)
    total_fn = sum(r["fn"] for r in per_contract_results)

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": total_tp,
        "fp": total_fp,
        "fn": total_fn,
    }


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("GATE 4 — Ground-truth reward + held-out split verification")
    print("=" * 60)

    print(f"\n  Total contracts: {len(ALL_CONTRACTS)}")
    print(f"  Train split:     {len(TRAIN_CONTRACTS)} contracts")
    print(f"  Held-out split:  {len(HELD_OUT_CONTRACTS)} contracts")
    print(f"  Held-out names:  {sorted(HELD_OUT_NAMES)}")

    # Count total ground truth vulns per split
    train_vulns = sum(
        len(d["ground_truth"]["vulnerabilities"]) for d in TRAIN_CONTRACTS.values()
    )
    held_vulns = sum(
        len(d["ground_truth"]["vulnerabilities"]) for d in HELD_OUT_CONTRACTS.values()
    )
    print(f"\n  Train vulns:     {train_vulns}")
    print(f"  Held-out vulns:  {held_vulns}")
    print(f"  Total vulns:     {train_vulns + held_vulns}")

    # Test reward function on a known case — perfect detection
    print(f"\n  Testing reward function on perfect detection ...")
    perfect_findings = [
        {"vuln_type": v["type"]} for v in
        ALL_CONTRACTS["WormholeStyle"]["ground_truth"]["vulnerabilities"]
    ]
    perfect_reward = compute_contract_reward(
        perfect_findings,
        ALL_CONTRACTS["WormholeStyle"]["ground_truth"],
    )
    print(f"  WormholeStyle (perfect): F1 = {perfect_reward:.3f}")
    assert perfect_reward == 1.0, f"Expected 1.0, got {perfect_reward}"

    # Test reward function on empty findings (worst case)
    empty_reward = compute_contract_reward(
        [],
        ALL_CONTRACTS["WormholeStyle"]["ground_truth"],
    )
    print(f"  WormholeStyle (empty):   F1 = {empty_reward:.3f}")
    assert empty_reward == 0.0, f"Expected 0.0, got {empty_reward}"

    # Test with false positives only
    fp_only = compute_contract_reward(
        [{"vuln_type": "fake_vuln_1"}, {"vuln_type": "fake_vuln_2"}],
        ALL_CONTRACTS["WormholeStyle"]["ground_truth"],
    )
    print(f"  WormholeStyle (FP only): F1 = {fp_only:.3f}")
    assert fp_only == 0.0, f"Expected 0.0, got {fp_only}"

    print(f"\n  GATE 4: PASS — reward function is deterministic, ground-truth-based, no self-assessment")
    print("=" * 60)
