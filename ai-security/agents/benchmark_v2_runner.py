"""
BRIDGE-bench v2 Benchmark Runner

Evaluates analyzers against the full 20-contract dataset with proper
precision/recall/F1 scoring and per-contract breakdown.

Usage:
    cd ai-security && python agents/benchmark_v2_runner.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmarks.bridge_contracts_v2 import ALL_CONTRACTS
from agents.static_analyzer_v2 import analyze_static, StaticFinding


# ── Fuzzy matching for vulnerability types ────────────────────────────

VULN_ALIASES = {
    "untrusted_external_call": [
        "untrusted_external_call", "arbitrary_external_call", "external_call",
        "fake_verifier", "unvalidated_verifier", "arbitrary_calls",
    ],
    "reentrancy": [
        "reentrancy", "reentrant", "re-entrancy", "missing_reentrancy_guard",
    ],
    "unprotected_initializer": [
        "unprotected_initializer", "no_access_control_init", "missing_init_guard",
        "initialization", "access_control_initializ",
    ],
    "reinitializable": [
        "reinitializable", "multiple_initialization", "re_initialization",
    ],
    "zero_root_acceptance": [
        "zero_root_acceptance", "zero_root", "default_value_exploit",
        "message_validation_zero", "zero_hash",
    ],
    "missing_signature_verification": [
        "missing_signature_verification", "unused_signature_parameter",
        "no_signature_check", "signature_bypass", "signature_verification",
    ],
    "missing_proof_link": [
        "missing_proof_link", "no_proof_verification", "process_without_proof",
        "message_validation_proof",
    ],
    "low_validator_threshold": [
        "low_validator_threshold", "insufficient_threshold",
        "validator_threshold", "threshold",
    ],
    "duplicate_signature_acceptance": [
        "duplicate_signature_acceptance", "duplicate_signer",
        "duplicate_signature", "signature_replay",
    ],
    "no_rate_limiting": [
        "no_rate_limiting", "rate_limit", "withdrawal_limit",
        "no_withdrawal_limit",
    ],
    "unprotected_admin_function": [
        "unprotected_admin_function", "missing_access_control",
        "no_access_control", "unprotected_state_change",
        "access_control",
    ],
    "no_withdrawal_delay": [
        "no_withdrawal_delay", "no_timelock", "missing_timelock",
        "timelock",
    ],
    "spot_price_oracle": [
        "spot_price_oracle", "oracle_manipulation", "price_manipulation",
        "flash_loan_oracle",
    ],
    "flash_loan_exploitable": [
        "flash_loan_exploitable", "flash_loan", "flash_loan_attack",
    ],
    "arbitrary_calldata": [
        "arbitrary_calldata", "arbitrary_call", "calldata_injection",
        "arbitrary_external_call", "arbitrary_calls",
    ],
    "approval_drain": [
        "approval_drain", "approval_exploitation", "infinite_approval",
        "transferfrom_drain",
    ],
    "unprotected_upgrade": [
        "unprotected_upgrade", "upgrade_risk", "delegatecall_upgrade",
    ],
    "delegatecall_injection": [
        "delegatecall_injection", "delegatecall_to_user_address",
        "delegatecall_to_user_input",
    ],
    "signature_malleability": [
        "signature_malleability", "malleable_signature", "ecrecover_malleability",
    ],
    "unchecked_return": [
        "unchecked_return", "unchecked_transfer", "unchecked_erc20",
        "unchecked_transfer_return", "token_handling",
    ],
    "cross_chain_replay": [
        "cross_chain_replay", "replay_attack", "missing_chain_id",
        "replay_chain_id", "replay",
    ],
    "missing_nonce": [
        "missing_nonce", "replay_nonce", "no_nonce",
    ],
    "unbounded_loop": [
        "unbounded_loop", "dos_loop", "gas_bomb", "unbounded_iteration",
        "unbounded_loop_dos", "dos_gas", "dos",
    ],
    "selfdestruct_balance": [
        "selfdestruct_balance", "force_eth", "unexpected_balance",
        "forced_eth_reception",
    ],
    "front_running": [
        "front_running", "frontrun", "mev", "sandwich",
    ],
    "missing_events": [
        "missing_events", "no_event", "missing_emit",
        "missing_event_emission",
    ],
    "fee_on_transfer": [
        "fee_on_transfer", "deflationary_token", "transfer_fee",
        "fee_on_transfer_mismatch",
    ],
    "zero_value_deposit": [
        "zero_value_deposit", "zero_value", "empty_deposit",
        "input_validation_zero", "input_validation_deposit",
    ],
    "timelock_bypass": [
        "timelock_bypass", "emergency_bypass", "emergency_withdrawal",
    ],
    "input_validation_missing": [
        "input_validation_missing", "input_validation", "missing_input_validation",
    ],
    "message_validation": [
        "message_validation", "cross_chain_message", "message_verification",
    ],
    "centralization_risk": [
        "centralization_risk", "centralization", "single_admin",
    ],
    "unprotected_push": [
        "unprotected_push", "unbounded_push", "array_push",
    ],
    "unbounded_fee": [
        "unbounded_fee", "fee_manipulation", "unrestricted_fee",
    ],
    "double_spend": [
        "double_spend", "double_withdrawal",
    ],
    "keeper_overwrite": [
        "keeper_overwrite", "keeper_key_overwrite",
    ],
    "arbitrary_execution": [
        "arbitrary_execution", "arbitrary_contract_call",
        "unrestricted_cross_chain_call",
    ],
}


def fuzzy_match(found_type: str, gt_type: str) -> bool:
    """Check if a found vulnerability type matches a ground truth type."""
    f = found_type.lower().replace("-", "_").replace(" ", "_")
    g = gt_type.lower().replace("-", "_").replace(" ", "_")

    if f == g:
        return True

    # Check alias groups
    for canonical, aliases in VULN_ALIASES.items():
        f_match = f == canonical or any(a in f for a in aliases)
        g_match = g == canonical or any(a in g for a in aliases)
        if f_match and g_match:
            return True

    # Substring match (last resort)
    if len(f) > 4 and len(g) > 4:
        if f in g or g in f:
            return True

    return False


def evaluate_contract(contract_name, source, ground_truth, analyzer_fn):
    """Evaluate an analyzer against one contract."""
    import inspect
    sig = inspect.signature(analyzer_fn)
    if "contract_name" in sig.parameters:
        findings = analyzer_fn(source, contract_name=contract_name)
    elif len(sig.parameters) >= 2:
        findings = analyzer_fn(source, contract_name)
    else:
        findings = analyzer_fn(source)

    gt_vulns = ground_truth["vulnerabilities"]
    gt_types = [v["type"] for v in gt_vulns]

    # Match findings to ground truth
    matched_gt = set()
    matched_findings = set()

    for i, finding in enumerate(findings):
        f_type = finding.vuln_type if hasattr(finding, "vuln_type") else finding["type"]
        for j, gt_type in enumerate(gt_types):
            if j not in matched_gt and fuzzy_match(f_type, gt_type):
                matched_gt.add(j)
                matched_findings.add(i)
                break

    tp = len(matched_gt)
    fp = len(findings) - len(matched_findings)
    fn = len(gt_vulns) - len(matched_gt)

    return {
        "contract": contract_name,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "findings": [f.vuln_type if hasattr(f, "vuln_type") else f["type"] for f in findings],
        "gt": gt_types,
        "matched": [gt_types[j] for j in matched_gt],
        "missed": [gt_types[j] for j in range(len(gt_types)) if j not in matched_gt],
        "false_pos": [
            (findings[i].vuln_type if hasattr(findings[i], "vuln_type") else findings[i]["type"])
            for i in range(len(findings)) if i not in matched_findings
        ],
    }


def run_benchmark(analyzer_fn, dataset=None, verbose=True):
    """Run full benchmark against all contracts."""
    if dataset is None:
        dataset = ALL_CONTRACTS

    results = []
    total_tp, total_fp, total_fn = 0, 0, 0

    if verbose:
        print("BRIDGE-bench v2 — Static Analyzer Evaluation")
        print(f"Dataset: {len(dataset)} contracts")
        print("=" * 70)

    for name, data in dataset.items():
        result = evaluate_contract(name, data["source"], data["ground_truth"], analyzer_fn)
        results.append(result)

        total_tp += result["tp"]
        total_fp += result["fp"]
        total_fn += result["fn"]

        if verbose:
            gt_count = len(result["gt"])
            found_count = len(result["findings"])
            status = "PERFECT" if result["tp"] == gt_count and result["fp"] == 0 else ""
            if result["tp"] == 0 and gt_count > 0:
                status = "MISS"

            print(f"\n{name:<25} GT={gt_count}  Found={found_count}  "
                  f"TP={result['tp']} FP={result['fp']} FN={result['fn']}  {status}")

            if result["matched"]:
                print(f"  Matched:    {', '.join(result['matched'])}")
            if result["missed"]:
                print(f"  Missed:     {', '.join(result['missed'])}")
            if result["false_pos"]:
                print(f"  False pos:  {', '.join(result['false_pos'])}")

    # Compute aggregate metrics
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    if verbose:
        print("\n" + "=" * 70)
        print("AGGREGATE RESULTS")
        print("=" * 70)
        print(f"  Contracts evaluated: {len(results)}")
        print(f"  Total ground truth:  {total_tp + total_fn}")
        print(f"  True positives:      {total_tp}")
        print(f"  False positives:     {total_fp}")
        print(f"  False negatives:     {total_fn}")
        print(f"  Precision:           {precision:.1%}")
        print(f"  Recall:              {recall:.1%}")
        print(f"  F1 Score:            {f1:.1%}")

        # Breakdown by severity
        print(f"\n{'─' * 70}")
        print("DETECTION GAPS (most commonly missed vulnerability types):")
        miss_counts = {}
        for r in results:
            for m in r["missed"]:
                miss_counts[m] = miss_counts.get(m, 0) + 1
        for vuln, count in sorted(miss_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {vuln:<40} missed {count}x")

        print(f"\nFALSE POSITIVE PATTERNS:")
        fp_counts = {}
        for r in results:
            for fp in r["false_pos"]:
                fp_counts[fp] = fp_counts.get(fp, 0) + 1
        for vuln, count in sorted(fp_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {vuln:<40} false positive {count}x")

    return {
        "results": results,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": total_tp,
        "fp": total_fp,
        "fn": total_fn,
    }


if __name__ == "__main__":
    print()
    metrics = run_benchmark(analyze_static)
    print(f"\n{'=' * 70}")
    print(f"STATIC ANALYZER BASELINE: F1 = {metrics['f1']:.1%}")
    print(f"  This is what an LLM agent needs to beat.")
    print(f"{'=' * 70}")
