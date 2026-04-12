"""
Agent v2 + Plan-Execute-Critique wrapper.

Wraps agent_v2_bridge.analyze_with_agent_v2 in a three-stage reasoning
pipeline (Plan -> Execute -> Critique) adapted from MultiMind-AI's Thinking
Pipeline (used under author-direct learning grant 2026-04-11).

Hypothesis: the critique stage improves precision without sacrificing recall,
lifting F1 above the 48.0% baseline recorded 2026-04-09.

Usage:
    cd ai-security && USE_BIFROST=1 python agents/agent_v2_bridge_critique.py

Author-grant provenance: JitseLambrichts granted Annunaki full learning rights
to MultiMind-AI on 2026-04-11. Internal use only. See
`~/Annunaki/Agent Vault/research/repos/MultiMind-AI.md` for details.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.agent_v2_bridge import (
    AgentV2Finding,
    BRIDGE_SYSTEM_PROMPT,
    analyze_with_agent_v2,
)


# -- Prompts ----------------------------------------------------------------

PLAN_SYSTEM_PROMPT = """You are the expert audit planning stage in a cross-chain bridge security pipeline.
Your task: analyze the provided bridge contract and produce a prioritized audit plan before any vulnerability is reported.

VULNERABILITY TAXONOMY (the same 10 categories the Execute stage will check):

1. MESSAGE VALIDATION — initialize access control, zero-root acceptance, cross-chain message auth
2. SIGNATURE VERIFICATION — verifier address source, ecrecover malleability, duplicate signature threshold
3. INPUT VALIDATION — zero-value deposits, address(0) checks, amount bounds
4. ARBITRARY CALLS — user-supplied address+calldata, approval drain, delegatecall injection
5. ORACLE MANIPULATION — AMM spot reserves, flash-loan price composition
6. ACCESS CONTROL — admin function protection, timelock presence, emergency bypass
7. REENTRANCY — external-call-before-state, cross-function reentrancy, missing guards
8. REPLAY / CHAIN ID — chain_id in signed messages, cross-chain replay, nonce usage
9. TOKEN HANDLING — transfer return checks, fee-on-transfer, force-send ETH
10. DOS / GAS — unbounded loops, gas griefing, out-of-gas DoS

Instructions:
1. SURFACE SCAN: Read the contract and identify which of the 10 categories are even possible given the contract's surface (e.g., no signature functions -> skip category 2; no external calls -> skip category 4).
2. PRIORITY RANKING: For the categories that ARE possible, rank them by likelihood-of-finding based on code patterns (e.g., presence of delegatecall -> category 4 high priority).
3. PER-CATEGORY CHECKLIST: For each high-priority category, list 2-3 specific checks the execute stage should run. Name the functions/variables to inspect.
4. DECOY AWARENESS: Note any code patterns that look suspicious but are likely safe (well-known library calls, standard OpenZeppelin patterns). This is what the Execute stage will use to avoid false positives.
5. CONFIDENCE THRESHOLD: State explicitly — only findings with specific function-level evidence should be reported. Speculative findings should be omitted.
6. DO NOT report vulnerabilities. Focus entirely on the audit strategy. The Execute stage will do the reporting.

Output format: plain text, no JSON. Structure:
  ACTIVE CATEGORIES: <list>
  PRIORITIES: <ranked list with reason>
  CHECKLIST: <per-category specific checks>
  DECOYS: <safe patterns to ignore>"""


CRITIQUE_SYSTEM_PROMPT = """You are the expert critique and revision stage in a cross-chain bridge audit pipeline.
Your task: rigorously audit the draft findings list against the audit plan and the bridge vulnerability taxonomy.

Instructions:
1. DIFFERENTIAL REVIEW: For each finding in the draft, verify (a) the vuln_type is in the approved taxonomy, (b) the location field names a real function or state variable in the contract, (c) the description cites specific code behavior, not general concerns.
2. PLAN CHECK: Confirm each finding maps to a category the plan marked ACTIVE. Remove findings in categories the plan marked as not applicable.
3. DECOY REJECTION: Remove findings that match patterns the plan flagged as DECOYS (false-positive-prone safe patterns).
4. CONFIDENCE RECALIBRATION: For findings with confidence >= 0.8, the description must cite specific function-level evidence. Downgrade to 0.6 any finding that lacks such evidence. Remove findings below 0.5.
5. CONSERVATIVE OUTPUT: When in doubt, remove the finding. This stage is a precision filter — the Execute stage already maximized recall.
6. OUTPUT FORMAT: Output ONLY a JSON array in the same schema as the draft (vuln_type, severity, location, description, confidence). Use one of the EXACT vuln_type strings from the taxonomy. No preamble, no markdown, no explanation of changes.

If the draft is empty or invalid, output an empty array: []"""


# -- Bifrost client helper --------------------------------------------------

def _get_client_and_model():
    """Return (client, model_name) tuple. Bifrost-only — fails loud if USE_BIFROST != 1."""
    if os.environ.get("USE_BIFROST") != "1":
        raise RuntimeError(
            "agent_v2_bridge_critique requires USE_BIFROST=1. "
            "Anthropic API credits are depleted; all runs must route through Bifrost."
        )
    from openai import OpenAI
    client = OpenAI(
        base_url=os.environ.get("BIFROST_URL", "http://localhost:8090/v1"),
        api_key=os.environ.get("BIFROST_KEY", "sk-bf-dev-interactive"),
    )
    model = os.environ.get("BRIDGE_MODEL", "anthropic/claude-sonnet-4-20250514")
    return client, model


def _bifrost_chat(system: str, user: str, max_tokens: int = 4096) -> str:
    """Single Bifrost chat call. Returns the string content."""
    client, model = _get_client_and_model()
    response = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return response.choices[0].message.content.strip()


# -- Stage 1: Plan ----------------------------------------------------------

def _run_plan(source_code: str, contract_name: str) -> str:
    """Produce an audit plan for the contract. Returns plan text.
    Falls back to empty string on failure — the execute stage will
    degrade to baseline behavior."""
    user_message = (
        f"Bridge contract to audit. Contract name: {contract_name}\n\n"
        f"```solidity\n{source_code}\n```\n\n"
        "Produce the audit plan following the instructions."
    )
    try:
        plan = _bifrost_chat(PLAN_SYSTEM_PROMPT, user_message, max_tokens=2048)
        return plan
    except Exception as exc:
        print(f"  [plan stage failed: {exc}] falling back to baseline behavior")
        return ""


# -- Stage 2: Execute (reuse existing analyzer) ------------------------------

def _run_execute(
    source_code: str, contract_name: str, plan: str
) -> list[AgentV2Finding]:
    """Run the existing Agent v2 analyzer with the plan prepended to the contract.
    The plan is visible to the execute stage but the system prompt is unchanged."""
    if plan:
        augmented_source = (
            f"/* AUDIT PLAN (from prior stage — use this to focus the audit):\n"
            f"{plan}\n"
            f"*/\n\n"
            f"{source_code}"
        )
    else:
        augmented_source = source_code
    return analyze_with_agent_v2(augmented_source, contract_name)


# -- Stage 3: Critique ------------------------------------------------------

def _findings_to_json(findings: list[AgentV2Finding]) -> str:
    """Serialize findings to the same JSON format the baseline outputs."""
    return json.dumps(
        [
            {
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "location": f.location,
                "description": f.description,
                "confidence": f.confidence,
            }
            for f in findings
        ],
        indent=2,
    )


def _parse_findings_json(text: str) -> Optional[list[AgentV2Finding]]:
    """Parse the critique stage output. Returns None on parse failure."""
    # Strip markdown fences (borrowed pattern from agent_v2_bridge.py)
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    try:
        results = json.loads(text)
        if isinstance(results, dict) and "vulnerabilities" in results:
            results = results["vulnerabilities"]
    except json.JSONDecodeError:
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if not match:
            return None
        try:
            results = json.loads(match.group())
        except json.JSONDecodeError:
            return None

    if not isinstance(results, list):
        return None

    findings = []
    for r in results:
        if not isinstance(r, dict):
            continue
        findings.append(
            AgentV2Finding(
                vuln_type=r.get("vuln_type", "unknown"),
                severity=r.get("severity", "medium"),
                location=r.get("location", "unknown"),
                description=r.get("description", ""),
                exploit_scenario=r.get("exploit_scenario", ""),
                confidence=r.get("confidence", 0.5),
            )
        )
    return findings


def _run_critique(
    source_code: str,
    contract_name: str,
    plan: str,
    draft: list[AgentV2Finding],
) -> list[AgentV2Finding]:
    """Audit the draft findings against the plan. Returns revised findings.
    Falls back to the draft on failure — the critique can never make things worse."""
    draft_json = _findings_to_json(draft)
    user_message = (
        f"Bridge contract. Contract name: {contract_name}\n\n"
        f"```solidity\n{source_code}\n```\n\n"
        f"Audit plan (from stage 1):\n{plan or 'No plan was generated.'}\n\n"
        f"Draft findings (from stage 2):\n{draft_json}\n\n"
        "Apply the critique and output the corrected findings JSON array."
    )
    try:
        output = _bifrost_chat(CRITIQUE_SYSTEM_PROMPT, user_message, max_tokens=4096)
    except Exception as exc:
        print(f"  [critique stage failed: {exc}] returning draft unchanged")
        return draft

    parsed = _parse_findings_json(output)
    if parsed is None:
        print(f"  [critique output unparseable for {contract_name}] returning draft")
        return draft
    return parsed


# -- Public API (drop-in replacement for analyze_with_agent_v2) --------------

def analyze_with_agent_v2_critique(
    source_code: str, contract_name: str = "Unknown"
) -> list[AgentV2Finding]:
    """Plan -> Execute -> Critique wrapper around analyze_with_agent_v2.
    Interface-compatible with the baseline — use as a drop-in in benchmark_v2_runner."""
    plan = _run_plan(source_code, contract_name)
    draft = _run_execute(source_code, contract_name, plan)
    final = _run_critique(source_code, contract_name, plan, draft)
    return final


# -- Benchmark runner --------------------------------------------------------

def run_critique_benchmark():
    """Head-to-head: baseline Agent v2 vs Plan-Execute-Critique wrapper."""
    from benchmarks.bridge_contracts_v2 import ALL_CONTRACTS  # noqa: F401
    from agents.benchmark_v2_runner import run_benchmark

    if os.environ.get("USE_BIFROST") != "1":
        print("This ablation requires USE_BIFROST=1. API credits are depleted.")
        print("Run: USE_BIFROST=1 python agents/agent_v2_bridge_critique.py")
        return

    print("=" * 70)
    print("AGENT v2 BASELINE vs PLAN-EXECUTE-CRITIQUE — Head-to-Head")
    print("=" * 70)

    # Baseline
    print("\n--- Agent v2 baseline (single prompt) ---")
    baseline_metrics = run_benchmark(
        lambda src: analyze_with_agent_v2(src),
        verbose=False,
    )

    # Treatment
    print("\n--- Agent v2 + Plan-Execute-Critique ---")
    critique_metrics = run_benchmark(
        lambda src: analyze_with_agent_v2_critique(src),
        verbose=True,
    )

    print("\n" + "=" * 70)
    print("COMPARISON")
    print("=" * 70)
    print(f"{'Metric':<20} {'Baseline':>12} {'+ Critique':>14} {'Delta':>10}")
    print("-" * 58)
    for key, label in [("precision", "Precision"), ("recall", "Recall"), ("f1", "F1")]:
        b = baseline_metrics[key]
        t = critique_metrics[key]
        delta = t - b
        sign = "+" if delta >= 0 else ""
        print(f"{label:<20} {b:>11.1%} {t:>13.1%} {sign}{delta:>9.1%}")

    delta_f1 = critique_metrics["f1"] - baseline_metrics["f1"]
    print("\n" + "=" * 70)
    if delta_f1 >= 0.05:
        print(f"RESULT: POSITIVE (DF1 = +{delta_f1:.1%}) — promote critique to other analyzers")
    elif delta_f1 > 0:
        print(f"RESULT: NEUTRAL (DF1 = +{delta_f1:.1%}) — within noise; file as negative result")
    else:
        print(f"RESULT: NEGATIVE (DF1 = {delta_f1:.1%}) — critique hurts or is neutral")
    print("=" * 70)

    # Persist raw metrics for the portfolio writeup
    results_path = Path(__file__).parent.parent / "results_critique_ablation.json"
    with open(results_path, "w") as f:
        json.dump(
            {
                "date": "2026-04-11",
                "baseline": baseline_metrics,
                "with_critique": critique_metrics,
                "delta_f1": delta_f1,
                "provenance": {
                    "source_pattern": "MultiMind-AI Thinking Pipeline (hard mode)",
                    "pattern_license": "author-direct learning grant 2026-04-11 (JitseLambrichts)",
                    "plan_source": "~/Annunaki/Agent Vault/plans/bridge-bench-plan-execute-critique-ablation.md",
                    "decision": "~/Annunaki/Agent Vault/decisions/Adopt batch 2026-04-11.md",
                },
            },
            f,
            indent=2,
            default=str,
        )
    print(f"\nRaw metrics written to {results_path}")


if __name__ == "__main__":
    run_critique_benchmark()
