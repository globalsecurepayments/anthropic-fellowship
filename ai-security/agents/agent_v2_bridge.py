"""
Agent v2: Bridge-Specific Vulnerability Detection

Upgrades over v1 (agentic_analyzer.py):
  - Bridge-specific system prompt with vulnerability taxonomy
  - Structured output format matching our ground truth labels
  - Chain-of-thought reasoning focused on bridge patterns
  - Explicit checks for each vulnerability class in our taxonomy

This agent targets the bridge-specific vulnerabilities that both
our static analyzer (41.6% F1) and Slither (11.1% F1) miss:
  - Message validation flaws (Nomad, Poly Network)
  - Approval drain via arbitrary calldata (LiFi, Socket)
  - Flash loan oracle composition
  - Signature malleability
  - Cross-chain replay attacks

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    cd ai-security && python agents/agent_v2_bridge.py
"""

import json
import sys
import os
from pathlib import Path
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent.parent))

from dashboard.backend.cost_tracker import record_usage as _record_usage

BRIDGE_SYSTEM_PROMPT = """You are an expert cross-chain bridge security auditor. You specialize in bridge-specific vulnerabilities that static analysis tools miss.

VULNERABILITY TAXONOMY — check each category systematically:

1. MESSAGE VALIDATION
   - Can initialize() be called by anyone? Can it be called multiple times?
   - If a root/hash is set to 0x00, does the default mapping value bypass checks?
   - Are cross-chain messages properly authenticated?

2. SIGNATURE VERIFICATION
   - Is the verification contract address hardcoded or user-supplied?
   - Is ecrecover used? Are v/r/s values validated against malleability?
   - Can duplicate signatures pass the threshold check?

3. INPUT VALIDATION
   - Can deposit functions be called with msg.value == 0 but still credit the deposit?
   - Are address(0) checks present where needed?

4. ARBITRARY CALLS
   - Can the contract make external calls with user-supplied address AND calldata?
   - Can an attacker craft calldata that calls transferFrom on tokens approved to the contract?
   - Is delegatecall used with a user-supplied target address?

5. ORACLE MANIPULATION
   - Does getPrice() use AMM spot reserves (getReserves/slot0)?
   - Can a flash loan manipulate the price within a single transaction?

6. ACCESS CONTROL
   - Are admin functions (updateValidators, setRelayer, upgrade) protected?
   - Is there a timelock on sensitive operations?
   - Can emergency functions bypass the timelock?

7. REENTRANCY
   - Are external calls made before state updates?
   - Is there a reentrancy guard?
   - Can cross-function reentrancy occur?

8. REPLAY / CHAIN ID
   - Is chain_id included in signed messages?
   - Can a valid message on chain A be replayed on chain B?
   - Are nonces used to prevent replay?

9. TOKEN HANDLING
   - Are ERC20 transfer/transferFrom return values checked?
   - Does the contract handle fee-on-transfer tokens correctly?
   - Can selfdestruct force-send ETH to break accounting?

10. DOS / GAS
    - Are there unbounded loops over user-controlled arrays?
    - Can an attacker push many elements to cause out-of-gas?

For EACH vulnerability found, output a JSON object. You MUST use one of these EXACT vuln_type strings:

  untrusted_external_call, reentrancy, unprotected_initializer, reinitializable,
  zero_root_acceptance, missing_signature_verification, missing_proof_link,
  low_validator_threshold, duplicate_signature_acceptance, no_rate_limiting,
  unprotected_admin_function, no_withdrawal_delay, spot_price_oracle,
  flash_loan_exploitable, arbitrary_calldata, approval_drain,
  unprotected_upgrade, delegatecall_injection, signature_malleability,
  unchecked_transfer_return, cross_chain_replay, missing_nonce,
  unbounded_loop_dos, forced_eth_reception, front_running,
  missing_event_emission, fee_on_transfer_mismatch, zero_value_deposit,
  timelock_bypass, centralization_risk, input_validation_missing,
  double_spend, arbitrary_execution, keeper_overwrite

Example output:
[
  {"vuln_type": "unprotected_initializer", "severity": "critical", "location": "initialize", "description": "Anyone can call initialize() — no access control", "confidence": 0.95},
  {"vuln_type": "missing_signature_verification", "severity": "critical", "location": "update", "description": "Signature parameter accepted but never verified with ecrecover", "confidence": 0.9}
]

Output ONLY a JSON array. No preamble, no markdown fences, no explanation.
Be thorough but ONLY report vulnerabilities you are confident about (>0.6).
Focus on BRIDGE-SPECIFIC vulnerabilities that static tools miss."""


@dataclass
class AgentV2Finding:
    vuln_type: str
    severity: str
    location: str
    description: str
    exploit_scenario: str = ""
    confidence: float = 0.5


def analyze_with_agent_v2(source_code: str, contract_name: str = "Unknown") -> list[AgentV2Finding]:
    """
    Analyze a contract using the bridge-specific agent v2.
    Returns findings in a format compatible with benchmark_v2_runner.
    """
    use_bifrost = os.environ.get("USE_BIFROST") == "1"
    model = os.environ.get("BRIDGE_MODEL", "anthropic/claude-sonnet-4-20250514")

    if use_bifrost:
        from openai import OpenAI
        client = OpenAI(
            base_url=os.environ.get("BIFROST_URL", "http://localhost:8090/v1"),
            api_key=os.environ.get("BIFROST_KEY", "sk-bf-dev-interactive"),
        )
        response = client.chat.completions.create(
            model=model,
            max_tokens=4096,
            messages=[
                {"role": "system", "content": BRIDGE_SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze this bridge contract for vulnerabilities. Contract: {contract_name}\n\n{source_code}"},
            ],
        )
        text = response.choices[0].message.content.strip()
        usage = getattr(response, "usage", None)
        if usage is not None:
            _record_usage(
                analyzer="agent_v2_bridge",
                model=model,
                contract=contract_name,
                prompt_tokens=usage.prompt_tokens or 0,
                completion_tokens=usage.completion_tokens or 0,
            )
    else:
        try:
            from anthropic import Anthropic
        except ImportError:
            print("anthropic package not installed")
            return []

        client = Anthropic()
        response = client.messages.create(
            model=model.replace("anthropic/", ""),
            max_tokens=4096,
            system=BRIDGE_SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": f"Analyze this bridge contract for vulnerabilities. Contract: {contract_name}\n\n{source_code}",
            }],
        )
        text = response.content[0].text.strip()
        usage = getattr(response, "usage", None)
        if usage is not None:
            _record_usage(
                analyzer="agent_v2_bridge",
                model=model,
                contract=contract_name,
                prompt_tokens=getattr(usage, "input_tokens", 0),
                completion_tokens=getattr(usage, "output_tokens", 0),
            )

    # Strip markdown fences if present
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
        # Try to extract JSON array from the response
        import re
        match = re.search(r'\[.*\]', text, re.DOTALL)
        if match:
            try:
                results = json.loads(match.group())
            except json.JSONDecodeError:
                print(f"  Failed to parse response for {contract_name}")
                return []
        else:
            print(f"  No JSON found in response for {contract_name}")
            return []

    findings = []
    for r in results:
        findings.append(AgentV2Finding(
            vuln_type=r.get("vuln_type", "unknown"),
            severity=r.get("severity", "medium"),
            location=r.get("location", "unknown"),
            description=r.get("description", ""),
            exploit_scenario=r.get("exploit_scenario", ""),
            confidence=r.get("confidence", 0.5),
        ))

    return findings


def run_agent_v2_benchmark():
    """Run agent v2 against all 20 contracts and compare."""
    from benchmarks.bridge_contracts_v2 import ALL_CONTRACTS
    from agents.benchmark_v2_runner import run_benchmark
    from agents.static_analyzer_v2 import analyze_static

    if not os.environ.get("ANTHROPIC_API_KEY") and os.environ.get("USE_BIFROST") != "1":
        print("ANTHROPIC_API_KEY not set (or set USE_BIFROST=1).")
        print("Agent v2 architecture:")
        print(f"  System prompt: {len(BRIDGE_SYSTEM_PROMPT)} chars")
        print(f"  Taxonomy: 10 vulnerability categories")
        print(f"  Output: structured JSON matching ground truth format")
        print()
        print("To run: export ANTHROPIC_API_KEY=sk-ant-... && python agents/agent_v2_bridge.py")
        return

    print("=" * 70)
    print("AGENT v2 vs STATIC ANALYZER — Head-to-Head")
    print("=" * 70)

    # Static baseline
    print("\n--- Static Analyzer v2 ---")
    static_metrics = run_benchmark(analyze_static, verbose=False)

    # Agent v2
    print("\n--- Agent v2 (Claude) ---")
    agent_metrics = run_benchmark(
        lambda src: analyze_with_agent_v2(src),
        verbose=True,
    )

    print("\n" + "=" * 70)
    print("COMPARISON")
    print("=" * 70)
    print(f"{'Metric':<20} {'Static v2':>12} {'Agent v2':>12}")
    print("-" * 46)
    print(f"{'Precision':<20} {static_metrics['precision']:>11.1%} {agent_metrics['precision']:>11.1%}")
    print(f"{'Recall':<20} {static_metrics['recall']:>11.1%} {agent_metrics['recall']:>11.1%}")
    print(f"{'F1':<20} {static_metrics['f1']:>11.1%} {agent_metrics['f1']:>11.1%}")


if __name__ == "__main__":
    run_agent_v2_benchmark()
