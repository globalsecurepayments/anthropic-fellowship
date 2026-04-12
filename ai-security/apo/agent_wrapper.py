"""
BRIDGE-bench APO agent wrapper.

Wraps the claude_analyzer system prompt in an agent-lightning LitAgent
(via @rollout decorator) so APO can optimize it against the ground-truth
F1 reward signal.

The @rollout decorator:
  1. Receives the current PromptTemplate from NamedResources
  2. Captures LLM call spans via the active tracer
  3. Returns the reward as a float

APO then:
  1. Reads the spans + reward from the LightningStore
  2. Computes textual gradients ("what should change in this prompt?")
  3. Applies edits to produce candidate prompts
  4. Evaluates candidates and keeps the best (beam search)

Decision: ~/Annunaki/Agent Vault/decisions/Adopt agent-lightning APO experiment.md
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, TypedDict, List

from openai import OpenAI

sys.path.insert(0, str(Path(__file__).parent.parent))

from agentlightning.litagent import rollout
from agentlightning.reward import emit_reward
from agentlightning.types import PromptTemplate

from apo.run_config import BIFROST_URL, BIFROST_KEY, BIFROST_MODEL
from apo.reward import compute_contract_reward


# ---------------------------------------------------------------------------
# Task type
# ---------------------------------------------------------------------------

class BridgeBenchTask(TypedDict):
    contract_name: str
    source: str
    ground_truth: dict


# ---------------------------------------------------------------------------
# Response parser (reused from agent_v2_bridge_critique.py pattern)
# ---------------------------------------------------------------------------

def _parse_findings(text: str) -> list[dict[str, Any]]:
    """Parse vulnerability findings from LLM response text.
    Handles: direct JSON, markdown-fenced JSON, embedded array extraction."""
    if not text:
        return []

    # Strip markdown fences
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0]
    elif text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    # Try direct parse
    try:
        result = json.loads(text.strip())
        if isinstance(result, dict):
            return result.get("vulnerabilities", [])
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass

    # Try extracting JSON array
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # Try extracting JSON object
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group())
            if isinstance(result, dict):
                return result.get("vulnerabilities", [])
        except json.JSONDecodeError:
            pass

    return []


# ---------------------------------------------------------------------------
# Seed prompt template
# ---------------------------------------------------------------------------

# Seed prompt — sourced from claude_analyzer.py SYSTEM_PROMPT (inlined to
# avoid importing claude_analyzer which has a broken sys import).
SEED_SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in cross-chain bridge vulnerabilities.

You analyze Solidity source code for security vulnerabilities. You have deep expertise in:
1. Reentrancy attacks (including cross-function and cross-contract)
2. Oracle manipulation and flash loan attacks
3. Bridge message verification flaws
4. Access control weaknesses
5. Integer overflow/underflow
6. Front-running and MEV extraction
7. Proxy/upgrade mechanism abuse
8. Cross-chain message forgery
9. Merkle proof verification bugs
10. Default value initialization errors

For each vulnerability found, provide:
- Type (from the categories above)
- Severity (critical/high/medium/low/informational)
- Location (function name and approximate line)
- Description of the vulnerability
- How an attacker would exploit it
- Suggested fix

Respond ONLY in valid JSON with this structure:
{{
  "vulnerabilities": [
    {{
      "type": "string",
      "severity": "critical|high|medium|low|informational",
      "location": "string",
      "description": "string",
      "exploit_scenario": "string",
      "suggested_fix": "string",
      "confidence": 0.0-1.0
    }}
  ],
  "overall_risk": "critical|high|medium|low",
  "summary": "string"
}}

Be thorough but avoid false positives. If you're unsure, set confidence lower.
Focus especially on cross-chain bridge-specific vulnerabilities."""


def seed_prompt_template() -> PromptTemplate:
    """The baseline system prompt that APO will optimize."""
    return PromptTemplate(
        template=SEED_SYSTEM_PROMPT,
        engine="f-string",
    )


# ---------------------------------------------------------------------------
# LitAgent (via @rollout decorator)
# ---------------------------------------------------------------------------

@rollout
def bridge_bench_analyzer(task: BridgeBenchTask, prompt_template: PromptTemplate) -> float:
    """Analyze a bridge contract and return F1 reward against ground truth.

    This function is decorated with @rollout, which:
    - Wraps it into a LitAgent[BridgeBenchTask]
    - Extracts prompt_template from NamedResources by parameter name
    - Captures OpenAI SDK spans via the active OtelTracer
    - Returns the float as the rollout reward

    APO optimizes the prompt_template text to maximize this reward.
    """
    # The system prompt is the PromptTemplate that APO optimizes.
    # No format variables — APO edits the text directly.
    system_prompt = prompt_template.template

    # Build user message (same format as claude_analyzer.analyze_with_claude)
    user_prompt = (
        f"Contract name: {task['contract_name']}\n\n"
        f"Analyze this Solidity smart contract for security vulnerabilities:\n\n"
        f"```solidity\n{task['source']}\n```\n\n"
        f"Provide your analysis as JSON."
    )

    # Call Bifrost — the OtelTracer captures this span automatically
    client = OpenAI(base_url=BIFROST_URL, api_key=BIFROST_KEY)
    try:
        response = client.chat.completions.create(
            model=BIFROST_MODEL,
            max_tokens=4096,
            temperature=0.0,  # Deterministic for reward stability
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
    except Exception as e:
        # LLM call failed — return 0 reward (worst case)
        print(f"  [LLM error on {task['contract_name']}]: {e}")
        return 0.0

    # Parse response
    response_text = ""
    if response.choices:
        response_text = response.choices[0].message.content or ""
    elif hasattr(response, "extra_fields"):
        # Bifrost proxy response — try raw content extraction
        response_text = str(response)

    findings = _parse_findings(response_text)

    # Compute deterministic F1 reward against ground truth
    reward = compute_contract_reward(findings, task["ground_truth"])

    # Explicitly emit reward as a span — required when using LitAgentRunner
    # outside the Trainer (the Trainer wraps float returns into spans; the
    # runner does not).
    emit_reward(reward)

    return reward


# ---------------------------------------------------------------------------
# Dataset builders
# ---------------------------------------------------------------------------

def build_train_dataset() -> list[BridgeBenchTask]:
    """Build training dataset from TRAIN_CONTRACTS split."""
    from apo.reward import TRAIN_CONTRACTS

    return [
        BridgeBenchTask(
            contract_name=name,
            source=data["source"],
            ground_truth=data["ground_truth"],
        )
        for name, data in TRAIN_CONTRACTS.items()
    ]


def build_val_dataset() -> list[BridgeBenchTask]:
    """Build validation dataset from HELD_OUT_CONTRACTS split."""
    from apo.reward import HELD_OUT_CONTRACTS

    return [
        BridgeBenchTask(
            contract_name=name,
            source=data["source"],
            ground_truth=data["ground_truth"],
        )
        for name, data in HELD_OUT_CONTRACTS.items()
    ]
