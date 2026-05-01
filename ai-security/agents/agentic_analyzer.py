"""
Agentic Bridge Vulnerability Analyzer

Unlike the simple claude_analyzer.py (single prompt → single response),
this agent can iteratively analyze contracts using tool calls:
  1. Read contract source code
  2. Identify interfaces and dependencies
  3. Trace cross-contract call flows
  4. Check for known vulnerability patterns
  5. Reason about compositional attack vectors
  6. Generate structured vulnerability report

This mirrors SCONE-bench's MCP-based agent but focused on detection
rather than exploitation.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python agentic_analyzer.py --contract NomadBridge
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass, field
from anthropic import Anthropic

sys.path.insert(0, str(Path(__file__).parent.parent))
from dashboard.backend.cost_tracker import record_usage as _record_usage

USE_BIFROST = os.environ.get("USE_BIFROST") == "1"


def _anthropic_tools_to_openai(tools):
    """Convert Anthropic tool definitions to OpenAI function calling format."""
    return [{
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t["description"],
            "parameters": t["input_schema"],
        },
    } for t in tools]


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in cross-chain bridge vulnerabilities. You have access to tools for analyzing contracts.

Your task is to find ALL security vulnerabilities in the provided bridge contract. Focus especially on:

1. MESSAGE VALIDATION: Does the bridge properly verify cross-chain messages?
   - Is the message source authenticated?
   - Are proofs correctly validated?
   - Can messages be replayed?

2. SIGNATURE/VERIFICATION: Are cryptographic verifications correct?
   - Is ecrecover used properly?
   - Can the verification be bypassed?
   - Are there trusted external calls that could be spoofed?

3. VALIDATOR GOVERNANCE: Is the validator set secure?
   - What's the multisig threshold? Is it high enough?
   - Can duplicate signatures pass validation?
   - Are validator changes protected by timelock?

4. APPROVAL EXPLOITATION: Can user token approvals be abused?
   - Does the contract make arbitrary external calls with user funds?
   - Can an attacker craft calldata to call transferFrom on approved tokens?

5. ORACLE MANIPULATION: Can prices be manipulated?
   - Are spot prices used instead of TWAPs?
   - Can flash loans manipulate the price feed?

6. INITIALIZATION: Are initialization functions protected?
   - Can initialize() be called by anyone?
   - Can it be called multiple times?
   - What happens if critical values are set to zero?

Think step by step. For each potential vulnerability:
1. Identify the vulnerable code pattern
2. Explain HOW an attacker would exploit it
3. Estimate the SEVERITY (critical/high/medium/low)
4. Suggest a CONCRETE fix

Be thorough but avoid false positives. If you're unsure, say so."""


# Tools the agent can use
TOOLS = [
    {
        "name": "read_source",
        "description": "Read the source code of a Solidity file. Use this to examine contract code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the Solidity file to read",
                }
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "search_code",
        "description": "Search for a pattern in Solidity source files. Use to find specific functions, variables, or patterns.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Text pattern to search for (case-insensitive)",
                },
                "source_code": {
                    "type": "string",
                    "description": "Source code to search in",
                },
            },
            "required": ["pattern", "source_code"],
        },
    },
    {
        "name": "check_vulnerability",
        "description": "Run a specific vulnerability check against source code. Returns structured results.",
        "input_schema": {
            "type": "object",
            "properties": {
                "check_type": {
                    "type": "string",
                    "enum": [
                        "reentrancy",
                        "access_control",
                        "signature_verification",
                        "initialization",
                        "oracle_manipulation",
                        "approval_drain",
                        "validator_threshold",
                        "upgrade_safety",
                    ],
                    "description": "Type of vulnerability check to run",
                },
                "source_code": {
                    "type": "string",
                    "description": "Contract source code to check",
                },
            },
            "required": ["check_type", "source_code"],
        },
    },
    {
        "name": "submit_finding",
        "description": "Submit a confirmed vulnerability finding. Call this for each vulnerability you find.",
        "input_schema": {
            "type": "object",
            "properties": {
                "vuln_type": {
                    "type": "string",
                    "description": "Vulnerability type (e.g., 'reentrancy', 'missing_access_control')",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                },
                "location": {
                    "type": "string",
                    "description": "Function name or code location",
                },
                "description": {
                    "type": "string",
                    "description": "What the vulnerability is",
                },
                "exploit_scenario": {
                    "type": "string",
                    "description": "How an attacker would exploit this",
                },
                "suggested_fix": {
                    "type": "string",
                    "description": "Concrete Solidity fix",
                },
                "confidence": {
                    "type": "number",
                    "description": "Confidence level 0.0-1.0",
                },
            },
            "required": ["vuln_type", "severity", "location", "description", "confidence"],
        },
    },
]


@dataclass
class AgentFinding:
    vuln_type: str
    severity: str
    location: str
    description: str
    exploit_scenario: str = ""
    suggested_fix: str = ""
    confidence: float = 0.5


@dataclass
class AgentAudit:
    contract_name: str
    findings: list[AgentFinding] = field(default_factory=list)
    tool_calls_made: int = 0
    total_tokens: int = 0
    reasoning_trace: list[str] = field(default_factory=list)


def handle_tool_call(tool_name: str, tool_input: dict, source_code: str) -> str:
    """Execute a tool call and return the result."""

    if tool_name == "read_source":
        path = tool_input.get("file_path", "")
        try:
            return Path(path).read_text()[:10000]  # Cap at 10k chars
        except Exception as e:
            return f"Error reading file: {e}"

    elif tool_name == "search_code":
        pattern = tool_input.get("pattern", "")
        code = tool_input.get("source_code", source_code)
        matches = []
        for i, line in enumerate(code.split("\n"), 1):
            if pattern.lower() in line.lower():
                matches.append(f"L{i}: {line.strip()}")
        if matches:
            return "\n".join(matches[:20])
        return f"No matches found for '{pattern}'"

    elif tool_name == "check_vulnerability":
        check_type = tool_input.get("check_type", "")
        code = tool_input.get("source_code", source_code)
        return _run_vuln_check(check_type, code)

    elif tool_name == "submit_finding":
        # This is handled by the caller to collect findings
        return "Finding recorded."

    return f"Unknown tool: {tool_name}"


def _run_vuln_check(check_type: str, source: str) -> str:
    """Run a specific vulnerability check."""
    src_lower = source.lower()

    checks = {
        "reentrancy": lambda: (
            "POTENTIAL REENTRANCY: External calls found before state updates"
            if ".call{value:" in source and "nonReentrant" not in source
            else "No obvious reentrancy pattern found"
        ),
        "access_control": lambda: (
            f"MISSING ACCESS CONTROL on functions: "
            + ", ".join(re.findall(r"function\s+(\w+).*external", source))
            if "external" in source and "onlyOwner" not in source
            else "Access controls appear present"
        ),
        "signature_verification": lambda: (
            "WARNING: Signature parameter found but ecrecover not used"
            if ("bytes" in source and "sig" in src_lower and "ecrecover" not in source)
            else "Signature verification present" if "ecrecover" in source
            else "No signature handling found"
        ),
        "initialization": lambda: (
            "CRITICAL: initialize() has no access control or reinit guard"
            if "initialize" in src_lower and "initializer" not in src_lower
            and "initialized" not in src_lower
            else "Initialization appears protected"
        ),
        "oracle_manipulation": lambda: (
            "CRITICAL: Spot price from AMM reserves (getReserves) — flash loan vulnerable"
            if "getreserves" in src_lower
            else "CRITICAL: slot0 used without TWAP"
            if "slot0" in src_lower and "twap" not in src_lower
            else "No obvious oracle manipulation vector"
        ),
        "approval_drain": lambda: (
            "POTENTIAL: Contract makes external calls that could drain approved tokens"
            if ("transferfrom" in src_lower or "calldatacopy" in src_lower)
            and ("call(" in source or "delegatecall" in source)
            else "No obvious approval drain vector"
        ),
        "validator_threshold": lambda: (
            "WARNING: No supermajority requirement for validator threshold"
            if "threshold" in src_lower and "2/3" not in source
            else "Threshold checks appear adequate"
        ),
        "upgrade_safety": lambda: (
            "WARNING: Upgradeable without timelock"
            if ("upgradeto" in src_lower or "delegatecall" in src_lower)
            and "timelock" not in src_lower
            else "No upgrade mechanism found or timelock present"
        ),
    }

    check_fn = checks.get(check_type)
    if check_fn:
        return check_fn()
    return f"Unknown check type: {check_type}"


def _process_tool_call(tool_name, tool_input, source_code, audit):
    """Process one tool call: either record a finding (submit_finding) or
    dispatch to handle_tool_call. Returns the result string for the LLM.
    Shared between the Bifrost and native-Anthropic loops in run_agent."""
    if tool_name == "submit_finding":
        finding = AgentFinding(
            vuln_type=tool_input.get("vuln_type", "unknown"),
            severity=tool_input.get("severity", "medium"),
            location=tool_input.get("location", "unknown"),
            description=tool_input.get("description", ""),
            exploit_scenario=tool_input.get("exploit_scenario", ""),
            suggested_fix=tool_input.get("suggested_fix", ""),
            confidence=tool_input.get("confidence", 0.5),
        )
        audit.findings.append(finding)
        return f"Finding #{len(audit.findings)} recorded: {finding.vuln_type} ({finding.severity})"
    return handle_tool_call(tool_name, tool_input, source_code)


def run_agent(
    source_code: str,
    contract_name: str,
    max_turns: int = 10,
    model: str = "claude-sonnet-4-20250514",
) -> AgentAudit:
    """
    Run the agentic analyzer on a contract.

    The agent iteratively uses tools to analyze the contract,
    submitting findings as it goes.
    """
    audit = AgentAudit(contract_name=contract_name)

    user_msg = f"""Analyze this bridge contract for security vulnerabilities.
Contract name: {contract_name}

Source code:
```solidity
{source_code[:8000]}
```

Use the available tools to thoroughly analyze this contract:
1. First, search for key patterns (external calls, access control, etc.)
2. Run specific vulnerability checks
3. Submit each finding you discover

Be thorough — check all vulnerability categories."""

    if USE_BIFROST:
        from openai import OpenAI
        client = OpenAI(
            base_url=os.environ.get("BIFROST_URL", "http://localhost:8090/v1"),
            api_key=os.environ.get("BIFROST_KEY", "sk-bf-dev-interactive"),
        )
        bifrost_model = os.environ.get("BRIDGE_MODEL", "anthropic/claude-sonnet-4-20250514")
        oai_tools = _anthropic_tools_to_openai(TOOLS)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ]

        for turn in range(max_turns):
            response = client.chat.completions.create(
                model=bifrost_model,
                max_tokens=4096,
                tools=oai_tools,
                messages=messages,
            )

            usage = response.usage
            if usage:
                audit.total_tokens += (usage.prompt_tokens or 0) + (usage.completion_tokens or 0)
                _record_usage(
                    analyzer="agentic_analyzer",
                    model=bifrost_model,
                    contract=contract_name,
                    prompt_tokens=usage.prompt_tokens or 0,
                    completion_tokens=usage.completion_tokens or 0,
                )

            choice = response.choices[0]
            msg = choice.message

            # Build assistant message for history
            assistant_msg = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                assistant_msg["tool_calls"] = [
                    {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in msg.tool_calls
                ]
            messages.append(assistant_msg)

            if msg.content:
                audit.reasoning_trace.append(msg.content)

            if not msg.tool_calls:
                break

            # Process tool calls
            for tc in msg.tool_calls:
                audit.tool_calls_made += 1
                tool_input = json.loads(tc.function.arguments)
                result = _process_tool_call(tc.function.name, tool_input, source_code, audit)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })
    else:
        client = Anthropic()
        messages = [{"role": "user", "content": user_msg}]

        for turn in range(max_turns):
            response = client.messages.create(
                model=model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )

            audit.total_tokens += response.usage.input_tokens + response.usage.output_tokens
            _record_usage(
                analyzer="agentic_analyzer",
                model=model,
                contract=contract_name,
                prompt_tokens=response.usage.input_tokens,
                completion_tokens=response.usage.output_tokens,
            )

            # Process response
            assistant_content = response.content
            messages.append({"role": "assistant", "content": assistant_content})

            # Check if we're done
            if response.stop_reason == "end_turn":
                for block in assistant_content:
                    if hasattr(block, "text"):
                        audit.reasoning_trace.append(block.text)
                break

            # Process tool calls
            tool_results = []
            for block in assistant_content:
                if block.type == "tool_use":
                    audit.tool_calls_made += 1
                    result = _process_tool_call(block.name, block.input, source_code, audit)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })

                elif hasattr(block, "text"):
                    audit.reasoning_trace.append(block.text)

            if tool_results:
                messages.append({"role": "user", "content": tool_results})

    return audit


def format_audit(audit: AgentAudit) -> str:
    """Format audit results for display."""
    lines = [
        f"{'=' * 60}",
        f"AGENTIC AUDIT: {audit.contract_name}",
        f"{'=' * 60}",
        f"Tool calls: {audit.tool_calls_made}",
        f"Tokens used: {audit.total_tokens:,}",
        f"Findings: {len(audit.findings)}",
        "",
    ]

    for i, f in enumerate(audit.findings, 1):
        lines.extend([
            f"[{i}] {f.vuln_type} ({f.severity.upper()}) — {f.confidence:.0%} confidence",
            f"    Location: {f.location}",
            f"    {f.description}",
        ])
        if f.exploit_scenario:
            lines.append(f"    Exploit: {f.exploit_scenario}")
        if f.suggested_fix:
            lines.append(f"    Fix: {f.suggested_fix}")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    if not os.environ.get("ANTHROPIC_API_KEY") and os.environ.get("USE_BIFROST") != "1":
        print("ANTHROPIC_API_KEY not set (or set USE_BIFROST=1). Showing agent architecture only.")
        print()
        print("Agent tools:")
        for t in TOOLS:
            print(f"  {t['name']}: {t['description'][:60]}...")
        print()
        print("To run:")
        print("  export ANTHROPIC_API_KEY=sk-ant-...")
        print("  python agentic_analyzer.py")
        sys.exit(0)

    # Run against test contracts
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from benchmarks.fixtures.test_contracts import TEST_CONTRACTS

    for name, data in TEST_CONTRACTS.items():
        print(f"\nAnalyzing {name}...")
        audit = run_agent(data["source"], name, max_turns=8)
        print(format_audit(audit))
