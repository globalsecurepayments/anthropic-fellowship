"""
AI-Powered Smart Contract Vulnerability Analyzer

Uses Claude to perform deep analysis of Solidity source code,
combining static pattern matching with LLM reasoning about
complex vulnerability patterns that static tools miss.

Key insight: Static analyzers (Slither, Mythril) catch known patterns.
LLMs can reason about novel vulnerability compositions — e.g., a flash
loan that manipulates an oracle which then triggers a reentrancy in a
cross-chain message handler. This compositional reasoning is where
AI agents add value over existing tools.
"""

import json
import os
from dataclasses import dataclass, asdict
from anthropic import Anthropic

sys.path.insert(0, str(Path(__file__).parent.parent))
from dashboard.backend.cost_tracker import record_usage as _record_usage

# Bifrost proxy support — route via OpenAI-compatible gateway
BIFROST_URL = os.environ.get("BIFROST_URL", "http://localhost:8090/v1")
BIFROST_KEY = os.environ.get("BIFROST_KEY", "sk-bf-dev-interactive")
USE_BIFROST = os.environ.get("USE_BIFROST", "0") == "1"

def _create_client():
    """Create Anthropic client, optionally routing through Bifrost."""
    if USE_BIFROST:
        try:
            from openai import OpenAI
            return OpenAI(base_url=BIFROST_URL, api_key=BIFROST_KEY), "openai"
        except ImportError:
            raise RuntimeError("pip install openai — required for Bifrost routing")
    return Anthropic(), "anthropic"


SYSTEM_PROMPT = """You are an expert smart contract security auditor specializing in cross-chain bridge vulnerabilities.

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
{
  "vulnerabilities": [
    {
      "type": "string",
      "severity": "critical|high|medium|low|informational",
      "location": "string",
      "description": "string",
      "exploit_scenario": "string",
      "suggested_fix": "string",
      "confidence": 0.0-1.0
    }
  ],
  "overall_risk": "critical|high|medium|low",
  "summary": "string"
}

Be thorough but avoid false positives. If you're unsure, set confidence lower.
Focus especially on cross-chain bridge-specific vulnerabilities."""


@dataclass
class Vulnerability:
    type: str
    severity: str
    location: str
    description: str
    exploit_scenario: str
    suggested_fix: str
    confidence: float


@dataclass
class AuditReport:
    contract_name: str
    vulnerabilities: list[Vulnerability]
    overall_risk: str
    summary: str
    static_findings: list[str]
    ai_findings_raw: dict


# Known vulnerability patterns for static pre-screening
STATIC_PATTERNS = {
    "reentrancy": {
        "indicators": [".call{value:", ".call(", "send(", "transfer("],
        "anti_patterns": ["nonReentrant", "ReentrancyGuard"],
        "check": "external_call_before_state_update",
    },
    "oracle_manipulation": {
        "indicators": ["getPrice", "latestAnswer", "latestRoundData", "slot0", "getReserves", "observe"],
        "anti_patterns": ["TWAP", "timeWeightedAverage"],
        "check": "spot_price_dependency",
    },
    "access_control": {
        "indicators": ["onlyOwner", "require(msg.sender", "tx.origin"],
        "anti_patterns": ["AccessControl", "Ownable"],
        "check": "missing_access_control",
    },
    "bridge_verification": {
        "indicators": ["verifyProof", "validateMessage", "receiveMessage", "processMessage", "relayMessage"],
        "anti_patterns": [],
        "check": "message_validation",
    },
    "upgrade_risk": {
        "indicators": ["upgradeTo", "delegatecall", "Proxy", "implementation"],
        "anti_patterns": ["TimelockController", "timelock"],
        "check": "unprotected_upgrade",
    },
    "initialization": {
        "indicators": ["initialize(", "init(", "constructor"],
        "anti_patterns": ["initializer", "onlyInitializing"],
        "check": "unprotected_initializer",
    },
}


def static_prescreen(source_code: str) -> list[str]:
    """Quick static pattern matching — baseline before AI analysis."""
    findings = []
    source_lower = source_code.lower()

    for vuln_type, patterns in STATIC_PATTERNS.items():
        has_indicator = any(p.lower() in source_lower for p in patterns["indicators"])
        has_protection = any(p.lower() in source_lower for p in patterns["anti_patterns"])

        if has_indicator and not has_protection:
            findings.append(vuln_type)

    return findings


def analyze_with_claude(
    source_code: str,
    contract_name: str = "Unknown",
    static_findings: list[str] | None = None,
) -> AuditReport:
    """
    Deep analysis using Claude. Combines static pre-screening results
    with LLM reasoning for comprehensive vulnerability detection.
    """
    client, mode = _create_client()

    # Build the user prompt with context
    context_parts = [f"Contract name: {contract_name}"]
    if static_findings:
        context_parts.append(
            f"Static analysis flags: {', '.join(static_findings)} "
            f"(investigate these areas carefully)"
        )

    user_prompt = f"""{chr(10).join(context_parts)}

Analyze this Solidity smart contract for security vulnerabilities:

```solidity
{source_code}
```

Provide your analysis as JSON."""

    model = os.environ.get("BRIDGE_MODEL", "anthropic/claude-sonnet-4-20250514")

    if mode == "openai":
        response = client.chat.completions.create(
            model=model,
            max_tokens=4096,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
        response_text = response.choices[0].message.content
        usage = getattr(response, "usage", None)
        if usage is not None:
            _record_usage(
                analyzer="claude_analyzer",
                model=model,
                contract=contract_name,
                prompt_tokens=usage.prompt_tokens or 0,
                completion_tokens=usage.completion_tokens or 0,
            )
    else:
        response = client.messages.create(
            model=model.replace("anthropic/", ""),
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        response_text = response.content[0].text
        usage = getattr(response, "usage", None)
        if usage is not None:
            _record_usage(
                analyzer="claude_analyzer",
                model=model,
                contract=contract_name,
                prompt_tokens=getattr(usage, "input_tokens", 0),
                completion_tokens=getattr(usage, "output_tokens", 0),
            )

    # Strip markdown fences if present
    if "```json" in response_text:
        response_text = response_text.split("```json")[1].split("```")[0]
    elif "```" in response_text:
        response_text = response_text.split("```")[1].split("```")[0]

    result = json.loads(response_text.strip())

    vulns = [
        Vulnerability(
            type=v["type"],
            severity=v["severity"],
            location=v["location"],
            description=v["description"],
            exploit_scenario=v["exploit_scenario"],
            suggested_fix=v["suggested_fix"],
            confidence=v.get("confidence", 0.5),
        )
        for v in result.get("vulnerabilities", [])
    ]

    return AuditReport(
        contract_name=contract_name,
        vulnerabilities=vulns,
        overall_risk=result.get("overall_risk", "unknown"),
        summary=result.get("summary", ""),
        static_findings=static_findings or [],
        ai_findings_raw=result,
    )


def format_report(report: AuditReport) -> str:
    """Format audit report for display."""
    lines = [
        f"{'=' * 60}",
        f"SECURITY AUDIT: {report.contract_name}",
        f"{'=' * 60}",
        f"Overall Risk: {report.overall_risk.upper()}",
        f"Summary: {report.summary}",
        f"",
        f"Static Pre-screen: {', '.join(report.static_findings) or 'none'}",
        f"AI-detected vulnerabilities: {len(report.vulnerabilities)}",
        f"{'─' * 60}",
    ]

    for i, v in enumerate(report.vulnerabilities, 1):
        lines.extend([
            f"",
            f"[{i}] {v.type} ({v.severity.upper()}) — confidence: {v.confidence:.0%}",
            f"    Location: {v.location}",
            f"    {v.description}",
            f"    Exploit: {v.exploit_scenario}",
            f"    Fix: {v.suggested_fix}",
        ])

    lines.append(f"\n{'=' * 60}")
    return "\n".join(lines)


# ─── Test Contracts ─────────────────────────────────────────

VULNERABLE_BRIDGE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleBridge {
    mapping(bytes32 => bool) public processedMessages;
    mapping(address => uint256) public deposits;
    address public relayer;
    address public owner;
    
    constructor(address _relayer) {
        relayer = _relayer;
        owner = msg.sender;
    }
    
    // Users deposit tokens on source chain
    function deposit() external payable {
        require(msg.value > 0, "Must deposit > 0");
        deposits[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    // Relayer processes withdrawal on destination chain
    function processWithdrawal(
        address recipient,
        uint256 amount,
        bytes32 messageHash,
        bytes memory signature
    ) external {
        require(!processedMessages[messageHash], "Already processed");
        
        // BUG: No verification that signature is from a valid relayer
        // BUG: No verification of messageHash contents
        // Anyone can call with arbitrary recipient/amount
        
        processedMessages[messageHash] = true;
        
        // BUG: Reentrancy — state update happens above, but the
        // external call could re-enter via a different messageHash
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(recipient, amount);
    }
    
    // BUG: No timelock on upgrade
    function setRelayer(address _newRelayer) external {
        require(msg.sender == owner, "Not owner");
        relayer = _newRelayer;
    }
    
    // BUG: Owner can drain all funds
    function emergencyWithdraw() external {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
}
"""

NOMAD_STYLE_VULN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract NomadStyleBridge {
    // Merkle root for valid messages
    bytes32 public committedRoot;
    mapping(bytes32 => uint256) public confirmAt;
    uint256 public optimisticTimeout = 30 minutes;
    
    mapping(bytes32 => bool) public messages;
    
    // BUG: During initialization, if committedRoot is set to 0x00,
    // then messages[0x00] maps to 0, and confirmAt[0x00] maps to 0,
    // which means the zero hash is always "confirmed" (block.timestamp > 0)
    
    function initialize(bytes32 _committedRoot) external {
        // BUG: No access control on initialization
        // BUG: Can be called multiple times
        committedRoot = _committedRoot;
        confirmAt[_committedRoot] = 1;  // Immediately confirmed
    }
    
    function update(bytes32 _oldRoot, bytes32 _newRoot, bytes memory _signature) external {
        require(committedRoot == _oldRoot, "Not current root");
        // BUG: No signature verification
        committedRoot = _newRoot;
        confirmAt[_newRoot] = block.timestamp + optimisticTimeout;
    }
    
    function prove(bytes32 _leaf, bytes32[32] calldata _proof, uint256 _index) external {
        bytes32 _calculatedRoot = calculateRoot(_leaf, _proof, _index);
        require(acceptableRoot(_calculatedRoot), "Invalid root");
        messages[_leaf] = true;
    }
    
    function process(bytes32 _messageHash, address _recipient, uint256 _amount) external {
        // BUG: If messages[_messageHash] is false but _messageHash happens
        // to map to an "acceptable" state via the zero-root bug,
        // this check passes
        require(messages[_messageHash], "Not proven");
        messages[_messageHash] = false;
        
        (bool success,) = _recipient.call{value: _amount}("");
        require(success);
    }
    
    function acceptableRoot(bytes32 _root) public view returns (bool) {
        uint256 _confirmAt = confirmAt[_root];
        if (_confirmAt == 0) return false;
        return block.timestamp >= _confirmAt;
    }
    
    function calculateRoot(bytes32 _leaf, bytes32[32] calldata _proof, uint256 _index) 
        internal pure returns (bytes32) 
    {
        bytes32 _current = _leaf;
        for (uint256 i = 0; i < 32; i++) {
            if (_index & (1 << i) == 0) {
                _current = keccak256(abi.encodePacked(_current, _proof[i]));
            } else {
                _current = keccak256(abi.encodePacked(_proof[i], _current));
            }
        }
        return _current;
    }
}
"""


if __name__ == "__main__":
    print("Testing static pre-screen...")
    print()

    for name, code in [("SimpleBridge", VULNERABLE_BRIDGE), ("NomadStyle", NOMAD_STYLE_VULN)]:
        findings = static_prescreen(code)
        print(f"{name}: {findings}")

    print()
    print("Static analysis complete. To run Claude analysis:")
    print("  report = analyze_with_claude(VULNERABLE_BRIDGE, 'SimpleBridge')")
    print("  print(format_report(report))")
    print()
    print("Requires ANTHROPIC_API_KEY environment variable.")
