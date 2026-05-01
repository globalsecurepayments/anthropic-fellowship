"""
Patch Generation and Verification Pipeline

Given a contract and identified vulnerabilities, generates Solidity patches
and verifies them using Foundry compilation.

Pipeline:
  1. Claude generates a patched version of the vulnerable contract
  2. Foundry compiles the patch (syntax + type checking)
  3. (Future) Run exploit tests against the patched contract

This implements the "Defense angle: can agent suggest patches?" task.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    cd ai-security && python agents/patch_verifier.py
"""

import json
import subprocess
import tempfile
import os
import sys
from pathlib import Path
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent))


PATCH_SYSTEM_PROMPT = """You are a Solidity security engineer. Given a vulnerable smart contract and a list of identified vulnerabilities, generate a PATCHED version that fixes all vulnerabilities while preserving the contract's core functionality.

Rules:
1. Output ONLY the complete patched Solidity source code
2. Add comments marking each fix with "// FIX: <description>"
3. Use established patterns: ReentrancyGuard, Ownable, SafeERC20, etc.
4. Do NOT change function signatures (preserve the interface)
5. Do NOT add unnecessary complexity
6. Ensure the patched contract compiles with Solidity ^0.8.20

Common fixes:
- Reentrancy: add nonReentrant modifier, use checks-effects-interactions
- Access control: add onlyOwner or role-based modifiers
- Oracle: use TWAP instead of spot price
- Initialization: add initializer modifier with initialized flag
- Signature: validate v value, check for duplicates, use EIP-712
- Input validation: require(msg.value > 0), require(addr != address(0))
- Unchecked returns: use SafeERC20.safeTransfer

Output the complete patched contract, ready to compile."""


@dataclass
class PatchResult:
    contract_name: str
    original_source: str
    patched_source: str
    compiles: bool
    compile_errors: str
    vulnerabilities_fixed: list[str]


def generate_patch(source_code: str, contract_name: str,
                   vulnerabilities: list[str]) -> str:
    """Generate a patched contract using Claude."""
    try:
        from anthropic import Anthropic
    except ImportError:
        return ""

    client = Anthropic()

    vuln_list = "\n".join(f"  - {v}" for v in vulnerabilities)

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=8192,
        system=PATCH_SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"""Contract: {contract_name}

Vulnerabilities to fix:
{vuln_list}

Original source:
```solidity
{source_code}
```

Generate the patched version.""",
        }],
    )

    text = response.content[0].text.strip()

    # Extract Solidity code from response
    if "```solidity" in text:
        text = text.split("```solidity")[1].split("```")[0]
    elif "```" in text:
        text = text.split("```")[1].split("```")[0]

    return text.strip()


def compile_with_foundry(source_code: str, contract_name: str) -> tuple[bool, str]:
    """Compile a Solidity contract using forge."""
    env = {**os.environ, "PATH": f"/root/.foundry/bin:{os.environ.get('PATH', '')}"}

    with tempfile.TemporaryDirectory() as tmpdir:
        # Minimal Foundry project
        (Path(tmpdir) / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\nsolc = "0.8.20"\n'
        )
        src_dir = Path(tmpdir) / "src"
        src_dir.mkdir()
        (src_dir / f"{contract_name}.sol").write_text(source_code)

        result = subprocess.run(
            ["forge", "build", "--root", tmpdir],
            capture_output=True, text=True, timeout=60,
            env=env,
        )

        if result.returncode == 0:
            return True, ""
        else:
            return False, result.stderr[:500]


def run_patch_pipeline():
    """Run patch generation and verification on test contracts."""
    from benchmarks.fixtures.bridge_contracts_v2 import ALL_CONTRACTS

    # Test on a subset of contracts
    test_contracts = ["NomadStyle", "WormholeStyle", "RoninStyle", "OracleManipulation"]

    has_api_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    has_foundry = True
    try:
        subprocess.run(
            ["forge", "--version"], capture_output=True, timeout=5,
            env={**os.environ, "PATH": f"/root/.foundry/bin:{os.environ.get('PATH', '')}"},
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        has_foundry = False

    print("=" * 70)
    print("PATCH GENERATION + VERIFICATION PIPELINE")
    print("=" * 70)
    print(f"  Foundry available: {has_foundry}")
    print(f"  API key set: {has_api_key}")
    print()

    if not has_api_key:
        print("Running compilation-only test (no patch generation without API key)")
        print()

        # Test that original contracts compile
        results = []
        for name in test_contracts:
            if name not in ALL_CONTRACTS:
                continue
            source = ALL_CONTRACTS[name]["source"]
            compiles, errors = compile_with_foundry(source, name)
            status = "COMPILES" if compiles else "FAILS"
            print(f"  {name:<25} [{status}]")
            if not compiles:
                print(f"    Error: {errors[:200]}")
            results.append({"name": name, "compiles": compiles})

        compiled = sum(1 for r in results if r["compiles"])
        print(f"\n  {compiled}/{len(results)} original contracts compile")
        print()
        print("To run full pipeline with patch generation:")
        print("  export ANTHROPIC_API_KEY=sk-ant-...")
        print("  python agents/patch_verifier.py")
        return results

    # Full pipeline with Claude
    results = []
    for name in test_contracts:
        if name not in ALL_CONTRACTS:
            continue

        data = ALL_CONTRACTS[name]
        source = data["source"]
        vulns = [v["type"] for v in data["ground_truth"]["vulnerabilities"]]

        print(f"\n{'─' * 70}")
        print(f"Contract: {name}")
        print(f"Vulnerabilities: {', '.join(vulns)}")

        # Generate patch
        print(f"  Generating patch...")
        patched = generate_patch(source, name, vulns)

        if not patched:
            print(f"  Failed to generate patch")
            results.append(PatchResult(name, source, "", False, "no patch generated", []))
            continue

        print(f"  Patch generated ({len(patched)} chars)")

        # Compile patch
        compiles, errors = compile_with_foundry(patched, name + "Patched")
        status = "COMPILES" if compiles else "COMPILE ERROR"
        print(f"  Compilation: [{status}]")
        if not compiles:
            print(f"  Error: {errors[:300]}")

        result = PatchResult(name, source, patched, compiles, errors, vulns)
        results.append(result)

    # Summary
    print(f"\n{'=' * 70}")
    print("PATCH PIPELINE RESULTS")
    print(f"{'=' * 70}")
    compiled = sum(1 for r in results if r.compiles)
    print(f"  Patches generated: {len(results)}")
    print(f"  Patches that compile: {compiled}/{len(results)}")
    print(f"  Compilation rate: {compiled/len(results):.0%}" if results else "  N/A")

    return results


if __name__ == "__main__":
    run_patch_pipeline()
