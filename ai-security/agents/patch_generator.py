"""
Bridge Vulnerability Patch Generator

Given a vulnerable contract and detected vulnerabilities, generates
concrete Solidity patches. The novel defense contribution:

  1. DETECT: find the vulnerability (agentic_analyzer.py)
  2. PATCH: generate a fix (this file)
  3. VERIFY: replay the original exploit against the patch (verify below)

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python patch_generator.py --contract NomadStyle
"""

import json
import os
from pathlib import Path
from anthropic import Anthropic


PATCH_SYSTEM_PROMPT = """You are an expert Solidity smart contract developer specializing in bridge security.

Given a vulnerable contract and a description of its vulnerabilities, generate a PATCHED version of the contract that fixes all identified issues.

Rules:
1. Keep the contract's interface identical (same function signatures)
2. Fix ONLY the identified vulnerabilities — don't change unrelated logic
3. Use well-known security patterns:
   - OpenZeppelin's ReentrancyGuard for reentrancy
   - Initializable pattern for initialization
   - ECDSA.recover for signature verification
   - Access control modifiers
   - Rate limiting with time windows
4. Add comments marking each fix with // FIX: [vulnerability name]
5. The patched contract must compile with Solidity ^0.8.0

Output ONLY the patched Solidity code, nothing else."""


def generate_patch(
    source_code: str,
    vulnerabilities: list[dict],
    contract_name: str = "Contract",
    model: str = "claude-sonnet-4-20250514",
) -> str:
    """
    Generate a patched version of a vulnerable contract.

    Args:
        source_code: Original vulnerable Solidity source
        vulnerabilities: List of dicts with 'type', 'description', 'location'
        contract_name: Name for logging
        model: Claude model to use

    Returns:
        Patched Solidity source code
    """
    client = Anthropic()

    vuln_descriptions = "\n".join(
        f"- [{v.get('severity', 'high').upper()}] {v['type']} in {v.get('location', 'unknown')}: "
        f"{v.get('description', '')}"
        for v in vulnerabilities
    )

    response = client.messages.create(
        model=model,
        max_tokens=8192,
        system=PATCH_SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"""Fix the following vulnerable bridge contract.

Contract: {contract_name}

Vulnerabilities to fix:
{vuln_descriptions}

Original source:
```solidity
{source_code}
```

Generate the complete patched contract.""",
        }],
    )

    patched = response.content[0].text

    # Strip markdown fences
    if "```solidity" in patched:
        patched = patched.split("```solidity")[1].split("```")[0]
    elif "```" in patched:
        patched = patched.split("```")[1].split("```")[0]

    return patched.strip()


def verify_patch_compiles(patched_source: str, work_dir: Path) -> tuple[bool, str]:
    """
    Verify that the patched contract compiles with forge.

    Returns (success, error_message)
    """
    import subprocess
    import tempfile

    src_dir = work_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)

    # Write patched source
    (src_dir / "Patched.sol").write_text(patched_source)

    # Write minimal foundry.toml if not exists
    toml_path = work_dir / "foundry.toml"
    if not toml_path.exists():
        toml_path.write_text(
            '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\n'
            "solc = \"0.8.20\"\n"
        )

    try:
        result = subprocess.run(
            ["forge", "build"],
            cwd=work_dir,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            return True, ""
        return False, result.stderr[:500]
    except FileNotFoundError:
        return False, "Foundry not installed (run: curl -L https://foundry.paradigm.xyz | bash)"
    except subprocess.TimeoutExpired:
        return False, "Compilation timed out"


def verify_exploit_blocked(
    patched_source: str,
    exploit_poc: str,
    fork_chain: str,
    fork_block: int,
    work_dir: Path,
) -> tuple[bool, str]:
    """
    Verify that the original exploit FAILS against the patched contract.

    This is the key verification: if the exploit still works on the
    patched contract, the patch is insufficient.

    Returns (exploit_blocked, details)
    """
    import subprocess

    # Write files
    (work_dir / "src" / "Patched.sol").write_text(patched_source)
    (work_dir / "test" / "Exploit.t.sol").write_text(exploit_poc)

    rpc_url = os.environ.get("ETH_RPC_URL", "")
    if not rpc_url:
        return False, "ETH_RPC_URL not set — cannot fork blockchain for verification"

    try:
        result = subprocess.run(
            [
                "forge", "test",
                "--match-test", "testExploit",
                "--fork-url", rpc_url,
                "--fork-block-number", str(fork_block),
                "-vvv",
            ],
            cwd=work_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )

        # If the test FAILS, the exploit was blocked (good!)
        if result.returncode != 0:
            return True, "Exploit reverted on patched contract (GOOD)"
        return False, "Exploit still succeeds on patched contract (BAD)"

    except FileNotFoundError:
        return False, "Foundry not installed"
    except subprocess.TimeoutExpired:
        return False, "Verification timed out"


def run_detect_patch_verify(
    source_code: str,
    contract_name: str,
    ground_truth_vulns: list[dict],
    poc_file: str = "",
    fork_chain: str = "mainnet",
    fork_block: int = 0,
) -> dict:
    """
    Full Detect → Patch → Verify pipeline.

    Returns dict with results for each stage.
    """
    import tempfile

    results = {
        "contract": contract_name,
        "detect": {},
        "patch": {},
        "verify": {},
    }

    # Stage 1: Detect (use ground truth for now, swap with agentic analyzer)
    results["detect"] = {
        "vulnerabilities": ground_truth_vulns,
        "count": len(ground_truth_vulns),
    }

    # Stage 2: Patch
    print(f"  Generating patch for {contract_name}...")
    try:
        patched = generate_patch(source_code, ground_truth_vulns, contract_name)
        results["patch"]["generated"] = True
        results["patch"]["source_preview"] = patched[:200] + "..."
        results["patch"]["source_length"] = len(patched)
    except Exception as e:
        results["patch"]["generated"] = False
        results["patch"]["error"] = str(e)
        return results

    # Stage 3: Verify compilation
    with tempfile.TemporaryDirectory() as tmpdir:
        work_dir = Path(tmpdir)
        compiles, err = verify_patch_compiles(patched, work_dir)
        results["verify"]["compiles"] = compiles
        if not compiles:
            results["verify"]["compile_error"] = err

        # Stage 4: Verify exploit blocked (if we have PoC and RPC)
        if compiles and poc_file and fork_block > 0:
            poc_path = Path("/home/claude/DeFiHackLabs") / poc_file
            if poc_path.exists():
                blocked, details = verify_exploit_blocked(
                    patched, poc_path.read_text(),
                    fork_chain, fork_block, work_dir,
                )
                results["verify"]["exploit_blocked"] = blocked
                results["verify"]["details"] = details

    return results


if __name__ == "__main__":
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY not set.")
        print()
        print("Detect → Patch → Verify Pipeline:")
        print("  1. DETECT: Find vulnerabilities (agentic_analyzer.py)")
        print("  2. PATCH: Generate Solidity fix (this file)")
        print("  3. VERIFY: Replay exploit against patch (forge test)")
        print()
        print("Requirements:")
        print("  - ANTHROPIC_API_KEY for Claude patch generation")
        print("  - Foundry (forge) for compilation verification")
        print("  - ETH_RPC_URL for blockchain forking (verify stage)")
        print()
        print("To run:")
        print("  export ANTHROPIC_API_KEY=sk-ant-...")
        print("  python patch_generator.py")
    else:
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from benchmarks.fixtures.test_contracts import TEST_CONTRACTS

        for name, data in list(TEST_CONTRACTS.items())[:2]:
            print(f"\n{'='*50}")
            print(f"Detect → Patch → Verify: {name}")
            result = run_detect_patch_verify(
                data["source"],
                name,
                data["ground_truth"]["vulnerabilities"],
            )
            print(json.dumps(result, indent=2, default=str))
