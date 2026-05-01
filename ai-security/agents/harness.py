"""
BRIDGE-bench Evaluation Harness

Docker-based harness for evaluating AI agents on bridge vulnerability
detection, patching, and verification. Mirrors SCONE-bench architecture
but focused on defense (Detect + Patch + Verify) rather than offense.

Architecture:
  1. Fork blockchain at pre-exploit block via Foundry's anvil
  2. Agent analyzes contract source code (Detect mode)
  3. Agent proposes Solidity patch (Patch mode)
  4. Harness replays original exploit against patched contract (Verify mode)
  5. Score: did the patch prevent the exploit without breaking functionality?

Requires: Docker, Foundry (forge/cast/anvil)

Setup:
    curl -L https://foundry.paradigm.xyz | bash
    foundryup
"""

import json
import subprocess
import tempfile
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from benchmarks.fixtures.bridge_bench import BRIDGE_EXPLOITS, BridgeExploit, DetectionMode


@dataclass
class DetectResult:
    """Result of vulnerability detection."""
    exploit_name: str
    vulnerabilities_found: list[dict]  # type, severity, location, description
    true_positives: int
    false_positives: int
    false_negatives: int
    detection_time_seconds: float


@dataclass
class PatchResult:
    """Result of patch generation and verification."""
    exploit_name: str
    patch_generated: bool
    patch_code: str
    patch_compiles: bool
    exploit_blocked: bool       # Original exploit fails on patched contract
    functionality_preserved: bool  # Basic operations still work
    verification_details: str


@dataclass
class BenchmarkResult:
    """Combined result for one exploit."""
    exploit: BridgeExploit
    detect: Optional[DetectResult]
    patch: Optional[PatchResult]


def check_foundry_installed() -> bool:
    """Check if Foundry toolchain is available."""
    try:
        result = subprocess.run(["forge", "--version"], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def fetch_contract_source(address: str, chain: str = "mainnet") -> Optional[str]:
    """Fetch verified contract source from Etherscan."""
    api_urls = {
        "mainnet": "https://api.etherscan.io/api",
        "bsc": "https://api.bscscan.com/api",
    }
    api_key = os.environ.get("ETHERSCAN_API_KEY", "")
    if not api_key:
        return None

    import requests
    url = api_urls.get(chain, api_urls["mainnet"])
    resp = requests.get(url, params={
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    }, timeout=30)

    data = resp.json()
    if data["status"] == "1" and data["result"]:
        return data["result"][0].get("SourceCode", "")
    return None


def setup_foundry_project(exploit: BridgeExploit, work_dir: Path) -> bool:
    """Initialize a Foundry project with the exploit's contract."""
    try:
        # Init Foundry project
        subprocess.run(
            ["forge", "init", "--no-commit", str(work_dir)],
            capture_output=True, text=True, timeout=30,
        )

        # Copy the PoC from DefiHackLabs
        poc_source = Path("/home/claude/DeFiHackLabs") / exploit.poc_file
        if poc_source.exists():
            dest = work_dir / "test" / poc_source.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            import shutil
            shutil.copy2(poc_source, dest)
            return True

        return False
    except Exception as e:
        print(f"  Error setting up project: {e}")
        return False


def run_detect_mode(
    exploit: BridgeExploit,
    analyzer_fn,  # callable(source_code, name) -> list[dict]
) -> DetectResult:
    """
    Detect mode: Give agent the contract source, measure what vulns it finds.

    analyzer_fn should accept (source_code: str, contract_name: str) and
    return a list of dicts with 'type' and 'severity' keys.
    """
    import time

    # Get source code
    source = None
    if exploit.vulnerable_contract:
        source = fetch_contract_source(exploit.vulnerable_contract, exploit.fork_chain)

    if not source:
        # Fall back to reading from PoC file for contract addresses
        poc_path = Path("/home/claude/DeFiHackLabs") / exploit.poc_file
        if poc_path.exists():
            source = poc_path.read_text()

    if not source:
        return DetectResult(
            exploit_name=exploit.name,
            vulnerabilities_found=[],
            true_positives=0, false_positives=0,
            false_negatives=len(exploit.vuln_details),
            detection_time_seconds=0,
        )

    start = time.time()
    findings = analyzer_fn(source, exploit.name)
    elapsed = time.time() - start

    # Evaluate against ground truth
    gt_types = {v["type"] for v in exploit.vuln_details}
    found_types = {f["type"] if isinstance(f, dict) else f.vuln_type for f in findings}

    # Fuzzy matching
    tp = len(gt_types & found_types)
    fp = len(found_types - gt_types)
    fn = len(gt_types - found_types)

    return DetectResult(
        exploit_name=exploit.name,
        vulnerabilities_found=findings if isinstance(findings[0], dict) else [{"type": f.vuln_type} for f in findings] if findings else [],
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        detection_time_seconds=elapsed,
    )


def run_patch_verify_mode(
    exploit: BridgeExploit,
    patch_fn,  # callable(source_code, vuln_description) -> str (patched source)
    work_dir: Path,
) -> PatchResult:
    """
    Patch + Verify mode:
      1. Agent generates a patched version of the contract
      2. Harness compiles the patch
      3. Harness replays the original exploit against the patch
      4. Score: exploit blocked AND functionality preserved

    Requires Foundry.
    """
    source = None
    if exploit.vulnerable_contract:
        source = fetch_contract_source(exploit.vulnerable_contract, exploit.fork_chain)

    if not source:
        return PatchResult(
            exploit_name=exploit.name,
            patch_generated=False, patch_code="",
            patch_compiles=False, exploit_blocked=False,
            functionality_preserved=False,
            verification_details="Could not fetch contract source",
        )

    # Generate patch
    vuln_desc = "; ".join(v["type"] for v in exploit.vuln_details)
    try:
        patched_source = patch_fn(source, vuln_desc)
    except Exception as e:
        return PatchResult(
            exploit_name=exploit.name,
            patch_generated=False, patch_code=str(e),
            patch_compiles=False, exploit_blocked=False,
            functionality_preserved=False,
            verification_details=f"Patch generation failed: {e}",
        )

    # Write patched source
    patch_file = work_dir / "src" / "Patched.sol"
    patch_file.parent.mkdir(parents=True, exist_ok=True)
    patch_file.write_text(patched_source)

    # Try to compile
    compile_result = subprocess.run(
        ["forge", "build"],
        cwd=work_dir, capture_output=True, text=True, timeout=60,
    )
    compiles = compile_result.returncode == 0

    # TODO: replay exploit against patched contract
    # This requires setting up the full Foundry test with anvil fork
    # For now, just check compilation
    return PatchResult(
        exploit_name=exploit.name,
        patch_generated=True,
        patch_code=patched_source[:500] + "...",
        patch_compiles=compiles,
        exploit_blocked=False,  # TODO: implement exploit replay
        functionality_preserved=False,  # TODO: implement basic function tests
        verification_details="Compilation check only (exploit replay TODO)",
    )


def run_benchmark(
    analyzer_fn=None,
    patch_fn=None,
    exploits=None,
    detect_only=True,
):
    """
    Run the full BRIDGE-bench evaluation.

    Args:
        analyzer_fn: Detection function (source, name) -> findings
        patch_fn: Patch generation function (source, vuln_desc) -> patched_source
        exploits: List of exploits to test (defaults to all LLM-detectable)
        detect_only: Skip patch/verify mode
    """
    if exploits is None:
        exploits = [
            e for e in BRIDGE_EXPLOITS
            if e.detection_mode in (DetectionMode.STATIC_SOURCE, DetectionMode.LLM_REASONING)
        ]

    print(f"BRIDGE-bench: Evaluating on {len(exploits)} exploits")
    print(f"{'=' * 60}")

    results = []
    total_tp, total_fp, total_fn = 0, 0, 0

    for exploit in exploits:
        print(f"\n{exploit.name} (${exploit.loss_usd:,.0f}, {exploit.vuln_class.value})")

        detect = None
        patch = None

        if analyzer_fn:
            detect = run_detect_mode(exploit, analyzer_fn)
            total_tp += detect.true_positives
            total_fp += detect.false_positives
            total_fn += detect.false_negatives
            print(f"  Detect: TP={detect.true_positives} FP={detect.false_positives} FN={detect.false_negatives}")

        if patch_fn and not detect_only and check_foundry_installed():
            with tempfile.TemporaryDirectory() as tmpdir:
                work_dir = Path(tmpdir) / "project"
                if setup_foundry_project(exploit, work_dir):
                    patch = run_patch_verify_mode(exploit, patch_fn, work_dir)
                    print(f"  Patch: compiled={patch.patch_compiles}")

        results.append(BenchmarkResult(exploit=exploit, detect=detect, patch=patch))

    # Summary
    if analyzer_fn:
        p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0

        print(f"\n{'=' * 60}")
        print(f"DETECTION RESULTS: P={p:.0%} R={r:.0%} F1={f1:.0%}")
        print(f"  TP={total_tp} FP={total_fp} FN={total_fn}")

    return results


if __name__ == "__main__":
    print("BRIDGE-bench Harness")
    print(f"Foundry installed: {check_foundry_installed()}")
    print(f"Etherscan API key: {'set' if os.environ.get('ETHERSCAN_API_KEY') else 'not set'}")
    print()

    from benchmarks.fixtures.bridge_bench import get_stats
    stats = get_stats()
    print(f"LLM-detectable exploits: {stats['by_detection'].get('llm_reasoning', {}).get('count', 0) + stats['by_detection'].get('static_source', {}).get('count', 0)}")
    print(f"LLM-detectable losses: ${stats['llm_detectable_loss']:,.0f}")
    print()
    print("To run with static analyzer:")
    print("  from agents.static_analyzer_v2 import analyze_static")
    print("  run_benchmark(analyzer_fn=lambda src, name: analyze_static(src))")
