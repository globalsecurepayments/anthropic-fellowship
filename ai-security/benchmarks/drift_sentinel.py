"""
Drift Sentinel — continuous monitoring of the labeled vulnerability dataset.

Implements Stummer Pattern P3 (Drift Sentinel, arXiv 2604.01661v1 §4.3):
detects when the ground-truth dataset changes between benchmark runs so
silent drift doesn't invalidate cross-run F1 comparisons.

How it works:
  1. Serializes ALL_CONTRACTS deterministically (sorted keys, stable JSON)
  2. Computes SHA256 of the serialization
  3. Compares against a stored baseline hash in drift_baseline.json
  4. If mismatch: prints which contracts changed and how many rules differ

Upgrade path (future, not implemented):
  - Semantic fingerprints (embedding-based drift detection) for catching
    label re-phrasings that don't change the JSON but change the meaning.
    Would require a vector store and embedding model — overkill for the
    current 22-contract dataset but worth it at 100+ contracts.

Usage:
    from benchmarks.drift_sentinel import check_drift, establish_baseline

    # First run: establishes baseline
    establish_baseline()

    # Subsequent runs: checks for drift
    result = check_drift()  # Returns DriftResult

Framework: Stummer §4.3 Drift Sentinel (arXiv 2604.01661v1)
Decision: ~/Annunaki/Agent Vault/decisions/Adopt Stummer ontology-aware design patterns 2026-04-18.md
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmarks.bridge_contracts_v2 import ALL_CONTRACTS


BASELINE_PATH = Path(__file__).parent / "drift_baseline.json"


# ---------------------------------------------------------------------------
# Deterministic serialization
# ---------------------------------------------------------------------------

def _serialize_contracts(contracts: dict[str, Any]) -> str:
    """Deterministic JSON serialization of the contract dataset.
    Sorted keys at all levels for stable hashing."""
    return json.dumps(contracts, sort_keys=True, ensure_ascii=True)


def _hash_contracts(contracts: dict[str, Any]) -> str:
    """SHA256 of the deterministic serialization."""
    serialized = _serialize_contracts(contracts)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _per_contract_hashes(contracts: dict[str, Any]) -> dict[str, str]:
    """SHA256 per contract for diff-level drift detection."""
    return {
        name: hashlib.sha256(
            json.dumps(data, sort_keys=True, ensure_ascii=True).encode("utf-8")
        ).hexdigest()
        for name, data in sorted(contracts.items())
    }


# ---------------------------------------------------------------------------
# Drift result
# ---------------------------------------------------------------------------

@dataclass
class DriftResult:
    """Result of a drift check."""
    drifted: bool
    baseline_hash: str
    current_hash: str
    changed_contracts: list[str] = field(default_factory=list)
    added_contracts: list[str] = field(default_factory=list)
    removed_contracts: list[str] = field(default_factory=list)
    message: str = ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def establish_baseline(
    contracts: dict[str, Any] | None = None,
    path: Path | None = None,
) -> str:
    """Write the current dataset hash as the drift baseline.
    Returns the baseline hash."""
    if contracts is None:
        contracts = ALL_CONTRACTS
    if path is None:
        path = BASELINE_PATH

    overall_hash = _hash_contracts(contracts)
    per_contract = _per_contract_hashes(contracts)

    baseline = {
        "hash": overall_hash,
        "contract_count": len(contracts),
        "per_contract": per_contract,
    }

    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)

    return overall_hash


def check_drift(
    contracts: dict[str, Any] | None = None,
    path: Path | None = None,
) -> DriftResult:
    """Check the current dataset against the stored baseline.

    If no baseline exists, establishes one and returns a non-drifted result.
    """
    if contracts is None:
        contracts = ALL_CONTRACTS
    if path is None:
        path = BASELINE_PATH

    current_hash = _hash_contracts(contracts)
    current_per = _per_contract_hashes(contracts)

    # No baseline yet — establish it
    if not path.exists():
        establish_baseline(contracts, path)
        result = DriftResult(
            drifted=False,
            baseline_hash=current_hash,
            current_hash=current_hash,
            message=f"Drift baseline established ({len(contracts)} contracts, hash {current_hash[:12]}...)",
        )
        print(f"  Drift baseline established ({len(contracts)} contracts)")
        return result

    # Load baseline
    with open(path) as f:
        baseline = json.load(f)

    baseline_hash = baseline["hash"]
    baseline_per = baseline.get("per_contract", {})

    # Quick check — overall hash
    if current_hash == baseline_hash:
        result = DriftResult(
            drifted=False,
            baseline_hash=baseline_hash,
            current_hash=current_hash,
            message="Drift sentinel: OK",
        )
        print("  Drift sentinel: OK")
        return result

    # Drift detected — compute diff
    changed = []
    added = []
    removed = []

    all_names = set(list(current_per.keys()) + list(baseline_per.keys()))
    for name in sorted(all_names):
        cur = current_per.get(name)
        base = baseline_per.get(name)

        if cur and not base:
            added.append(name)
        elif base and not cur:
            removed.append(name)
        elif cur != base:
            changed.append(name)

    # Build message
    parts = ["DRIFT DETECTED:"]
    if changed:
        parts.append(f"  Changed: {', '.join(changed)}")
    if added:
        parts.append(f"  Added: {', '.join(added)}")
    if removed:
        parts.append(f"  Removed: {', '.join(removed)}")

    # Count ground truth rule differences for changed contracts
    for name in changed:
        cur_gt = contracts.get(name, {}).get("ground_truth", {}).get("vulnerabilities", [])
        # Can't compare to baseline rules directly (we only stored hashes),
        # but we can report current rule count
        parts.append(f"    {name}: {len(cur_gt)} ground truth rules (hash changed)")

    msg = "\n".join(parts)
    print(f"  WARNING: {msg}")

    return DriftResult(
        drifted=True,
        baseline_hash=baseline_hash,
        current_hash=current_hash,
        changed_contracts=changed,
        added_contracts=added,
        removed_contracts=removed,
        message=msg,
    )


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import copy
    import tempfile

    print("=" * 60)
    print("Drift Sentinel — acceptance tests")
    print("=" * 60)

    # Use a temp path so we don't clobber the real baseline
    tmp = Path(tempfile.mkdtemp()) / "drift_baseline.json"

    # Test 1: First run establishes baseline
    print("\n--- Test 1: First run (no baseline) ---")
    r1 = check_drift(path=tmp)
    assert not r1.drifted, f"Expected no drift, got: {r1.message}"
    assert "baseline established" in r1.message.lower(), f"Expected 'baseline established', got: {r1.message}"
    assert tmp.exists(), "Baseline file should exist"
    print("  PASS: First run writes baseline and prints 'Drift baseline established'")

    # Test 2: Second run with unchanged data
    print("\n--- Test 2: Unchanged data ---")
    r2 = check_drift(path=tmp)
    assert not r2.drifted, f"Expected no drift, got: {r2.message}"
    assert "OK" in r2.message, f"Expected 'OK', got: {r2.message}"
    print("  PASS: Second run prints 'Drift sentinel: OK'")

    # Test 3: Modify one ground_truth entry, detect drift
    print("\n--- Test 3: Modified contract ---")
    modified = copy.deepcopy(dict(ALL_CONTRACTS))
    first_name = list(modified.keys())[0]
    modified[first_name]["ground_truth"]["vulnerabilities"].append({
        "type": "test_drift_vuln",
        "severity": "low",
        "location": "test",
        "description": "Injected for drift test",
    })
    r3 = check_drift(modified, path=tmp)
    assert r3.drifted, f"Expected drift, got: {r3.message}"
    assert first_name in r3.changed_contracts, f"Expected {first_name} in changed"
    assert "DRIFT DETECTED" in r3.message
    print(f"  PASS: Detects '{first_name}' changed")

    # Test 4: Added contract
    print("\n--- Test 4: Added contract ---")
    modified["NewTestContract"] = {"source": "test", "ground_truth": {"vulnerabilities": []}}
    r4 = check_drift(modified, path=tmp)
    assert r4.drifted
    assert "NewTestContract" in r4.added_contracts
    print("  PASS: Detects added contract")

    # Cleanup
    tmp.unlink(missing_ok=True)

    print(f"\n  ALL 4 ACCEPTANCE TESTS PASS")
    print("=" * 60)
