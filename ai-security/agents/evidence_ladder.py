"""
Evidence Ladder — typed confidence progression for BRIDGE-bench findings.

A 6-rung evidence ladder where each rung requires more expensive verification
than the rung below. Findings are tagged with their current evidence level;
downstream gates (reporting, adversarial verification) key on rung position.

Framework: ~/Annunaki/Agent Vault/research/frameworks/Evidence Ladder — Framework.md
Source pattern: clearwing (Lazarus AI, MIT) findings/types.py
Decision: ~/Annunaki/Agent Vault/decisions/Verdict batch 2026-04-17b.md

CRITICAL DESIGN CONSTRAINT (from Gotchas 2026-04-11):
  This module GRADES findings — it does NOT discard them.
  Filtering on evidence level is done at the REPORTING layer, not here.
  The reporting gate retains all findings in raw output; it only excludes
  below-threshold findings from the REPORTED results used for scoring.
  This is structurally different from the critique ablation's "when in doubt,
  remove" approach that caused ΔF1 = −38.9pp recall collapse.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

# ---------------------------------------------------------------------------
# Evidence level type + ordering
# ---------------------------------------------------------------------------

EvidenceLevel = Literal[
    "suspicion",
    "static_corroboration",
    "crash_reproduced",
    "root_cause_explained",
    "exploit_demonstrated",
    "patch_validated",
]

EVIDENCE_LEVELS: list[str] = [
    "suspicion",
    "static_corroboration",
    "crash_reproduced",
    "root_cause_explained",
    "exploit_demonstrated",
    "patch_validated",
]


def evidence_at_or_above(level: str, threshold: str) -> bool:
    """Check if level is at or above the threshold in the ladder."""
    try:
        return EVIDENCE_LEVELS.index(level) >= EVIDENCE_LEVELS.index(threshold)
    except ValueError:
        return False


def bump_evidence(current: str, proposed: str) -> str:
    """Monotonically advance evidence level — never retreat."""
    try:
        if EVIDENCE_LEVELS.index(proposed) > EVIDENCE_LEVELS.index(current):
            return proposed
    except ValueError:
        pass
    return current


# ---------------------------------------------------------------------------
# Reporting gate config
# ---------------------------------------------------------------------------

# Default: report findings at static_corroboration or above.
# Findings below this threshold are retained in raw output but excluded
# from reported results used for scoring.
# Override via MIN_EVIDENCE_LEVEL env var.
DEFAULT_MIN_EVIDENCE_LEVEL = "static_corroboration"

MIN_EVIDENCE_LEVEL = os.environ.get(
    "MIN_EVIDENCE_LEVEL", DEFAULT_MIN_EVIDENCE_LEVEL
)


def passes_reporting_gate(level: str) -> bool:
    """Check if a finding's evidence level meets the reporting threshold."""
    return evidence_at_or_above(level, MIN_EVIDENCE_LEVEL)


# ---------------------------------------------------------------------------
# Evidence tagging — tag findings based on what evidence actually exists
# ---------------------------------------------------------------------------

def tag_evidence_level(
    finding_vuln_type: str,
    finding_description: str,
    finding_confidence: float,
    static_corroborated: bool = False,
    has_foundry_test: bool = False,
) -> str:
    """Determine the evidence level for a finding based on available evidence.

    This is a MEASUREMENT function — it observes what evidence exists,
    it does not generate or require new evidence.

    Args:
        finding_vuln_type: The vulnerability type string
        finding_description: The LLM's description of the finding
        finding_confidence: The LLM's self-reported confidence (0-1)
        static_corroborated: True if the static analyzer also found this type
        has_foundry_test: True if a Foundry test exists that reproduces this

    Returns:
        The appropriate evidence level string.
    """
    # Rung 3: crash_reproduced — Foundry test confirms the exploit
    if has_foundry_test:
        return "crash_reproduced"

    # Rung 2: static_corroboration — static analyzer independently agrees
    if static_corroborated:
        return "static_corroboration"

    # Rung 1: suspicion — LLM-only finding, no external corroboration
    return "suspicion"


def cross_check_static(
    agent_findings: list[dict],
    static_findings: list,
    source_code: str,
) -> list[dict]:
    """Cross-check agent findings against static analyzer to determine
    which findings have static corroboration.

    Uses the same fuzzy_match logic as benchmark_v2_runner to determine
    if two vulnerability types refer to the same issue.

    Args:
        agent_findings: list of finding dicts with 'vuln_type' key
        static_findings: list of StaticFinding objects from analyze_static()
        source_code: the contract source (unused, reserved for future)

    Returns:
        The same agent_findings list, each augmented with 'evidence_level' key.
    """
    from agents.benchmark_v2_runner import fuzzy_match

    static_types = set()
    for sf in static_findings:
        st = getattr(sf, "vuln_type", None) or sf.get("vuln_type", "")
        if st:
            static_types.add(st.lower().replace("-", "_").replace(" ", "_"))

    for finding in agent_findings:
        ft = (
            finding.get("vuln_type", "")
            or finding.get("type", "")
            or getattr(finding, "vuln_type", "")
        )

        # Check if any static finding matches this agent finding
        corroborated = any(
            fuzzy_match(ft, st) for st in static_types
        )

        confidence = finding.get("confidence", 0.5)
        if isinstance(confidence, str):
            try:
                confidence = float(confidence)
            except (ValueError, TypeError):
                confidence = 0.5

        finding["evidence_level"] = tag_evidence_level(
            finding_vuln_type=ft,
            finding_description=finding.get("description", ""),
            finding_confidence=confidence,
            static_corroborated=corroborated,
        )

    return agent_findings


def apply_reporting_gate(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split findings into reported (meets threshold) and below-threshold.

    BOTH lists are returned. The below-threshold findings are NOT discarded —
    they are retained for raw output and debugging. Only the reported list
    is used for scoring.

    Returns:
        (reported_findings, below_threshold_findings)
    """
    reported = []
    below = []
    for f in findings:
        level = f.get("evidence_level", "suspicion")
        if passes_reporting_gate(level):
            reported.append(f)
        else:
            below.append(f)
    return reported, below


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("Evidence Ladder — smoke test")
    print("=" * 60)

    # Test ordering
    assert evidence_at_or_above("suspicion", "suspicion")
    assert evidence_at_or_above("static_corroboration", "suspicion")
    assert not evidence_at_or_above("suspicion", "static_corroboration")
    assert evidence_at_or_above("crash_reproduced", "static_corroboration")
    print("  Ordering: OK")

    # Test bump
    assert bump_evidence("suspicion", "static_corroboration") == "static_corroboration"
    assert bump_evidence("static_corroboration", "suspicion") == "static_corroboration"
    assert bump_evidence("crash_reproduced", "crash_reproduced") == "crash_reproduced"
    print("  Bump: OK")

    # Test tagging
    assert tag_evidence_level("reentrancy", "test", 0.9) == "suspicion"
    assert tag_evidence_level("reentrancy", "test", 0.9, static_corroborated=True) == "static_corroboration"
    assert tag_evidence_level("reentrancy", "test", 0.9, has_foundry_test=True) == "crash_reproduced"
    print("  Tagging: OK")

    # Test reporting gate
    f1 = {"vuln_type": "x", "evidence_level": "suspicion"}
    f2 = {"vuln_type": "y", "evidence_level": "static_corroboration"}
    f3 = {"vuln_type": "z", "evidence_level": "crash_reproduced"}
    reported, below = apply_reporting_gate([f1, f2, f3])
    assert len(reported) == 2  # f2, f3
    assert len(below) == 1     # f1
    assert below[0]["vuln_type"] == "x"
    print("  Reporting gate: OK")

    # Test cross_check_static
    from dataclasses import dataclass

    @dataclass
    class MockStatic:
        vuln_type: str = "reentrancy"

    agent = [
        {"vuln_type": "reentrancy", "description": "test", "confidence": 0.9},
        {"vuln_type": "front_running", "description": "test", "confidence": 0.7},
    ]
    tagged = cross_check_static(agent, [MockStatic()], "")
    assert tagged[0]["evidence_level"] == "static_corroboration"
    assert tagged[1]["evidence_level"] == "suspicion"
    print("  Cross-check: OK")

    print(f"\n  MIN_EVIDENCE_LEVEL: {MIN_EVIDENCE_LEVEL}")
    print("  ALL TESTS PASS")
    print("=" * 60)
