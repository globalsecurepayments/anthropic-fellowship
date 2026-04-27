"""Pilot DeepEval G-Eval suite for agent_v2_bridge analyzer.

Phase 1 anchor of the DeepEval adoption (Adopt deepeval 2026-04-27).
Wraps the existing single-prompt Agent v2 baseline (29-contract eval, F1 60.3%,
P 46%, R 87.7% — see projects/active/BRIDGE-bench.md) with a G-Eval correctness
metric judged via Bifrost.

This is the *pilot* — three representative contracts, not the full 29 — to
validate the wiring + metric definition before any larger run. Costs ~3 judge
calls per pytest invocation.

Run:
    pytest ai-security/evals/test_agent_v2_geval.py -v

Skips automatically if Bifrost is not reachable at localhost:8090.
"""

from __future__ import annotations

import os
import socket
import pytest

deepeval = pytest.importorskip("deepeval")
from deepeval.metrics import GEval  # noqa: E402
from deepeval.test_case import LLMTestCase, LLMTestCaseParams  # noqa: E402

from evals.judge_factory import make_judge  # noqa: E402


def _bifrost_reachable(host: str = "localhost", port: int = 8090) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _bifrost_reachable(),
    reason="Bifrost not reachable at localhost:8090; judge calls require it.",
)


# Three representative contracts spanning the bridge vulnerability taxonomy:
# RoninStyle (validator governance), LiFiStyle (approval drain), OracleManipulation.
# Inputs are minimal stubs — the goal is wiring validation, not analyzer accuracy.
PILOT_CASES = [
    {
        "name": "RoninStyle_validator_governance",
        "input": "function withdraw(bytes calldata sig) { require(verify(sig)); }",
        "expected_vuln": "validator governance / 5-of-9 multisig compromise pattern",
        "actual_finding": (
            "Single-signer verification path with no quorum check — vulnerable to "
            "validator key compromise (Ronin-class)."
        ),
    },
    {
        "name": "LiFiStyle_approval_drain",
        "input": "function swap(address target, bytes calldata data) { target.call(data); }",
        "expected_vuln": "arbitrary calldata + approval drain (LiFi-class)",
        "actual_finding": (
            "Unvalidated arbitrary call enables ERC20 transferFrom against any prior "
            "approval — approval drain vector."
        ),
    },
    {
        "name": "OracleManipulation_compositional",
        "input": "function liquidate() { uint p = oracle.spot(); ... }",
        "expected_vuln": "spot-price oracle manipulation via flash loan",
        "actual_finding": (
            "Single-block spot price read with no TWAP — flash-loan-manipulable in "
            "the same transaction."
        ),
    },
]


@pytest.fixture(scope="module")
def correctness_metric() -> GEval:
    return GEval(
        name="BridgeVulnerabilityCorrectness",
        criteria=(
            "Determine whether the actual finding correctly identifies the "
            "expected bridge vulnerability class. Reward findings that name the "
            "underlying mechanism (validator quorum, calldata validation, oracle "
            "freshness, etc.) — not just the symptom."
        ),
        evaluation_params=[
            LLMTestCaseParams.INPUT,
            LLMTestCaseParams.ACTUAL_OUTPUT,
            LLMTestCaseParams.EXPECTED_OUTPUT,
        ],
        model=make_judge(),
        threshold=0.6,
    )


@pytest.mark.parametrize("case", PILOT_CASES, ids=lambda c: c["name"])
def test_agent_v2_finding_correctness(case, correctness_metric: GEval) -> None:
    test_case = LLMTestCase(
        input=case["input"],
        actual_output=case["actual_finding"],
        expected_output=case["expected_vuln"],
    )
    correctness_metric.measure(test_case)
    assert correctness_metric.score is not None, "Judge returned no score"
    assert correctness_metric.score >= correctness_metric.threshold, (
        f"G-Eval score {correctness_metric.score:.2f} below threshold "
        f"{correctness_metric.threshold} — reason: {correctness_metric.reason}"
    )
