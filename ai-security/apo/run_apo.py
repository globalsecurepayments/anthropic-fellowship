"""
BRIDGE-bench APO experiment — main entry point.

Bypasses agent-lightning's Trainer (broken on macOS due to multiprocessing
pickle errors in ClientServerExecutionStrategy) and runs the APO algorithm
+ LitAgentRunner as concurrent async tasks in a single event loop.

Pattern: examples/apo/apo_custom_algorithm.py from agent-lightning.

Usage:
    cd ai-security && python -m apo.run_apo

Decision: ~/Annunaki/Agent Vault/decisions/Adopt agent-lightning APO experiment.md
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import cast

sys.path.insert(0, str(Path(__file__).parent.parent))

from openai import AsyncOpenAI

import agentlightning as agl
from agentlightning.adapter import TraceToMessages
from agentlightning.algorithm.apo import APO
from agentlightning.runner import LitAgentRunner
from agentlightning.types import Dataset

from apo.run_config import (
    BIFROST_URL,
    BIFROST_KEY,
    BIFROST_MODEL,
    APO_GRADIENT_MODEL,
    APO_EDIT_MODEL,
    validate_bifrost_routing,
    get_tracer,
    get_store,
    RESULTS_DIR,
)
from apo.agent_wrapper import (
    BridgeBenchTask,
    bridge_bench_analyzer,
    build_train_dataset,
    build_val_dataset,
    seed_prompt_template,
)
from apo.regression_gate import run_regression_gate


# ---------------------------------------------------------------------------
# APO logging
# ---------------------------------------------------------------------------

def setup_apo_logger(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"apo-{datetime.now().strftime('%Y%m%d-%H%M')}.log"
    handler = logging.FileHandler(log_path)
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] (%(name)s) %(message)s"
    ))
    logging.getLogger("agentlightning.algorithm.apo").addHandler(handler)
    print(f"  APO logs: {log_path}")


# ---------------------------------------------------------------------------
# Async runner task — processes rollouts enqueued by APO
# ---------------------------------------------------------------------------

async def run_runner(store: agl.LightningStore, tracer: agl.Tracer) -> None:
    """Background task: dequeue rollouts from store, execute agent, emit spans.
    Runs until cancelled by the main task."""
    runner = LitAgentRunner[BridgeBenchTask](tracer=tracer)
    with runner.run_context(agent=bridge_bench_analyzer, store=store):
        await runner.iter()  # Loops forever, processing rollouts as they arrive


# ---------------------------------------------------------------------------
# Main async entrypoint
# ---------------------------------------------------------------------------

async def async_main() -> None:
    agl.setup_logging()

    print("=" * 70)
    print("BRIDGE-bench APO Experiment")
    print("=" * 70)

    # ── Pre-flight ─────────────────────────────────────────────
    print("\n--- Pre-flight gate validation ---")
    validate_bifrost_routing()
    print("  Gate 1 (Bifrost routing):  PASS")

    tracer = get_tracer()
    print(f"  Gate 2 (Tracer):           {type(tracer).__name__}")

    store = get_store()
    print(f"  Gate 3 (Store):            {type(store).__name__}")

    print("  Gate 4 (Reward):           ground-truth F1 (deterministic)")
    print("  Gate 5 (Regression gate):  armed (will run post-optimization)")

    # ── Datasets ───────────────────────────────────────────────
    train_tasks = build_train_dataset()
    val_tasks = build_val_dataset()
    train_dataset = cast(Dataset[BridgeBenchTask], train_tasks)
    val_dataset = cast(Dataset[BridgeBenchTask], val_tasks)

    print(f"\n--- Dataset ---")
    print(f"  Train: {len(train_tasks)} contracts")
    print(f"  Val (held-out): {len(val_tasks)} contracts")

    # ── Results dir ────────────────────────────────────────────
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    setup_apo_logger(RESULTS_DIR)

    # ── Seed prompt ────────────────────────────────────────────
    seed = seed_prompt_template()
    print(f"\n--- Seed prompt ---")
    print(f"  Length: {len(seed.template)} chars")
    print(f"  First 120 chars: {seed.template[:120]}...")

    # Seed the initial resources in the store
    await store.add_resources({"prompt_template": seed})

    # ── APO algorithm ──────────────────────────────────────────
    apo_client = AsyncOpenAI(base_url=BIFROST_URL, api_key=BIFROST_KEY)
    algo = APO[BridgeBenchTask](
        apo_client,
        gradient_model=APO_GRADIENT_MODEL,
        apply_edit_model=APO_EDIT_MODEL,
        val_batch_size=6,
        gradient_batch_size=4,
        beam_width=2,
        branch_factor=2,
        beam_rounds=3,
        _poml_trace=True,
    )

    # Wire the store and adapter into the algorithm.
    # CRITICAL: keep strong references — algo stores weakrefs internally.
    adapter = TraceToMessages()  # Must persist — algo uses weakref
    algo.set_store(store)
    algo.set_adapter(adapter)
    algo.set_initial_resources({"prompt_template": seed})

    print(f"\n--- Starting APO optimization ---")
    print(f"  Model: {BIFROST_MODEL}")
    print(f"  Gradient model: {APO_GRADIENT_MODEL}")
    print(f"  Edit model: {APO_EDIT_MODEL}")
    print(f"  Beam: width={algo.beam_width}, branches={algo.branch_factor}, rounds={algo.beam_rounds}")
    est_calls = (2 * 2 * 3) * (len(train_tasks) + len(val_tasks))
    print(f"  Estimated LLM calls: ~{est_calls}")
    print()

    # ── Launch runner + algorithm concurrently ─────────────────
    # The runner processes rollouts enqueued by APO.
    # APO.run() blocks until beam search completes.
    runner_task = asyncio.create_task(run_runner(store, tracer))

    try:
        await algo.run(train_dataset, val_dataset)
    finally:
        runner_task.cancel()
        try:
            await runner_task
        except asyncio.CancelledError:
            pass

    # ── Extract best prompt ────────────────────────────────────
    print("\n--- APO optimization complete ---")

    best_prompt = algo.get_best_prompt()
    if best_prompt:
        optimized_text = best_prompt.template
        print(f"  Best prompt length: {len(optimized_text)} chars (seed: {len(seed.template)})")

        result_path = RESULTS_DIR / "best_prompt.json"
        with open(result_path, "w") as f:
            json.dump({
                "date": datetime.now().isoformat(),
                "model": BIFROST_MODEL,
                "gradient_model": APO_GRADIENT_MODEL,
                "seed_prompt_length": len(seed.template),
                "optimized_prompt_length": len(optimized_text),
                "optimized_prompt": optimized_text,
                "seed_prompt": seed.template,
            }, f, indent=2)
        print(f"  Saved to: {result_path}")
    else:
        print("  WARNING: No best prompt returned — APO may have failed to improve")

    # ── Post-optimization regression gate (Gate 5) ─────────────
    print("\n--- Post-optimization regression gate (Gate 5) ---")

    optimized_system_prompt = optimized_text if best_prompt else seed.template

    from openai import OpenAI as SyncOpenAI
    _gate_client = SyncOpenAI(base_url=BIFROST_URL, api_key=BIFROST_KEY)

    def optimized_analyzer(source: str, contract_name: str = "Unknown") -> list:
        from agents.parse_utils import parse_llm_findings
        from dataclasses import dataclass

        @dataclass
        class Finding:
            vuln_type: str
            severity: str = "medium"
            location: str = "unknown"
            description: str = ""
            confidence: float = 0.5

        try:
            resp = _gate_client.chat.completions.create(
                model=BIFROST_MODEL, max_tokens=4096, temperature=0.0,
                messages=[
                    {"role": "system", "content": optimized_system_prompt},
                    {"role": "user", "content": (
                        f"Contract name: {contract_name}\n\n"
                        f"Analyze this Solidity smart contract for security vulnerabilities:\n\n"
                        f"```solidity\n{source}\n```\n\nProvide your analysis as JSON."
                    )},
                ],
            )
            text = resp.choices[0].message.content if resp.choices else ""
            findings = parse_llm_findings(text or "")
        except Exception as e:
            print(f"  [Gate error on {contract_name}]: {e}")
            findings = []

        return [
            Finding(
                vuln_type=f.get("type", f.get("vuln_type", "unknown")),
                severity=f.get("severity", "medium"),
                location=f.get("location", "unknown"),
                description=f.get("description", ""),
                confidence=f.get("confidence", 0.5),
            )
            for f in findings
        ]

    gate_result = run_regression_gate(
        optimized_analyzer, label="APO-optimized prompt", verbose=True,
    )

    # ── Final results ──────────────────────────────────────────
    print("\n" + "=" * 70)
    print("EXPERIMENT RESULTS")
    print("=" * 70)

    if gate_result["passed"]:
        print("  Regression gate: PASS")
        if best_prompt:
            delta = gate_result["metrics"]["f1"] - 0.500
            print(f"  Held-out F1: {gate_result['metrics']['f1']:.1%} (baseline: 50.0%)")
            print(f"  ΔF1: {'+' if delta >= 0 else ''}{delta:.1%}")
            if delta >= 0.03:
                print("  VERDICT: SUCCESS — ΔF1 >= +3pp on held-out")
            else:
                print("  VERDICT: NEUTRAL — improvement below +3pp threshold")
    else:
        print("  Regression gate: FAIL")
        for v in gate_result["violations"]:
            print(f"    {v}")
        print("  VERDICT: ABORT — regression detected")

    final_path = RESULTS_DIR / "experiment_results.json"
    with open(final_path, "w") as f:
        json.dump({
            "date": datetime.now().isoformat(),
            "model": BIFROST_MODEL,
            "gate_passed": gate_result["passed"],
            "held_out_metrics": gate_result["metrics"],
            "violations": gate_result["violations"],
            "best_prompt_length": len(optimized_text) if best_prompt else None,
        }, f, indent=2, default=str)
    print(f"\n  Full results: {final_path}")
    print("=" * 70)


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
