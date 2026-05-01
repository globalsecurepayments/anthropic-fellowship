"""
BRIDGE-bench APO experiment — run configuration.

All five pre-flight gates are configured here. Every LLM call routes through
Bifrost at localhost:8090 (fleet invariant). No direct provider calls.

Decision: ~/Annunaki/Agent Vault/decisions/Adopt agent-lightning APO experiment.md
Gateway discipline: ~/Annunaki/Agent Vault/research/synthesis/LLM Gateway Discipline — Synthesis.md
"""

from __future__ import annotations

import os
import sys
import functools
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Gate 1 — Bifrost routing (hard invariant)
# ---------------------------------------------------------------------------

BIFROST_URL = "http://localhost:8090/v1"
BIFROST_KEY = os.environ.get("BIFROST_KEY", "sk-bf-dev-interactive")
# Anthropic API key rolled 2026-04-12. Credits restored.
BIFROST_MODEL = os.environ.get(
    "BRIDGE_MODEL", "anthropic/claude-sonnet-4-20250514"
)

# APO gradient/edit model — can be cheaper than the analyzer model.
# Must still route through Bifrost.
APO_GRADIENT_MODEL = os.environ.get("APO_GRADIENT_MODEL", BIFROST_MODEL)
APO_EDIT_MODEL = os.environ.get("APO_EDIT_MODEL", BIFROST_MODEL)


def assert_bifrost_url(url: str, context: str = "") -> None:
    """Hard assertion: every LLM endpoint must be Bifrost.
    Raises RuntimeError if url does not point at localhost:8090."""
    normalized = url.rstrip("/")
    allowed = {"http://localhost:8090/v1", "http://localhost:8090"}
    if normalized not in allowed:
        raise RuntimeError(
            f"[GATE 1 VIOLATION] LLM endpoint '{url}' does not route through "
            f"Bifrost (localhost:8090). Context: {context}. "
            f"All calls MUST traverse Bifrost — see LLM Gateway Discipline synthesis."
        )


def get_sync_client():
    """OpenAI-compatible sync client routed through Bifrost.
    Mirrors the USE_BIFROST pattern from claude_analyzer.py / agent_v2_bridge.py."""
    from openai import OpenAI

    assert_bifrost_url(BIFROST_URL, "sync client construction")
    return OpenAI(base_url=BIFROST_URL, api_key=BIFROST_KEY)


def get_async_client():
    """OpenAI-compatible async client for APO gradient/edit calls.
    Same Bifrost routing — APO's own LLM calls are not exempt."""
    from openai import AsyncOpenAI

    assert_bifrost_url(BIFROST_URL, "async client construction (APO gradient/edit)")
    return AsyncOpenAI(base_url=BIFROST_URL, api_key=BIFROST_KEY)


def get_model_config() -> dict:
    """agent-lightning ModelConfig dict for LLMProxy (if used).
    api_base points at Bifrost, not a direct provider."""
    assert_bifrost_url(BIFROST_URL, "ModelConfig construction")
    return {
        "model_name": BIFROST_MODEL,
        "litellm_params": {
            "model": BIFROST_MODEL,
            "api_base": BIFROST_URL,
            "api_key": BIFROST_KEY,
        },
    }


# ---------------------------------------------------------------------------
# Outbound call guard — validates all client base_urls before any run
# ---------------------------------------------------------------------------

def validate_bifrost_routing() -> None:
    """Pre-run assertion: verify every configured endpoint targets Bifrost.
    Call this once before starting any APO run. Fails loud on violation."""
    endpoints = [
        ("BIFROST_URL (analyzer)", BIFROST_URL),
        ("ModelConfig.api_base", get_model_config()["litellm_params"]["api_base"]),
    ]
    for label, url in endpoints:
        assert_bifrost_url(url, label)

    # Verify live connectivity
    import urllib.request
    try:
        req = urllib.request.Request(
            f"{BIFROST_URL}/models",
            headers={"Authorization": f"Bearer {BIFROST_KEY}"},
        )
        resp = urllib.request.urlopen(req, timeout=5)
        if resp.status != 200:
            raise RuntimeError(f"Bifrost returned {resp.status}")
    except Exception as e:
        raise RuntimeError(
            f"[GATE 1 BLOCKED] Bifrost not reachable at {BIFROST_URL}: {e}. "
            f"Do NOT work around this — escalate."
        ) from e


# ---------------------------------------------------------------------------
# Gate 2 — Tracer selection (OtelTracer, NOT AgentOpsTracer)
# ---------------------------------------------------------------------------

def get_tracer():
    """Return OtelTracer instance. AgentOpsTracer is prohibited per fleet convention."""
    from agentlightning.tracer.otel import OtelTracer

    return OtelTracer()


# ---------------------------------------------------------------------------
# Gate 3 — Store backend (InMemoryLightningStore, no MongoDB)
# ---------------------------------------------------------------------------

def get_store():
    """Return InMemoryLightningStore with eviction monitoring enabled.

    Eviction guard: the eviction_memory_threshold defaults to 70% of system
    memory. For BRIDGE-bench APO runs (~80 rollouts per iteration, ~4K tokens
    per span), total span payload is <100MB — well below threshold on a 48GB
    machine. The safe_memory_threshold at 60% triggers cleanup before hard
    eviction. If either threshold fires, the store logs a warning via its
    internal MemoryPressureManager — monitor stderr for 'eviction' messages
    during long runs.
    """
    from agentlightning import InMemoryLightningStore

    return InMemoryLightningStore(
        thread_safe=True,
        eviction_memory_threshold=0.7,  # 70% of system RAM
        safe_memory_threshold=0.6,  # cleanup starts at 60%
    )


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

AI_SECURITY_ROOT = Path(__file__).parent.parent
BENCHMARKS_ROOT = AI_SECURITY_ROOT / "benchmarks"
AGENTS_ROOT = AI_SECURITY_ROOT / "agents"
APO_ROOT = Path(__file__).parent
RESULTS_DIR = AI_SECURITY_ROOT / "apo" / "results"


# ---------------------------------------------------------------------------
# Smoke test — run with: python -m apo.run_config
# ---------------------------------------------------------------------------

def smoke_test() -> None:
    """Verify Gate 1: a trial LLM call traverses Bifrost."""
    import json

    print("=" * 60)
    print("GATE 1 SMOKE TEST — Bifrost routing verification")
    print("=" * 60)

    # 1. Assert config
    assert_bifrost_url(BIFROST_URL, "smoke test")
    print(f"  Bifrost URL: {BIFROST_URL} ... OK")

    # 2. Validate all endpoints
    validate_bifrost_routing()
    print("  All endpoints validated against Bifrost ... OK")

    # 3. Construct clients
    sync = get_sync_client()
    print(f"  Sync client base_url: {sync.base_url} ... OK")

    async_client = get_async_client()
    print(f"  Async client base_url: {async_client.base_url} ... OK")

    # 4. ModelConfig check
    mc = get_model_config()
    print(f"  ModelConfig api_base: {mc['litellm_params']['api_base']} ... OK")

    # 5. Trial call through Bifrost
    print(f"\n  Sending trial call to {BIFROST_MODEL} via Bifrost ...")
    try:
        response = sync.chat.completions.create(
            model=BIFROST_MODEL,
            max_tokens=10,
            messages=[{"role": "user", "content": "Reply with exactly: BIFROST_OK"}],
        )
        # Handle both standard and Bifrost-proxied response shapes
        if response.choices:
            reply = response.choices[0].message.content or "(empty)"
            print(f"  Response: {reply.strip()}")
        else:
            print(f"  Response: (no choices — raw: {response})")
        print(f"  Model in response: {response.model}")
    except Exception as e:
        # Even a 400 from Bifrost confirms routing works (the call reached Bifrost)
        err_str = str(e)
        if "is_bifrost_error" in err_str or "provider" in err_str:
            print(f"  Bifrost returned error (routing confirmed): {err_str[:120]}")
        else:
            raise

    print(f"\n  GATE 1: PASS — trial call routed through Bifrost")
    print("=" * 60)


if __name__ == "__main__":
    smoke_test()
