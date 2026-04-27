"""Fleet-default DeepEval judge factory.

All DeepEval judge calls MUST go through Bifrost (localhost:8090).
deepeval.models.AnthropicModel hardcodes the Anthropic SDK and bypasses
Bifrost — it is intentionally NOT exported from this module. Use make_judge()
for every LLM-as-judge metric.

Decision: ~/Annunaki/Agent Vault/decisions/Adopt deepeval 2026-04-27.md
Bifrost invariant: ai-security/apo/run_config.py (assert_bifrost_url).
"""

from __future__ import annotations

import os
from typing import Optional

from deepeval.models import DeepEvalBaseLLM
from deepeval.models.llms.litellm_model import LiteLLMModel

# Bifrost invariant — mirrors apo/run_config.py.
BIFROST_URL = "http://localhost:8090/v1"
_ALLOWED_BIFROST_URLS = {"http://localhost:8090/v1", "http://localhost:8090"}


def _assert_bifrost_url(url: str) -> None:
    if url.rstrip("/") not in _ALLOWED_BIFROST_URLS:
        raise RuntimeError(
            f"Judge factory refused base_url={url!r}. All LLM calls MUST "
            f"traverse Bifrost (one of {_ALLOWED_BIFROST_URLS}). "
            "See LLM Gateway Discipline synthesis."
        )


# Default judge: openai/gpt-4o-mini via Bifrost. Two reasons:
#   1. AXI separate-model judge rule — judge MUST differ from the analyzer
#      (BRIDGE_MODEL defaults to anthropic/claude-sonnet-4-20250514).
#   2. G-Eval requires response_format=json_schema. Bifrost's OpenAI-compat
#      layer rejects this for anthropic/* models ("does not support output
#      format"); openai/* models accept it.
DEFAULT_JUDGE_MODEL = "openai/gpt-4o-mini"


def make_judge(
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    temperature: float = 0.0,
) -> DeepEvalBaseLLM:
    """Return a DeepEval-compatible judge wired through Bifrost.

    Defaults:
        model    — env JUDGE_MODEL, then DEFAULT_JUDGE_MODEL
                   ("openai/gpt-4o-mini"). Do NOT default to BRIDGE_MODEL —
                   that's the analyzer; AXI rule forbids judging with the same
                   model.
        base_url — env BIFROST_URL, then http://localhost:8090/v1.
        api_key  — env BIFROST_KEY, then "sk-bf-dev-interactive".
    """
    base_url = base_url or os.environ.get("BIFROST_URL", BIFROST_URL)
    _assert_bifrost_url(base_url)

    api_key = api_key or os.environ.get("BIFROST_KEY", "sk-bf-dev-interactive")

    raw_model = (
        model
        or os.environ.get("JUDGE_MODEL")
        or DEFAULT_JUDGE_MODEL
    )
    # Force OpenAI-compat transport so litellm hits Bifrost rather than the
    # Anthropic SDK. The openai/ prefix may double-up (openai/openai/gpt-4o-mini)
    # — litellm strips one layer and routes to Bifrost; Bifrost dispatches to
    # the inner provider.
    litellm_model = raw_model if raw_model.startswith("openai/") else f"openai/{raw_model}"

    return LiteLLMModel(
        model=litellm_model,
        base_url=base_url,
        api_key=api_key,
        temperature=temperature,
    )


__all__ = ["make_judge", "BIFROST_URL", "DEFAULT_JUDGE_MODEL"]
