# BRIDGE-bench: AI-Assisted Cross-Chain Bridge Vulnerability Detection

Defense-focused benchmark for evaluating AI agents on cross-chain bridge security. Built on real exploit data from DefiHackLabs.

## Differentiation from SCONE-bench

SCONE-bench (Xiao & Killian): 405 contracts, exploit-focused (red team), dollar-value scoring.
BRIDGE-bench (ours): bridge-specific subset, defense-focused (detect + patch + verify), P/R/F1 scoring.

## Data: 10 real bridge exploits, $1.6B total losses

LLM-detectable: 8/10 exploits, $896M. Static-detectable: 3/10, $85M.

## Current baseline: Static v2 at 55% F1 on test contracts

Systematic gaps Claude should fill: compositional vulns, trust relationship flaws, approval drain via arbitrary calldata, recurring vulnerability detection.

## Quick Start

    make setup        # install deps + clone DefiHackLabs
    make test-static  # run static baseline
    make test-claude  # run Claude analyzer (needs ANTHROPIC_API_KEY)
    make benchmark    # head-to-head comparison

## Eval Stack

BRIDGE-bench uses a three-layer eval stack. The convention is fleet-wide — DeepEval Phase 2/3 consumers (ai-hedgefund, Trading Bots, Hydrabet, GEO Auditor, embeddable-assistant) inherit it.

| Layer | Tool | Role |
|-------|------|------|
| Outer harness | promptfoo | YAML-driven regression suites, multi-provider matrix, CI gates, red-teaming |
| Inner metric engine | DeepEval | Python-native metrics (G-Eval, RAG, agent-trace, MCP correctness), pytest plugin, `Synthesizer` adversarial fixtures |
| Deterministic replay | aimock | HTTP-layer LLM mocking — same trace yields same result twice |

**Judge factory.** All DeepEval judge calls go through `evals.judge_factory.make_judge()`, which returns a `LiteLLMModel` pinned to Bifrost (`localhost:8090`). `deepeval.models.AnthropicModel` is intentionally not exported — it hardcodes the Anthropic SDK and bypasses the gateway. Override the judge model with `JUDGE_MODEL`.

**Telemetry opt-out.** `DEEPEVAL_TELEMETRY_OPT_OUT=true` is the gating env var. Unset, deepeval fires PostHog + Sentry events at import and pulls the public IP from `api.ipify.org`. Set in `.env.example`; verify on every dev machine.

**HumanEval gating.** DeepEval's `deepeval/benchmarks/human_eval/` calls `secure_exec()` with a bypassable builtins restriction. **Do not** run HumanEval against untrusted models without SmolVM (Firecracker microVM) hardware-plane isolation — see `decisions/Adopt SmolVM 2026-04-15`.

**Separate-model judge rule.** Per AXI's 915-run validity finding, the judge model must differ from the agent under evaluation. Default `BRIDGE_MODEL` is the analyzer; `JUDGE_MODEL` (when set) overrides for the metric pass.

Decision: `~/Annunaki/Agent Vault/decisions/Adopt deepeval 2026-04-27.md`. Pilot suite at `evals/test_agent_v2_geval.py`; fixture generator at `evals/synthesize_fixtures.py`.
