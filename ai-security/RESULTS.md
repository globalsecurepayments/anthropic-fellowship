# BRIDGE-bench Results

## Detection Baselines

### Static Analyzer v2 (Custom)

Our regex + heuristic-based analyzer, tuned for bridge-specific patterns.

| Metric | Value |
|--------|-------|
| **F1** | **41.6%** |
| Precision | 48.5% |
| Recall | 36.4% |
| True Positives | 16 |
| False Positives | 17 |
| False Negatives | 28 |

**Strengths:**
- Catches initialization bugs (NomadStyle: 4/5 vulns found)
- Detects oracle manipulation (spot price patterns)
- Good at unchecked ERC20 returns (PERFECT on UncheckedTransfer)
- Low false positive rate for bridge-specific patterns

**Weaknesses:**
- Misses compositional vulnerabilities (Poly Network: 0/3)
- Can't detect approval drain via arbitrary calldata (LiFi: 0/2)
- No understanding of cross-contract interactions
- Misses signature malleability, front-running, fee-on-transfer

### Slither (Trail of Bits)

Industry-standard static analysis with AST parsing, data flow, and taint tracking.

| Metric | Value |
|--------|-------|
| **F1** | **11.1%** |
| Precision | 10.9% |
| Recall | 11.4% |
| True Positives | 5 |
| False Positives | 41 |
| False Negatives | 39 |

**Why Slither performs poorly on BRIDGE-bench:**
1. Generic detectors don't map to bridge-specific vulnerability taxonomy
2. High false positive rate (41 FPs) from detectors like `low-level-calls`, `unused-return` that fire on every contract
3. Doesn't understand bridge-specific patterns (message validation, cross-chain replay)
4. Our simplified contracts trigger fewer of Slither's sophisticated detectors

**This is expected** — Slither is designed for general smart contract auditing, not bridge-specific analysis. The comparison demonstrates that domain-specific tooling (even simple heuristics) outperforms general-purpose tools on specialized benchmarks.

### Agent v2 (Claude, bridge-specific prompt)

LLM-based analyzer with bridge-specific system prompt and structured output.

| Metric | Value |
|--------|-------|
| **F1** | **59.0%** |
| Precision | 44.5% |
| Recall | 87.5% |
| True Positives | 49 |
| False Positives | 61 |
| False Negatives | 7 |

Tested on the full 27-contract expanded dataset (56 vulnerabilities).

**Strengths:**
- 87.5% recall — finds 49 of 56 vulnerabilities
- 2 PERFECT scores (UncheckedTransfer, TokenBridgeWithFeeAndApproval)
- Catches compositional vulnerabilities that static tools miss completely:
  - LiFi approval drain (2/2), Poly Network (2/3), Ronin (5/5)
  - TimelockBypass (2/2), FrontRun (1/1), FeeOnTransfer (1/1)
- Correctly identifies remaining bugs in partially-fixed contracts

**Weaknesses:**
- 61 false positives — flags `arbitrary_execution` and `reentrancy` too aggressively
- 8 false positives on clean contracts (SecureBridge, SecureMultisig)
- Lower precision (44.5%) than static analyzer (48.5%)

**Cost:** ~$0.50 per full benchmark run

### v3 Final Results (29 contracts, 65 vulnerabilities)

Including Drift Protocol ($285M, Apr 2026) and Circle CCTP bridge contracts.

| Analyzer | F1 | Precision | Recall | TP | FP | FN |
|----------|-----|-----------|--------|----|----|-----|
| **Agent v2 (Claude)** | **60.3%** | 46.0% | **87.7%** | **57** | 67 | **8** |
| Static Analyzer v2 | 37.8% | 45.7% | 32.3% | 21 | 25 | 44 |
| Slither | 11.1% | 10.9% | 11.4% | 5 | 41 | 39 |

**DriftStyle: 5/5 PERFECT** — agent found all governance + oracle vulnerabilities.
**CCTPStyle: 3/4** — found rate limiting gaps, centralization, zero timelock.

## Dataset

### v1: Test Contracts (4 contracts, 14 vulnerabilities)

| Contract | Vulns | Static v2 TP | Notes |
|----------|-------|-------------|-------|
| WormholeStyle | 2 | 1 | Misses untrusted verifier (compositional) |
| NomadStyle | 5 | 4 | Misses proof link (semantic) |
| RoninStyle | 5 | 2 | Misses dup sigs, withdrawal delay |
| OracleManipulation | 2 | 1 | Misses flash loan (compositional) |

### v2: Full Benchmark (20 contracts, 44 vulnerabilities)

| Contract | Based On | Vulns | Static v2 | Best Result |
|----------|----------|-------|-----------|-------------|
| WormholeStyle | Wormhole $320M | 2 | 0 TP, 1 FP | — |
| NomadStyle | Nomad $190M | 5 | 4 TP, 1 FP | Near-perfect |
| RoninStyle | Ronin $625M | 5 | 2 TP, 1 FP | — |
| OracleManipulation | Allbridge $570K | 2 | 1 TP, 0 FP | — |
| LiFiStyle | LiFi $11.6M | 2 | 0 TP, 0 FP | MISS |
| QubitStyle | Qubit $80M | 2 | 1 TP, 1 FP | New detection |
| HarmonyStyle | Harmony $100M | 3 | 2 TP, 1 FP | — |
| PolyNetworkStyle | Poly Network $611M | 3 | 0 TP, 0 FP | MISS |
| BadProxyBridge | UUPS proxy | 2 | 1 TP, 2 FP | — |
| ReplayBridge | Cross-chain replay | 2 | 1 TP, 0 FP | — |
| DelegateCallBridge | delegatecall inject | 1 | 1 TP, 5 FP | New detection |
| TimelockBypass | Emergency bypass | 2 | 0 TP, 1 FP | MISS |
| MalleableSig | ECDSA malleability | 2 | 0 TP, 2 FP | MISS |
| UncheckedTransfer | Unchecked ERC20 | 2 | 2 TP, 0 FP | PERFECT |
| DoubleSpend | Reentrancy | 2 | 1 TP, 1 FP | — |
| GasBomb | DoS via gas | 2 | 0 TP, 1 FP | MISS |
| SelfDestruct | Force-ETH | 1 | 0 TP, 2 FP | MISS |
| FrontRun | MEV/sandwich | 1 | 0 TP, 1 FP | MISS |
| MissingEvents | No events | 2 | 0 TP, 0 FP | MISS |
| FeeOnTransfer | Deflationary | 1 | 0 TP, 2 FP | MISS |

### Detection Gap Analysis

Vulnerabilities MISSED by static analysis but theoretically detectable by LLMs:

| Vulnerability Class | Contracts | Total $ at Risk | Why LLM Should Help |
|---|---|---|---|
| Arbitrary calldata → approval drain | LiFi, Poly Network | $621M | Requires tracing call flow |
| Message validation (zero root) | Nomad (missed 1/5) | $190M | Semantic understanding of defaults |
| Flash loan + oracle composition | Oracle, Allbridge | $570K+ | Multi-step reasoning |
| Signature malleability | MalleableSig | — | Crypto domain knowledge |
| Cross-chain replay | ReplayBridge | — | Protocol-level reasoning |
| Front-running / MEV | FrontRun | — | Transaction ordering reasoning |

## Patch Pipeline

Status: Architecture complete, compilation verification working.

```
Detect (static/agent) → Patch (Claude) → Compile (Foundry) → Verify (exploit replay)
```

Current: Detect + Patch + Compile stages implemented.
TODO: Exploit replay verification (requires matching Foundry tests to patches).

## Key Insight

**The gap between static tools and LLM agents is exactly where bridge-specific compositional vulnerabilities live.** Static tools catch pattern-matching bugs (42% F1). Slither catches generic Solidity issues (11% F1). Neither can reason about the multi-step attack flows that caused $1.6B in bridge losses.

This is the hypothesis BRIDGE-bench tests: **LLM agents should significantly outperform static tools on Tier 2 (compositional) vulnerabilities.**

## Plan-Execute-Critique Ablation (2026-04-11)

**Hypothesis:** Wrapping Agent v2 in a Plan -> Execute -> Critique reasoning
topology from MultiMind-AI (author-grant 2026-04-11) improves F1 by lifting
precision without sacrificing recall.

**Baseline (Agent v2 single-prompt, USE_BIFROST=1, 22 contracts):**
- Precision: 40.9%
- Recall:    84.9%
- F1:        55.2%
- TP=45, FP=65, FN=8

**Treatment (Agent v2 + Plan-Execute-Critique):**
- Precision: 21.2%
- Recall:    13.2%
- F1:        16.3%
- TP=7, FP=26, FN=46

**Delta:**
- DP: -19.7pp
- DR: -71.7pp
- DF1: -38.9pp

**Result:** NEGATIVE (catastrophic)

**Interpretation:** The Plan-Execute-Critique topology caused catastrophic recall
collapse. 15 of 22 contracts returned 0 findings — the critique stage stripped
all findings, including true positives. The critique prompt's "when in doubt,
remove" directive was too aggressive: it treated ANY finding without exhaustive
function-level evidence as suspect, even when the execute stage correctly
identified real vulnerabilities. The plan stage also hurt: prepending audit
strategy text as a Solidity comment confused the execute stage on several
contracts ("Failed to parse response for Unknown"), causing it to produce fewer
or malformed findings that the critique then zeroed out entirely.

Root causes:
1. Critique too aggressive — "remove when in doubt" + confidence threshold
   filtering eliminated findings that were actually correct
2. Plan-as-comment injection — prepending plan text as `/* ... */` in the
   Solidity source confused the model on contracts where the plan was longer
   than the contract itself
3. No contract name propagation — benchmark runner passes only `source_code`
   to the analyzer, so contract_name was always "Unknown", weakening the
   plan and critique prompts

**Lesson:** Reasoning topologies that add filtering stages between the model
and the output are dangerous for recall-sensitive tasks. The baseline's
single-prompt approach is better for security auditing because it errs on the
side of reporting — false positives are cheaper than missed vulnerabilities.

**Provenance:** Pattern from MultiMind-AI `multimind/pipeline.py` under
author-direct learning grant from JitseLambrichts, 2026-04-11.
Plan document: `~/Annunaki/Agent Vault/plans/bridge-bench-plan-execute-critique-ablation.md`
Decision record: `~/Annunaki/Agent Vault/decisions/Adopt batch 2026-04-11.md`

## Evidence Ladder Phase 1 — Reporting Gate (2026-04-17)

**Hypothesis:** Tagging Agent v2 findings with a 6-rung evidence level
(suspicion -> static_corroboration -> crash_reproduced -> ...) and gating
reported results at >= static_corroboration would remove false positives
without the uniform recall collapse seen in the critique ablation and APO
experiment. Pattern extracted from clearwing (Lazarus AI, MIT).

**Design:** Single-pass — LLM runs once, findings are tagged via static
analyzer cross-check, then split into reported (>= static_corroboration)
vs below-threshold (suspicion). Same findings, two views. Eliminates
LLM run-to-run variance from the comparison.

**Baseline (all findings, same LLM run):**
- Precision: 45.9%
- Recall:    84.9%
- F1:        59.6%
- TP=45, FP=53, FN=8

**Evidence-gated (>= static_corroboration):**
- Precision: 85.0%
- Recall:    32.1%
- F1:        46.6%
- TP=17, FP=3, FN=36

**Evidence distribution:** 78 suspicion, 20 corroborated (out of 98 findings)

**Delta:**
- DP: +39.1pp (precision rescue works)
- DR: -52.8pp (recall catastrophe)
- DF1: -13.0pp

**Result:** ABORT (recall floor breached by 52.8pp)

**Interpretation:** The evidence ladder tagging works correctly — it
accurately identifies which findings have static corroboration and which
are LLM-only. The problem is structural: 62% of true positives (28 of 45)
are LLM-only findings with NO static corroboration possible. These are
exactly the compositional vulnerabilities (flash loan + oracle, arbitrary
calldata + approval drain, governance + timelock bypass) that make the LLM
valuable — the static analyzer has no pattern for them by definition.

Requiring static corroboration as a filter threshold is fundamentally
incompatible with a benchmark whose thesis is "LLMs catch what static
tools miss." The gate filters 50 FPs (excellent) but also 28 TPs (fatal).

**Structural finding:** The evidence ladder is a valid GRADING tool (tag
findings for downstream prioritization) but NOT a valid FILTERING tool
for BRIDGE-bench. This is the third consecutive precision-fix attempt to
fail on the same fundamental constraint: the baseline's recall comes from
findings that lack external corroboration, and any filter that requires
corroboration destroys recall proportionally.

**Three-experiment precision-fix summary:**

| Experiment | Mechanism | DP | DR | Verdict |
|---|---|---|---|---|
| Critique ablation (2026-04-11) | "Remove when in doubt" | -19.7pp | -71.7pp | ABORT |
| APO experiment (2026-04-12) | Specificity pressure | +7.2pp | -19.1pp | ABORT |
| Evidence Ladder gate (2026-04-17) | Static corroboration filter | +39.1pp | -52.8pp | ABORT |

All three improve precision at catastrophic recall cost. The pattern is
now confirmed: BRIDGE-bench's precision weakness cannot be fixed by any
post-hoc filtering mechanism because the LLM's true positives and false
positives are both at the same evidence level (suspicion).

**Provenance:** Evidence Ladder framework from clearwing (Lazarus AI, MIT).
Decision record: `~/Annunaki/Agent Vault/decisions/Verdict batch 2026-04-17b.md`
