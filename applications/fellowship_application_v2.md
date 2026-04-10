# Anthropic Fellows Program: Application

## Track: AI Security Fellow

---

## Research Proposal: Cross-Chain Bridge Vulnerability Detection with AI Agents

### Problem

Cross-chain bridges have lost over $3 billion to exploits since 2021. Six days ago, Drift Protocol was drained for $285M, the largest DeFi exploit of 2026. The attacker (attributed to DPRK/Lazarus) used social-engineered pre-signed nonce transactions, a fabricated token with wash-traded price history, and a zero-timelock governance migration. Circle had 6 hours to freeze the $232M in stolen USDC bridged via CCTP and didn't act.

Static analysis tools like Slither catch pattern-matching bugs. They do not reason about the multi-step attack flows that caused these losses. The vulnerability classes that matter are compositional: cross-chain message forgery, governance takeover, oracle manipulation via fake tokens, approval drain via arbitrary calldata. They require understanding how individually-safe components interact to create exploitable conditions.

Xiao & Killian (Anthropic Fellows, 2026) demonstrated that AI agents can find $4.6M in exploitable single-chain vulnerabilities with SCONE-bench. BRIDGE-bench extends this to cross-chain bridges, where the dollar amounts are 100x larger and the attack surface is different in kind.

### Results

I built BRIDGE-bench and ran the experiments before applying. Here are the numbers.

BRIDGE-bench v3: 29 contracts, 65 labeled vulnerabilities, 23 Foundry exploit tests

| Analyzer | F1 | Precision | Recall | TP/Total |
|----------|-----|-----------|--------|----------|
| Slither (Trail of Bits) | 11.1% | 10.9% | 11.4% | 5/44* |
| Static Analyzer v2 (custom) | 37.8% | 45.7% | 32.3% | 21/65 |
| Agent v2 (Claude Sonnet, single-prompt) | 60.3% | 46.0% | 87.7% | 57/65 |
| Agentic multi-turn (Claude, tool use) | 68% | 54% | 93% | 13/14** |

*Slither tested on 20-contract subset. **Multi-turn tested on 4 core contracts (14 vulns), 51 tool calls per run.

The Claude agent finds 88% of bridge vulnerabilities, 2.7x the recall of our best static analyzer and 7.7x Slither's. The multi-turn agentic approach pushes F1 to 68% on the core contract set, at 135K tokens per run.

The agent catches compositional vulnerabilities that static tools cannot detect:

| Vulnerability | Real Loss | Static | Agent |
|---|---|---|---|
| Drift governance takeover + oracle manipulation | $285M | MISS | 5/5 |
| CCTP bridge centralization + no rate limiting | (used in $285M Drift bridge) | MISS | 3/4 |
| LiFi approval drain via arbitrary calldata | $11.6M | MISS | 2/2 |
| Poly Network unrestricted cross-chain call | $611M | MISS | 2/3 |
| Ronin duplicate signatures + low threshold | $625M | 2/5 | 5/5 |
| Timelock bypass + centralization risk | common pattern | MISS | 2/2 |

The tradeoff: 67 false positives vs 25 for static. In bridge security, missing a real vulnerability means nine-figure losses. The recall advantage is what matters.

### The Benchmark

11 real bridge exploits ($1.9B total losses) with fork block data for reproduction:

| Exploit | Date | Loss | Vulnerability |
|---------|------|------|---------------|
| Poly Network | 2021-08 | $610M | Unrestricted cross-chain call |
| Ronin Bridge | 2022-03 | $625M | Validator key compromise (5/9) |
| Nomad Bridge | 2022-08 | $190M | Zero-root message validation |
| Qubit Finance | 2022-01 | $80M | Zero-value deposit |
| Orbit Chain | 2024-01 | $82M | Multisig key compromise |
| LiFi v2 | 2024-07 | $10M | Approval drain via calldata |
| Socket Gateway | 2024-01 | $3.3M | Approval exploitation |
| LiFi v1 | 2022-03 | $600K | Arbitrary external call |
| Allbridge | 2023-04 | $570K | Flash loan oracle manipulation |
| XBridge | 2024-04 | $1.6M | Approval exploitation |
| Drift Protocol | 2026-04 | $285M | Governance takeover + oracle + CCTP bridge |

29 simplified pattern contracts with 65 labeled vulnerabilities across 17 classes, including partially-fixed variants (test if analyzers handle incomplete patches), combined multi-vuln patterns, and clean contracts (calibrate false positive rate).

23 passing Foundry exploit reproduction tests across 4 suites (Nomad, Wormhole, Ronin, CCTP).

Full pipeline: Detect → Patch → Compile → Verify (Foundry). All stages implemented.

### Proposed Fellowship Research

Three research questions, in order of expected impact.

1. False positive reduction through structured verification (target: 46% → 70%+ precision)

The agent's 67 false positives cluster around three categories: `input_validation_missing` (15), `reentrancy` (8), and `missing_event_emission` (7). These are real code smells but not exploitable in their specific context. The research question: can a second-pass verification agent, given the flagged finding and the full contract, distinguish "this pattern exists" from "this pattern is exploitable here"? I would test:
- Verification agent with exploit-construction prompt ("write a Foundry test that exploits this finding")
- If the agent cannot construct an exploit, downgrade confidence
- Calibrate confidence thresholds against the labeled dataset

This forces the agent to demonstrate exploitability rather than argue about it. Chain-of-thought verification asks "are you sure?" and gets "yes" back. Exploit construction asks "prove it" and either produces a working test or doesn't.

2. Real deployed contracts (Etherscan source)

The current benchmark uses simplified patterns. The gap between "simplified RoninStyle contract" and "the actual Ronin Bridge deployed at 0x..." is significant: real contracts have proxy patterns, library imports, inherited authorization logic, and thousands of lines of context. Testing on real source code is the validation that matters to the security community.

3. Patch generation with exploit replay verification

The pipeline architecture exists (detect → patch → compile). The missing piece: after patching, replay the original Foundry exploit test. If the test that previously passed (demonstrating the vulnerability) now fails (patch blocked the exploit), the fix is verified. This closes the loop from detection through remediation with a machine-checkable proof.

### Why Me

I built a working benchmark, ran the experiments, and have measured results. Before applying. The code is public and the numbers are reproducible.

I wrote every contract, every test, and every analyzer. 29 contracts with 65 labeled ground-truth vulnerabilities. 23 Foundry exploit reproductions. A static analyzer, a single-prompt Claude analyzer, and a multi-turn agentic analyzer with tool use. The evaluation harness with precision/recall/F1 scoring. The detect-patch-compile pipeline.

I added Drift within days of the exploit. The $285M attack happened April 1, 2026. I had DriftStyle and CCTPStyle contracts with labeled vulnerabilities in the benchmark by April 4. The agent found 5/5 Drift vulnerabilities and 3/4 CCTP vulnerabilities. I knew what to model because I understood the attack.

I know these systems from the inside. 8+ years building DeFi infrastructure: cross-chain arbitrage (Bellman-Ford pathfinder across 40+ DEXs), MEV protection, bridge integrations, a trading system with Rust execution and Python ML signal generation. I have personally experienced a USDC theft and executed multi-channel recovery. The attacker and defender perspectives are not theoretical for me.

I replicate before extending. My mech interp portfolio (below) demonstrates the same approach: 14 experiments replicating established results, honest documentation of mistakes (multi-token patching error in experiment 1), explicit negative results (SAE feature steering, experiment 13), then careful extensions with mechanistic evidence.

### Mechanistic Interpretability Portfolio

To demonstrate technical range, I completed a full mech interp research sprint. Replication, not novelty claims.

14 experiments covering TransformerLens, activation patching, direct logit attribution, induction heads, superposition, SAEs, and circuit analysis:

| # | Experiment | Key Finding |
|---|-----------|-------------|
| 01 | Factual recall localization | Resolved at 75-83% depth; documented multi-token patching mistake |
| 02 | Multi-token patching correction | Corrected methodology shows consistent depth across model families |
| 03 | Cross-model replication | GPT-2 + Pythia-70m + Pythia-160m convergence |
| 04 | Negation processing | Negation *boosts* target logit in 4/6 cases, distributional artifact |
| 05 | Cross-model negation | Booster effect attenuates with scale, suppression failure persists |
| 06 | Induction head detection | L5H5=0.92 score, 33x loss on ablation |
| 07 | Direct logit attribution + logit lens | Predictions crystallize at L9-L10 |
| 08 | Activation patching | 98% recovery from last-position patch |
| 09 | Toy superposition models | Phase transitions, importance-based encoding |
| 10 | SAE on GPT-2 small | From-scratch implementation, 100% variance explained |
| 11 | Greater-than circuit | 117x year ordering ratio, L7-L8 transition, 5-step analysis |
| 12 | IOI circuit | Name movers (L0H9: +3.52), S-inhibitors (L0H8: -3.17) |
| 13 | SAE feature steering | Negative result: insufficient data for monosemantic features |
| 14 | Activation steering | Positive result: sentiment and formality are linear directions |

4 writeups ready: factual recall replication, negation as factual booster, greater-than circuit, IOI circuit.

### Timeline (4 months)

| Month | Focus | Deliverable |
|-------|-------|-------------|
| 1 | Expand to 50+ real contracts (Etherscan source), build verification agent | Precision improvement measured |
| 2 | Multi-turn agent tuning, exploit replay verification pipeline | End-to-end detect-patch-verify on real contracts |
| 3 | Validation against professional audit findings, head-to-head comparison | Comparison dataset with audit firm ground truth |
| 4 | Paper, open-source release, blog post | Publication + public benchmark |

### Expected Output

- Paper: "BRIDGE-bench: Evaluating AI Agents on Cross-Chain Bridge Vulnerability Detection"
- Open-source: BRIDGE-bench dataset + agents + eval harness + Foundry tests
- Measured result: agent F1 on real deployed bridge contracts (not simplified patterns)
- Blog post for the DeFi security community

---

## About Me

I'm a systems engineer and startup founder. 8+ years in crypto and DeFi infrastructure. I've built cross-chain arbitrage systems, MEV protection layers, and trading bots with Rust execution engines. I've had money stolen and recovered it. I understand these systems at the level where I know which line of code the attacker would target, because I've written that line.

I'm pursuing AI safety research because the intersection of AI capabilities and financial attack surfaces is where safety work has immediate, measurable, dollar-denominated impact. Bridges get exploited every month. The Drift hack happened while I was building this benchmark. I don't need to construct hypothetical threat models. The threat model plays out on-chain, in public, with nine-figure consequences.

I don't have a PhD or ML publications. I build working systems fast, I have deep domain knowledge in exactly the area this research targets, and I document mistakes and negative results alongside successes.

Code: github.com/globalsecurepayments/anthropic-fellowship
