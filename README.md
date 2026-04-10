# BRIDGE-bench + Mech Interp Portfolio

Research portfolio for the Anthropic Fellows Program (July 2026 cohort).

## BRIDGE-bench: AI-Assisted Cross-Chain Bridge Vulnerability Detection

Defense-focused benchmark for evaluating AI agents on cross-chain bridge security.
Built on real exploit data from [DefiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs),
the same source used by [SCONE-bench](https://github.com/safety-research/SCONE-bench) (Xiao & Killian, 2026).

### The Thesis

SCONE-bench asks: *"Can AI break smart contracts?"*
BRIDGE-bench asks: *"Can AI protect bridges?"*

Static analysis tools catch pattern-matching vulnerabilities (38% F1 baseline).
LLM agents should catch compositional bridge vulnerabilities — message validation flaws,
approval drain via arbitrary calldata, flash loan + oracle composability — that static
tools systematically miss. These gaps represent $811M in historical losses.

### Data

11 real bridge exploits ($1.9B total losses) with fork data for reproduction:

| Exploit | Date | Loss | Vulnerability Class |
|---------|------|------|---------------------|
| Poly Network | 2021-08 | $610M | Message validation |
| Ronin Bridge | 2022-03 | $625M | Validator governance |
| Nomad Bridge | 2022-08 | $190M | Message validation |
| Qubit Finance | 2022-01 | $80M | Input validation |
| Orbit Chain | 2024-01 | $82M | Validator governance |
| LiFi v2 | 2024-07 | $10M | Approval exploitation |
| Socket Gateway | 2024-01 | $3.3M | Approval exploitation |
| XBridge | 2024-04 | $1.6M | Approval exploitation |
| LiFi v1 | 2022-03 | $600K | Approval exploitation |
| Allbridge | 2023-04 | $570K | Oracle manipulation |
| Drift Protocol | 2026-04 | $285M | Governance takeover + oracle manipulation |

### Architecture: Detect → Patch → Verify

```
agents/
├── static_analyzer_v2.py    # Pattern-matching baseline (38% F1)
├── claude_analyzer.py       # Single-prompt Claude analysis
├── agentic_analyzer.py      # Multi-turn Claude agent with tools
├── patch_generator.py       # Claude generates Solidity patches
├── harness.py               # Docker + Foundry evaluation harness
├── benchmark_runner.py      # Head-to-head comparison with metrics
├── eval_harness.py          # Precision / Recall / F1 evaluation
└── pipeline.py              # End-to-end pipeline

benchmarks/
├── bridge_bench.py          # Real exploit database (from DefiHackLabs)
├── test_contracts.py        # 4 simplified contracts, 14 labeled vulns
├── bridge_exploits.py       # Exploit metadata catalog
└── fetch_contracts.py       # Etherscan source code fetcher
```

### Quick Start

```bash
# Install deps and clone DefiHackLabs
make setup

# Run static analyzer baseline (no API key needed)
make test-static

# Run Claude analyzer (needs API key)
export ANTHROPIC_API_KEY=sk-ant-...
make test-claude

# Full benchmark comparison
make benchmark
```

### Current Results (v3: 29 contracts, 65 vulnerabilities)

| Analyzer | F1 | Precision | Recall | TP | FP | FN |
|----------|-----|-----------|--------|----|----|-----|
| Slither (Trail of Bits) | 11.1% | 10.9% | 11.4% | 5 | 41 | 39 |
| Static Analyzer v2 (custom) | 37.8% | 45.7% | 32.3% | 21 | 25 | 44 |
| Agent v2 (Claude Sonnet, single-prompt) | 60.3% | 46.0% | 87.7% | 57 | 67 | 8 |
| Agentic multi-turn (Claude, tool use)* | 68% | 54% | 93% | 13 | 11 | 1 |

*Multi-turn tested on 4 core contracts (14 vulns), 51 tool calls per run.

The Claude agent finds 88% of bridge vulnerabilities, 2.7x the recall of our best static analyzer and 7.7x Slither's. See `ai-security/RESULTS.md` for full breakdown.

---

## Mechanistic Interpretability Portfolio

14 experiments replicating known results as capability demonstration.
Replication, not novelty claims.

| # | Experiment | Key Finding |
|---|-----------|-------------|
| 01 | Factual recall localization | Resolved at 75-83% depth; documented multi-token patching mistake |
| 02 | Multi-token patching correction | Corrected methodology shows consistent depth across model families |
| 03 | Cross-model replication | GPT-2 + Pythia-70m + Pythia-160m convergence |
| 04 | Negation processing | Negation boosts target logit in 4/6 cases, distributional artifact |
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

4 writeups: factual recall replication, negation as factual booster, greater-than circuit, IOI circuit.

---

## Structure

```
anthropic-fellowship/
├── ai-security/              # BRIDGE-bench (primary track)
│   ├── agents/               # Detection + patching + evaluation code
│   ├── benchmarks/           # Exploit database + test contracts
│   └── requirements.txt
├── mech-interp/              # Capability demonstration
│   ├── experiments/          # 14 experiments (Python scripts)
│   ├── notebooks/            # TransformerLens starter
│   ├── writeups/             # 4 Alignment Forum drafts
│   └── requirements.txt
├── applications/             # Fellowship application draft
├── reading-notes/            # Paper reading template
├── Dockerfile                # Docker evaluation environment
├── Makefile                  # One-command operations
└── SPRINT.md                 # Week-by-week progress tracker
```

## Requirements

- Python 3.10+
- [Foundry](https://book.getfoundry.sh/) for Solidity compilation and blockchain forking
- `ANTHROPIC_API_KEY` for Claude-based analysis
- `ETHERSCAN_API_KEY` (free) for fetching real contract source

## Author

Derick Smith ([@globalsecurepayments](https://github.com/globalsecurepayments))

Originally developed as [@0xSoftBoi](https://github.com/0xSoftBoi).

## Links

- [Anthropic Fellows Application](https://constellation.fillout.com/anthropicsecurityfellows)
- [SCONE-bench](https://github.com/safety-research/SCONE-bench) (prior art)
- [DefiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) (exploit data source)
- [EVMbench](https://arxiv.org/html/2603.04915v1) (related work)
