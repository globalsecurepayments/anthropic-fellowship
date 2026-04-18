"""
graphiti Kuzu prototype — ingest BRIDGE-bench analyzer runs as episodes.

Validates graphiti on Kuzu backend (no Neo4j) for bi-temporal benchmark
run history. Each results JSON is ingested as a graphiti episode with
timestamped findings.

Usage:
    cd graphiti_prototype && .venv/bin/python ingest_runs.py

Decision: ~/Annunaki/Agent Vault/decisions/Adopt graphiti scoped Kuzu 2026-04-18.md
Scope boundary: ~/Annunaki/Agent Vault/decisions/Memory stack scope boundary — hindsight graphiti keplai 2026-04-18.md
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

# graphiti imports
from graphiti_core import Graphiti
from graphiti_core.driver.kuzu_driver import KuzuDriver
from graphiti_core.nodes import EpisodeType
from graphiti_core.llm_client import OpenAIClient
from graphiti_core.llm_client.config import LLMConfig
from graphiti_core.search.search_filters import (
    SearchFilters,
    DateFilter,
    ComparisonOperator,
)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BIFROST_URL = os.environ.get("BIFROST_URL", "http://localhost:8090/v1")
BIFROST_KEY = os.environ.get("BIFROST_KEY", "sk-bf-dev-interactive")
BIFROST_MODEL = os.environ.get("BRIDGE_MODEL", "anthropic/claude-sonnet-4-20250514")

# Kuzu database path (file-based for persistence across runs)
KUZU_DB_PATH = str(Path(__file__).parent / "kuzu_data")

# Results files to ingest
RESULTS_DIR = Path(__file__).parent.parent
RESULTS_FILES = [
    ("results.json", "2026-04-09", "agent_v2_bridge baseline"),
    ("results_critique_ablation.json", "2026-04-11", "critique ablation head-to-head"),
    ("results_evidence_ladder.json", "2026-04-17", "evidence ladder phase 1"),
]

GROUP_ID = "bridge-bench"


# ---------------------------------------------------------------------------
# Episode body builders
# ---------------------------------------------------------------------------

def build_episode_body(filepath: Path, description: str) -> str:
    """Convert a results JSON into a structured episode body for graphiti."""
    with open(filepath) as f:
        data = json.load(f)

    lines = [f"BRIDGE-bench analyzer run: {description}"]

    # Handle different result file formats
    if "baseline" in data and "with_critique" in data:
        # Critique ablation format
        baseline = data["baseline"]
        treatment = data["with_critique"]
        lines.append(f"Baseline: P={baseline['precision']:.1%} R={baseline['recall']:.1%} F1={baseline['f1']:.1%}")
        lines.append(f"Treatment: P={treatment['precision']:.1%} R={treatment['recall']:.1%} F1={treatment['f1']:.1%}")
        lines.append(f"Delta F1: {data.get('delta_f1', 0):.1%}")

        # Per-contract details from baseline
        for r in baseline.get("results", []):
            lines.append(
                f"Contract {r['contract']}: "
                f"TP={r['tp']} FP={r['fp']} FN={r['fn']} "
                f"findings=[{', '.join(r.get('findings', []))}]"
            )

    elif "baseline" in data and "evidence_gated" in data:
        # Evidence ladder format
        b = data["baseline"]
        g = data["evidence_gated"]
        lines.append(f"Baseline: P={b['precision']:.1%} R={b['recall']:.1%} F1={b['f1']:.1%}")
        lines.append(f"Evidence-gated: P={g['precision']:.1%} R={g['recall']:.1%} F1={g['f1']:.1%}")
        lines.append(f"Delta F1: {data.get('delta_f1', 0):.1%}")
        lines.append(f"Abort: {data.get('abort', False)}")

    else:
        # Generic format — dump key metrics
        for key in ["precision", "recall", "f1", "tp", "fp", "fn"]:
            if key in data:
                lines.append(f"{key}: {data[key]}")

        # Per-contract results if present
        for r in data.get("results", []):
            if isinstance(r, dict) and "contract" in r:
                lines.append(
                    f"Contract {r['contract']}: "
                    f"TP={r.get('tp', '?')} FP={r.get('fp', '?')} FN={r.get('fn', '?')}"
                )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    print("=" * 60)
    print("graphiti Kuzu prototype — BRIDGE-bench episode ingestion")
    print("=" * 60)

    # --- Setup Kuzu driver (file-based, no Neo4j) ---
    # Remove stale Kuzu directory if exists (Kuzu creates its own)
    import shutil
    if Path(KUZU_DB_PATH).is_dir():
        shutil.rmtree(KUZU_DB_PATH)
    kuzu_driver = KuzuDriver(db=KUZU_DB_PATH)

    # --- Setup LLM client via Bifrost ---
    llm_config = LLMConfig(
        api_key=BIFROST_KEY,
        base_url=BIFROST_URL,
        model=BIFROST_MODEL,
        small_model=BIFROST_MODEL,  # Use same model for both
    )
    llm_client = OpenAIClient(config=llm_config)

    print(f"\n  Kuzu DB: {KUZU_DB_PATH}")
    print(f"  LLM via Bifrost: {BIFROST_URL}")
    print(f"  Model: {BIFROST_MODEL}")
    print(f"  Group: {GROUP_ID}")

    # --- Embedder + cross-encoder via Bifrost ---
    # All three LLM components must route through Bifrost.
    from graphiti_core.embedder.openai import OpenAIEmbedder, OpenAIEmbedderConfig
    from graphiti_core.cross_encoder.openai_reranker_client import OpenAIRerankerClient

    # Embeddings: use Ollama nomic-embed-text directly (Bifrost's VK blocks
    # embedding requests). Ollama is local ($0), no gateway bypass concern.
    OLLAMA_URL = "http://localhost:11434/v1"
    embedder = OpenAIEmbedder(config=OpenAIEmbedderConfig(
        api_key="ollama",
        base_url=OLLAMA_URL,
        embedding_model="nomic-embed-text:latest",
    ))
    # Cross-encoder reuses the same LLMConfig as the LLM client
    cross_encoder = OpenAIRerankerClient(config=llm_config)

    # --- Create Graphiti instance ---
    graphiti = Graphiti(
        graph_driver=kuzu_driver,
        llm_client=llm_client,
        embedder=embedder,
        cross_encoder=cross_encoder,
        store_raw_episode_content=True,
    )

    try:
        # Build schema
        print("\n--- Building Kuzu schema ---")
        t0 = time.time()
        await graphiti.build_indices_and_constraints()
        print(f"  Schema built in {time.time() - t0:.2f}s")

        # --- Ingest episodes ---
        print(f"\n--- Ingesting {len(RESULTS_FILES)} episodes ---")
        episode_uuids = []

        for filename, date_str, description in RESULTS_FILES:
            filepath = RESULTS_DIR / filename
            if not filepath.exists():
                print(f"  SKIP: {filename} not found")
                continue

            ref_time = datetime.fromisoformat(f"{date_str}T12:00:00+00:00")
            body = build_episode_body(filepath, description)

            print(f"\n  Ingesting: {filename} ({description})")
            print(f"  Reference time: {ref_time.isoformat()}")
            print(f"  Body length: {len(body)} chars")

            t0 = time.time()
            result = await graphiti.add_episode(
                name=f"bridge-bench-{date_str}",
                episode_body=body,
                source_description=f"BRIDGE-bench {description}",
                reference_time=ref_time,
                source=EpisodeType.text,
                group_id=None,  # Kuzu driver bug: group_id triggers _database attr error
            )
            elapsed = time.time() - t0

            episode_uuids.append(result.episode.uuid)
            print(f"  Extracted: {len(result.nodes)} entities, {len(result.edges)} edges")
            print(f"  Episode UUID: {result.episode.uuid}")
            print(f"  Time: {elapsed:.1f}s")

        # --- Temporal query ---
        print(f"\n--- Temporal query test ---")
        query = "what did agent_v2_bridge believe about WormholeStyle?"
        print(f"  Query: {query}")

        t0 = time.time()
        search_results = await graphiti.search_(
            query=query,
            group_ids=None,
        )
        elapsed = time.time() - t0

        print(f"  Results: {len(search_results.edges)} edges found")
        print(f"  Query time: {elapsed:.2f}s")

        for i, edge in enumerate(search_results.edges[:5]):
            print(f"    [{i}] {edge.fact} (valid_at: {edge.valid_at})")

        # --- Date-filtered query ---
        print(f"\n--- Date-filtered temporal query ---")
        query2 = "BRIDGE-bench analyzer precision and recall"
        date_filter = SearchFilters(
            created_at=[[DateFilter(
                date=datetime(2026, 4, 10, tzinfo=timezone.utc),
                comparison_operator=ComparisonOperator.greater_than_equal,
            )]]
        )
        print(f"  Query: {query2} (created_at >= 2026-04-10)")

        t0 = time.time()
        results2 = await graphiti.search_(
            query=query2,
            search_filter=date_filter,
            group_ids=None,
        )
        elapsed = time.time() - t0

        print(f"  Results: {len(results2.edges)} edges found")
        print(f"  Query time: {elapsed:.2f}s")

        for i, edge in enumerate(results2.edges[:5]):
            print(f"    [{i}] {edge.fact} (valid_at: {edge.valid_at})")

        # --- Summary ---
        print(f"\n" + "=" * 60)
        print("PROTOTYPE SUMMARY")
        print("=" * 60)
        print(f"  Episodes ingested: {len(episode_uuids)}")
        print(f"  Neo4j dependency: NONE (Kuzu in-process)")
        print(f"  Kuzu DB path: {KUZU_DB_PATH}")
        print(f"  LLM calls routed through Bifrost: YES")
        print("=" * 60)

    finally:
        await graphiti.close()


if __name__ == "__main__":
    asyncio.run(main())
