# graphiti Kuzu Prototype — BRIDGE-bench Temporal KG

Validates graphiti (Zep AI, Apache 2.0) on Kuzu backend (no Neo4j) for
bi-temporal benchmark run history.

## Status: VALIDATED ✓

3 episodes ingested, 2 temporal queries answered. Zero Neo4j dependency.

### Results

| Episode | Content | Entities | Edges | Time |
|---------|---------|----------|-------|------|
| results.json (2026-04-09) | baseline | 2 | 1 | 31.9s |
| results_critique_ablation.json (2026-04-11) | critique head-to-head | 23 | 22 | 40.5s |
| results_evidence_ladder.json (2026-04-17) | evidence ladder | 5 | 2 | 8.4s |

Temporal query "what did agent_v2_bridge believe about WormholeStyle?" returned
10 edges with correct `valid_at` timestamps, including facts from the 2026-04-11
critique ablation run.

Date-filtered query (created_at >= 2026-04-10) correctly excluded the 2026-04-09
baseline from primary results.

## Install

```bash
cd graphiti_prototype
python -m venv .venv
.venv/bin/pip install "graphiti-core[kuzu]"
```

## Config

All LLM calls route through Bifrost (localhost:8090). Embeddings use Ollama
directly (localhost:11434) because Bifrost's dev VK blocks embedding requests.

```
BIFROST_URL=http://localhost:8090/v1  # LLM entity extraction
BIFROST_KEY=sk-bf-dev-interactive
BRIDGE_MODEL=openai/gpt-4o-mini      # Must support Responses API ($defs)
Ollama: localhost:11434               # nomic-embed-text for embeddings
```

**Model constraint:** graphiti uses OpenAI's Responses API (`client.responses.parse`)
with JSON Schema `$defs`. Anthropic via Bifrost does NOT support `$defs` references.
Must use an OpenAI model (gpt-4o-mini recommended).

## Run

```bash
BIFROST_URL=http://localhost:8090/v1 \
BIFROST_KEY=sk-bf-dev-interactive \
BRIDGE_MODEL=openai/gpt-4o-mini \
.venv/bin/python ingest_runs.py
```

## Kuzu-Specific Gotchas

1. **FTS indices not created by driver** — graphiti's KuzuDriver.build_indices_and_constraints()
   is a no-op. The FTS indices defined in graph_queries.py are never called.
   **Workaround:** manually call `CREATE_FTS_INDEX` for all 4 tables after schema
   init (see `ingest_runs.py` lines 171-185). File upstream issue.
2. **`group_id` parameter** — triggers `AttributeError: 'KuzuDriver' object
   has no attribute '_database'`. Workaround: pass `group_id=None`.
3. **DB path** — Kuzu expects a file path, not a directory. `KuzuDriver(db="path")`
   creates the directory itself.
4. **Responses API** — graphiti uses `client.responses.parse()` which requires
   OpenAI's Responses API. Anthropic via Bifrost returns schema validation errors
   (`$defs/ExtractedEntity`). Use `openai/gpt-4o-mini` not Anthropic.

## Benchmark Notes

- Schema + FTS index build: 0.80s
- Episode ingestion: 8-41s per episode (LLM-bound, depends on content size)
- Temporal query: 1.4-2.4s (includes embedding + graph traversal)
- Memory: Kuzu in-process, ~50MB for 3 episodes with 30 entities
- Kuzu DB on disk: ~2MB for this prototype

## Next Steps

- File upstream issue on graphiti-core for missing Kuzu FTS index creation
- Evaluate graphiti MCP server integration with BRIDGE-bench dashboard
- Ingest full run history (all results*.json + APO results) as episodes

## Decision Context

- Adoption: ~/Annunaki/Agent Vault/decisions/Adopt graphiti scoped Kuzu 2026-04-18.md
- Scope boundary: ~/Annunaki/Agent Vault/decisions/Memory stack scope boundary — hindsight graphiti keplai 2026-04-18.md
