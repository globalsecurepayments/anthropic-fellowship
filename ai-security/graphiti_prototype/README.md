# graphiti Kuzu Prototype — BRIDGE-bench Temporal KG

Validates graphiti (Zep AI, Apache 2.0) on Kuzu backend (no Neo4j) for
bi-temporal benchmark run history.

## Status: BLOCKED

**Blocker:** graphiti's Kuzu driver does not create full-text search (FTS)
indices during `build_indices_and_constraints()`. The FTS index
`node_name_and_summary` on the `Entity` table is required for entity
resolution during `add_episode()`. Without it, the core ingestion pipeline
fails with:

```
RuntimeError: Binder exception: Table Entity doesn't have an index with
name node_name_and_summary.
```

This is a graphiti-internal issue (Kuzu driver schema initialization is
incomplete relative to what the search module expects). Neo4j backend
likely creates the equivalent indices correctly.

### What Works

- Kuzu driver initializes correctly (schema tables created)
- LLM entity extraction via Bifrost (gpt-4o-mini) works
- Embeddings via Ollama nomic-embed-text work
- Zero Neo4j dependency confirmed

### What Doesn't Work

- FTS indices not created → entity resolution fails → `add_episode()` crashes
- `group_id` parameter triggers `_database` attribute error (separate bug)

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

1. **FTS indices not created** — BLOCKER. See status above.
2. **`group_id` parameter** — triggers `AttributeError: 'KuzuDriver' object
   has no attribute '_database'`. Workaround: pass `group_id=None`.
3. **DB path** — Kuzu expects a file path, not a directory. `KuzuDriver(db="path")`
   creates the directory itself.
4. **Responses API** — graphiti uses `client.responses.parse()` which requires
   OpenAI's Responses API. Anthropic via Bifrost returns schema validation errors
   (`$defs/ExtractedEntity`). Use `openai/gpt-4o-mini` not Anthropic.

## Next Steps (if FTS blocker is resolved)

- File a GitHub issue on graphiti-core for missing Kuzu FTS index creation
- OR: manually create the FTS index before calling `add_episode()`
- OR: use graphiti from source (`pip install -e ~/Annunaki/github-sources/graphiti[kuzu]`)
  and patch the Kuzu driver's schema queries

## Decision Context

- Adoption: ~/Annunaki/Agent Vault/decisions/Adopt graphiti scoped Kuzu 2026-04-18.md
- Scope boundary: ~/Annunaki/Agent Vault/decisions/Memory stack scope boundary — hindsight graphiti keplai 2026-04-18.md
