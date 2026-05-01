"""
Shared LLM response parsing utilities for BRIDGE-bench analyzers.

Extracts vulnerability findings from LLM text responses that may be
wrapped in markdown fences, embedded in prose, or returned as raw JSON.

Three-level fallback:
  1. Direct json.loads (cleanest case)
  2. Markdown fence extraction (```json ... ```)
  3. Regex extraction of embedded JSON array or object
"""

from __future__ import annotations

import json
import re
from typing import Any


def parse_llm_findings(text: str) -> list[dict[str, Any]]:
    """Parse vulnerability findings from an LLM response.

    Handles all response shapes seen across BRIDGE-bench analyzers:
      - Raw JSON array: [{"type": ...}, ...]
      - JSON object with "vulnerabilities" key: {"vulnerabilities": [...]}
      - Markdown-fenced JSON (```json ... ```)
      - JSON embedded in prose text

    Returns a list of finding dicts. Each dict has at least a "type" or
    "vuln_type" key (varies by model). Returns [] on parse failure.
    """
    if not text:
        return []

    cleaned = _strip_markdown_fences(text)

    # Level 1: direct parse
    result = _try_parse(cleaned)
    if result is not None:
        return result

    # Level 2: extract JSON array via regex
    match = re.search(r"\[.*\]", cleaned, re.DOTALL)
    if match:
        result = _try_parse(match.group())
        if result is not None:
            return result

    # Level 3: extract JSON object via regex
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        result = _try_parse(match.group())
        if result is not None:
            return result

    return []


def _strip_markdown_fences(text: str) -> str:
    """Remove markdown code fences (```json ... ``` or ``` ... ```)."""
    text = text.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0]
    elif text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
    return text.strip()


def _try_parse(text: str) -> list[dict[str, Any]] | None:
    """Attempt to parse text as JSON and normalize to a findings list.
    Returns None on failure."""
    try:
        data = json.loads(text.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        vulns = data.get("vulnerabilities")
        if isinstance(vulns, list):
            return [item for item in vulns if isinstance(item, dict)]
        # Single finding wrapped in an object — return as one-item list
        if "type" in data or "vuln_type" in data:
            return [data]
    return None
