"""
Fetch verified contract source code from Etherscan for bridge exploit benchmark.

Usage:
    export ETHERSCAN_API_KEY=your_key
    python fetch_contracts.py

This populates the benchmarks/ directory with real contract source code
that can be fed to the Claude analyzer for evaluation.
"""

import os
import json
import time
import requests
from pathlib import Path

ETHERSCAN_API = "https://api.etherscan.io/api"
BENCHMARK_DIR = Path(__file__).parent.parent / "benchmarks" / "contracts"

# Contracts with verified source on Etherscan
CONTRACTS_TO_FETCH = [
    {
        "name": "wormhole_bridge",
        "address": "0x3ee18B2214AFF97000D974cf647E7C347E8fa585",
        "chain": "ethereum",
        "exploit_date": "2022-02-02",
        "loss_usd": 320_000_000,
        "vuln_type": "signature_verification_bypass",
    },
    {
        "name": "nomad_bridge_replica",
        "address": "0xB92336759618F55bd0F8313bd843604592E27bd8",
        "chain": "ethereum",
        "exploit_date": "2022-08-01",
        "loss_usd": 190_000_000,
        "vuln_type": "default_value_initialization",
    },
    {
        "name": "ronin_bridge",
        "address": "0x1A2a1c938CE3eC39b6D47113c7955bAa9B236945",
        "chain": "ethereum",
        "exploit_date": "2022-03-23",
        "loss_usd": 625_000_000,
        "vuln_type": "validator_key_theft",
    },
]


def fetch_contract_source(address: str, api_key: str) -> dict | None:
    """Fetch verified contract source from Etherscan API."""
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    }

    try:
        resp = requests.get(ETHERSCAN_API, params=params, timeout=30)
        data = resp.json()

        if data["status"] != "1" or not data["result"]:
            print(f"  Failed: {data.get('message', 'Unknown error')}")
            return None

        result = data["result"][0]
        return {
            "contract_name": result.get("ContractName", "Unknown"),
            "source_code": result.get("SourceCode", ""),
            "abi": result.get("ABI", ""),
            "compiler_version": result.get("CompilerVersion", ""),
            "optimization_used": result.get("OptimizationUsed", ""),
            "proxy": result.get("Proxy", "0"),
            "implementation": result.get("Implementation", ""),
        }
    except Exception as e:
        print(f"  Error: {e}")
        return None


def fetch_all_contracts():
    """Fetch all benchmark contracts and save to disk."""
    api_key = os.environ.get("ETHERSCAN_API_KEY", "")
    if not api_key:
        print("WARNING: No ETHERSCAN_API_KEY set.")
        print("Get a free key at https://etherscan.io/apis")
        print("Running in demo mode with placeholder data.\n")

    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)

    for contract in CONTRACTS_TO_FETCH:
        name = contract["name"]
        addr = contract["address"]
        print(f"Fetching {name} ({addr})...")

        if api_key:
            source = fetch_contract_source(addr, api_key)
            time.sleep(0.25)  # Rate limit: 5 req/sec
        else:
            source = None

        # Save metadata + source
        output = {
            **contract,
            "source": source,
            "fetched": source is not None,
        }

        output_path = BENCHMARK_DIR / f"{name}.json"
        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        if source:
            # Also save raw .sol file for easy reading
            sol_path = BENCHMARK_DIR / f"{name}.sol"
            sol_source = source["source_code"]
            # Handle multi-file contracts (Etherscan returns JSON)
            if sol_source.startswith("{"):
                try:
                    files = json.loads(sol_source)
                    if "sources" in files:
                        sol_source = "\n\n".join(
                            f"// File: {fname}\n{fdata['content']}"
                            for fname, fdata in files["sources"].items()
                        )
                except json.JSONDecodeError:
                    pass
            with open(sol_path, "w") as f:
                f.write(sol_source)
            print(f"  ✓ Saved {sol_path.name} ({len(sol_source)} chars)")
        else:
            print(f"  ⚠ No source fetched (set ETHERSCAN_API_KEY)")

    print(f"\nContracts saved to {BENCHMARK_DIR}/")


def analyze_benchmark_contracts():
    """
    Run the Claude analyzer against all fetched contracts.
    Requires: ANTHROPIC_API_KEY environment variable.
    """
    from ai_security.agents.claude_analyzer import (
        analyze_with_claude,
        static_prescreen,
        format_report,
    )

    for json_file in sorted(BENCHMARK_DIR.glob("*.json")):
        with open(json_file) as f:
            data = json.load(f)

        if not data.get("fetched"):
            print(f"Skipping {data['name']} (no source code)")
            continue

        source = data["source"]["source_code"]
        name = data["name"]

        print(f"\nAnalyzing {name}...")
        static = static_prescreen(source)
        report = analyze_with_claude(source, name, static)
        print(format_report(report))


if __name__ == "__main__":
    fetch_all_contracts()
