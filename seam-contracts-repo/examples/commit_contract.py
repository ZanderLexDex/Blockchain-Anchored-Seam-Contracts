#!/usr/bin/env python3
"""Example: Hash a seam contract and commit to BSV blockchain.
Requires: BSV_PRIVATE_KEY env var + funded wallet."""
import asyncio, json, os
from seam_contracts import hash_contract, commit_to_bsv, init_tracking_db, store_contract
from sanitize_engine import verify_contract_text

# Load contract
with open("example_contract.json") as f:
    contracts = json.load(f)
contract = contracts[0]

# 1. Verify text integrity before hashing
integrity = verify_contract_text(contract)
if not integrity["clean"]:
    print(f"⚠️  Contract contains steganographic content in {len(integrity['findings'])} fields")
    print("   Cannot commit. Clean the contract first.")
    exit(1)

# 2. Hash
contract_hash = hash_contract(contract)
print(f"Contract: {contract['contract_id']} v{contract['version']}")
print(f"SHA-256:  {contract_hash}")

# 3. Commit to BSV (uncomment when ready)
# wif = os.environ["BSV_PRIVATE_KEY"]
# source_tx_hex = "YOUR_SOURCE_TX_HEX"  # from a funded UTXO
# tx_id = asyncio.run(commit_to_bsv(contract, wif, source_tx_hex))
# print(f"On-chain: {tx_id}")

# 4. Store locally
# init_tracking_db("agent.db")
# store_contract("agent.db", contract, tx_id)
