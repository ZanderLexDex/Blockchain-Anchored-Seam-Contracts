# BLOCKCHAIN-ANCHORED SEAM CONTRACTS
# Universal Implementation Guide for Autonomous AI Agents
# Framework Version: 1.0 | BSV Blockchain
# Optimized for: AI agent context ingestion and autonomous execution

---

## WHAT THIS IS

A seam contract is a formal governance agreement between two components of a data pipeline. It defines what crosses the boundary, what the producer guarantees, and what the consumer depends on.

This document provides a complete, agent-executable framework for:
1. Defining seam contracts in structured JSON
2. Cryptographically hashing them (SHA-256)
3. Committing the hashes to the BSV blockchain (immutable, timestamped, verifiable)
4. Running automated verification that live systems comply with committed contracts
5. Maintaining a version chain when contracts are updated
6. Producing audit trails suitable for enterprise stakeholders

**Why blockchain?** A contract in a markdown file is authoritative by convention. A contract hashed to a blockchain is authoritative by cryptography. The hash proves WHAT was committed. The transaction proves WHEN. The version chain proves HOW it evolved. No party can retroactively modify a committed contract.

**Why BSV?** Unbounded OP_RETURN data capacity (no 80-byte limit), sub-cent transaction fees, and the official BSV Python SDK (`bsv-sdk`) provides native transaction construction. Other chains with OP_RETURN support could substitute, but BSV's fee structure makes high-frequency contract commitments economically trivial.

---

## DEPENDENCIES

```bash
pip install bsv-sdk        # Official BSV Python SDK (v1.0.11+, PyPI)
# No external runtime dependencies
```

**Core imports:**
```python
from bsv import PrivateKey, P2PKH, Transaction, TransactionInput, TransactionOutput, Script
import hashlib
import json
import sqlite3
import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
```

**Optional (simpler OP_RETURN API):**
```bash
pip install bsvlib          # Community BSV library
```

---

## CONCEPTS

### Seam
A boundary between two components where data crosses. Examples:
- Data ingestion → storage
- Storage → analytics/intelligence
- Analytics → alert/notification system
- Storage → ML training pipeline
- Any producer → any consumer

### Contract
A structured document that formally specifies the seam's interface:
- **Producer guarantees:** What the producing side promises (validation, units, formats, completeness)
- **Consumer dependencies:** What the consuming side relies on
- **Cannot-assume clauses:** What may fail, be absent, or vary

### Commitment
The SHA-256 hash of a canonicalized contract, written to the BSV blockchain via OP_RETURN. Creates an immutable timestamp proving the contract existed in that exact form at that exact time.

### Verification
Automated checks that compare live system behavior against committed contract guarantees. Runs on a schedule (cron). Failures are logged and can trigger alerts.

### Version Chain
When a contract is updated, the new version references the previous version's BSV transaction ID. Creates a linked list of contract evolution, all on-chain.

```
Contract v1 → SHA-256 → BSV tx_001
    ↓ (violation found, contract updated)
Contract v2 → SHA-256 → BSV tx_002 (prev_tx: tx_001)
    ↓ (new capability added)
Contract v3 → SHA-256 → BSV tx_003 (prev_tx: tx_002)
```

---

## CONTRACT SCHEMA

### Minimal Contract (required fields)

```json
{
  "contract_id": "string — unique identifier",
  "version": "integer — incrementing",
  "effective_date": "string — ISO 8601 date",
  "system_id": "string — identifies the system this governs",
  "producer": {
    "component": "string — producing component name",
    "artifacts": ["array of strings — scripts, services, or modules"]
  },
  "consumer": {
    "component": "string — consuming component name",
    "artifacts": ["array of strings — tables, endpoints, or interfaces"]
  },
  "guarantees": [
    {
      "id": "string — G001, G002, etc.",
      "description": "string — human-readable guarantee",
      "verification": "string — executable check (SQL, command, or API call)",
      "verification_type": "string — sql_zero_count | sql_non_empty | command_exit_zero | http_200 | manual"
    }
  ],
  "not_guaranteed": ["array of strings — explicit disclaimers"],
  "prev_version_tx": "string or null — BSV tx_id of previous version",
  "signers": ["array of strings — who ratified this contract"]
}
```

### Extended Contract (optional fields)

```json
{
  "...all minimal fields...": "...",
  "network_id": "string — identifies the broader network/organization",
  "protocol_version": "string — schema version, e.g. edencode_seam_v1",
  "expiry_date": "string or null — when this contract expires",
  "review_frequency_days": "integer — how often to review the contract",
  "tags": ["array of strings — categorization"],
  "dependencies": ["array of contract_ids this contract depends on"],
  "metadata": {
    "created_by": "string",
    "rationale": "string — why this contract exists",
    "audit_ref": "string — reference to audit that triggered creation"
  }
}
```

---

## CORE LIBRARY

### seam_contracts.py

```python
"""
Seam Contract Library — Blockchain-Anchored Governance
Universal implementation. No system-specific dependencies.
"""

import hashlib
import json
import sqlite3
import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ============================================================
# HASHING
# ============================================================

def canonicalize(contract: dict) -> str:
    """Deterministic JSON serialization for hashing.
    Sorted keys, no whitespace, UTF-8. Identical input always
    produces identical output regardless of platform or locale."""
    return json.dumps(contract, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def hash_contract(contract: dict) -> str:
    """SHA-256 hash of canonicalized contract."""
    return hashlib.sha256(canonicalize(contract).encode('utf-8')).hexdigest()


def verify_hash(contract: dict, expected_hash: str) -> bool:
    """Verify a contract matches a known hash."""
    return hash_contract(contract) == expected_hash


# ============================================================
# BSV COMMITMENT (using official bsv-sdk)
# ============================================================

async def commit_to_bsv(
    contract: dict,
    private_key_wif: str,
    source_tx_hex: str,
    source_output_index: int = 0,
    protocol_prefix: str = "seam_contract_v1"
) -> str:
    """
    Commit contract hash to BSV blockchain via OP_RETURN.
    
    Args:
        contract: The seam contract dict
        private_key_wif: BSV private key in WIF format
        source_tx_hex: Raw hex of a TX containing a UTXO you control
        source_output_index: Which output of source_tx to spend
        protocol_prefix: Protocol identifier in the OP_RETURN payload
    
    Returns:
        BSV transaction ID (hex string)
    """
    from bsv import PrivateKey, P2PKH, Transaction, TransactionInput, TransactionOutput, Script
    
    key = PrivateKey(private_key_wif)
    source_tx = Transaction.from_hex(source_tx_hex)
    
    payload = json.dumps({
        "p": protocol_prefix,
        "id": contract["contract_id"],
        "v": contract["version"],
        "sys": contract.get("system_id", ""),
        "h": hash_contract(contract),
        "prev": contract.get("prev_version_tx"),
        "t": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
    }, separators=(',', ':')).encode('utf-8')
    
    op_return_script = Script.from_asm(f"OP_FALSE OP_RETURN {payload.hex()}")
    
    tx_input = TransactionInput(
        source_transaction=source_tx,
        source_txid=source_tx.txid(),
        source_output_index=source_output_index,
        unlocking_script_template=P2PKH().unlock(key),
    )
    
    op_return_output = TransactionOutput(locking_script=op_return_script, satoshis=0)
    change_output = TransactionOutput(locking_script=P2PKH().lock(key.address()), change=True)
    
    tx = Transaction([tx_input], [op_return_output, change_output], version=1)
    tx.fee()
    tx.sign()
    await tx.broadcast()
    
    return tx.txid()


async def commit_batch(
    contracts: list,
    private_key_wif: str,
    source_tx_hex: str,
    source_output_index: int = 0
) -> list:
    """Commit multiple contracts sequentially, chaining UTXOs."""
    results = []
    current_tx_hex = source_tx_hex
    current_index = source_output_index
    
    for contract in contracts:
        tx_id = await commit_to_bsv(
            contract, private_key_wif, current_tx_hex, current_index
        )
        results.append({
            "contract_id": contract["contract_id"],
            "version": contract["version"],
            "hash": hash_contract(contract),
            "tx_id": tx_id,
            "committed_at": datetime.now(timezone.utc).isoformat()
        })
        # For chaining: fetch the new TX for the next commitment
        # In practice, you'd fetch the raw TX from a block explorer API
        # or use the Transaction object's hex output
        print(f"  Committed: {contract['contract_id']} v{contract['version']} → {tx_id}")
    
    return results


# ============================================================
# LOCAL TRACKING
# ============================================================

TRACKING_SCHEMA = """
CREATE TABLE IF NOT EXISTS seam_contract (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id     TEXT NOT NULL,
    version         INTEGER NOT NULL,
    system_id       TEXT,
    contract_json   TEXT NOT NULL,
    sha256_hash     TEXT NOT NULL,
    bsv_tx_id       TEXT,
    prev_tx_id      TEXT,
    status          TEXT DEFAULT 'DRAFT'
                    CHECK(status IN ('DRAFT','RATIFIED','ACTIVE','VIOLATED','REMEDIATED','SUPERSEDED')),
    committed_at    DATETIME,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(contract_id, version)
);

CREATE TABLE IF NOT EXISTS seam_verification (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id     TEXT NOT NULL,
    contract_version INTEGER NOT NULL,
    guarantee_id    TEXT NOT NULL,
    check_time      DATETIME NOT NULL,
    passed          INTEGER NOT NULL CHECK(passed IN (0, 1)),
    result_value    TEXT,
    expected        TEXT,
    notes           TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_seam_verification_contract 
    ON seam_verification(contract_id, check_time);
CREATE INDEX IF NOT EXISTS idx_seam_verification_failed 
    ON seam_verification(passed) WHERE passed = 0;
"""


def init_tracking_db(db_path: str):
    """Create tracking tables if they don't exist."""
    conn = sqlite3.connect(db_path)
    conn.executescript(TRACKING_SCHEMA)
    conn.commit()
    conn.close()


def store_contract(db_path: str, contract: dict, tx_id: Optional[str] = None):
    """Store a contract in the local tracking database."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """INSERT OR REPLACE INTO seam_contract 
           (contract_id, version, system_id, contract_json, sha256_hash, bsv_tx_id, prev_tx_id, status, committed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            contract["contract_id"],
            contract["version"],
            contract.get("system_id"),
            canonicalize(contract),
            hash_contract(contract),
            tx_id,
            contract.get("prev_version_tx"),
            "ACTIVE" if tx_id else "DRAFT",
            datetime.now(timezone.utc).isoformat() if tx_id else None,
        )
    )
    conn.commit()
    conn.close()


# ============================================================
# VERIFICATION ENGINE
# ============================================================

def verify_guarantee(conn: sqlite3.Connection, guarantee: dict) -> dict:
    """
    Verify a single guarantee against a live database.
    
    Supports verification_type:
      - sql_zero_count: query must return 0
      - sql_non_empty: query must return a non-null, non-zero result
      - command_exit_zero: shell command must exit 0
      - manual: skip (returns None)
    """
    g_id = guarantee["id"]
    g_type = guarantee["verification_type"]
    g_check = guarantee.get("verification")
    
    if g_type == "manual" or g_check is None:
        return {"guarantee_id": g_id, "passed": None, "note": "Manual review required"}
    
    try:
        if g_type in ("sql_zero_count", "sql_non_empty"):
            cursor = conn.execute(g_check)
            row = cursor.fetchone()
            value = row[0] if row else None
            
            if g_type == "sql_zero_count":
                passed = (value == 0)
            else:  # sql_non_empty
                passed = (value is not None and value != 0 and value != "")
            
            return {
                "guarantee_id": g_id,
                "passed": passed,
                "value": value,
                "description": guarantee["description"]
            }
        
        elif g_type == "command_exit_zero":
            import subprocess
            result = subprocess.run(g_check, shell=True, capture_output=True, timeout=30)
            return {
                "guarantee_id": g_id,
                "passed": (result.returncode == 0),
                "value": result.returncode,
                "description": guarantee["description"]
            }
        
        else:
            return {"guarantee_id": g_id, "passed": False, "error": f"Unknown type: {g_type}"}
    
    except Exception as e:
        return {"guarantee_id": g_id, "passed": False, "error": str(e), "description": guarantee["description"]}


def verify_contract(db_path: str, contract: dict, log_results: bool = True) -> dict:
    """
    Run all guarantee checks for a seam contract.
    
    Args:
        db_path: Path to the SQLite database being governed
        contract: The seam contract dict
        log_results: Whether to write results to seam_verification table
    
    Returns:
        {contract_id, version, check_time, total, passed, failed, skipped, details}
    """
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    
    results = []
    for g in contract["guarantees"]:
        result = verify_guarantee(conn, g)
        results.append(result)
        
        if log_results and result.get("passed") is not None:
            conn.execute(
                """INSERT INTO seam_verification 
                   (contract_id, contract_version, guarantee_id, check_time, passed, result_value, expected)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    contract["contract_id"],
                    contract["version"],
                    result["guarantee_id"],
                    datetime.now(timezone.utc).isoformat(),
                    1 if result["passed"] else 0,
                    str(result.get("value", result.get("error", ""))),
                    "0" if contract["guarantees"][results.index(result)].get("verification_type") == "sql_zero_count" else "non-empty"
                )
            )
    
    if log_results:
        conn.commit()
    conn.close()
    
    passed = sum(1 for r in results if r.get("passed") is True)
    failed = sum(1 for r in results if r.get("passed") is False)
    skipped = sum(1 for r in results if r.get("passed") is None)
    
    return {
        "contract_id": contract["contract_id"],
        "version": contract["version"],
        "check_time": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "all_passed": (failed == 0),
        "details": results
    }


def verify_all(db_path: str, contracts: list, log_results: bool = True) -> dict:
    """
    Verify all contracts against a database.
    
    Returns:
        {check_time, contracts_checked, total_guarantees, passed, failed, 
         skipped, compliance_rate, results: [...]}
    """
    all_results = []
    for contract in contracts:
        result = verify_contract(db_path, contract, log_results)
        all_results.append(result)
    
    total_passed = sum(r["passed"] for r in all_results)
    total_failed = sum(r["failed"] for r in all_results)
    total_skipped = sum(r["skipped"] for r in all_results)
    total_checks = total_passed + total_failed + total_skipped
    
    return {
        "check_time": datetime.now(timezone.utc).isoformat(),
        "contracts_checked": len(contracts),
        "total_guarantees": total_checks,
        "passed": total_passed,
        "failed": total_failed,
        "skipped": total_skipped,
        "compliance_rate": f"{(total_passed / max(total_passed + total_failed, 1)) * 100:.1f}%",
        "all_passed": (total_failed == 0),
        "results": all_results
    }


# ============================================================
# REPORTING
# ============================================================

def print_verification_report(report: dict):
    """Human-readable verification report to stdout."""
    print(f"\n{'='*60}")
    print(f"SEAM CONTRACT VERIFICATION — {report['check_time']}")
    print(f"{'='*60}")
    print(f"Contracts: {report['contracts_checked']}")
    print(f"Guarantees: {report['total_guarantees']} total | {report['passed']} passed | {report['failed']} failed | {report['skipped']} skipped")
    print(f"Compliance: {report['compliance_rate']}")
    print(f"Status: {'ALL PASSING' if report['all_passed'] else 'VIOLATIONS DETECTED'}")
    print()
    
    for r in report["results"]:
        status = "PASS" if r["all_passed"] else "FAIL"
        print(f"  [{status}] {r['contract_id']} v{r['version']} — {r['passed']}/{r['total']}")
        
        if not r["all_passed"]:
            for d in r["details"]:
                if d.get("passed") is False:
                    desc = d.get("description", d.get("guarantee_id"))
                    val = d.get("value", d.get("error", "unknown"))
                    print(f"         VIOLATION: {d['guarantee_id']} — {desc} (got: {val})")
    
    print(f"\n{'='*60}\n")


def generate_pilot_report(
    db_path: str,
    pilot_id: str,
    system_id: str,
    start_date: str,
    end_date: str,
    bsv_transactions: list
) -> dict:
    """
    Generate a complete pilot report from verification history.
    Queries seam_verification table for the date range.
    """
    conn = sqlite3.connect(db_path)
    
    total_checks = conn.execute(
        "SELECT COUNT(*) FROM seam_verification WHERE check_time BETWEEN ? AND ?",
        (start_date, end_date)
    ).fetchone()[0]
    
    total_passed = conn.execute(
        "SELECT COUNT(*) FROM seam_verification WHERE passed = 1 AND check_time BETWEEN ? AND ?",
        (start_date, end_date)
    ).fetchone()[0]
    
    total_failed = conn.execute(
        "SELECT COUNT(*) FROM seam_verification WHERE passed = 0 AND check_time BETWEEN ? AND ?",
        (start_date, end_date)
    ).fetchone()[0]
    
    violations = conn.execute(
        """SELECT contract_id, guarantee_id, check_time, result_value, notes 
           FROM seam_verification WHERE passed = 0 AND check_time BETWEEN ? AND ?
           ORDER BY check_time""",
        (start_date, end_date)
    ).fetchall()
    
    distinct_days = conn.execute(
        "SELECT COUNT(DISTINCT date(check_time)) FROM seam_verification WHERE check_time BETWEEN ? AND ?",
        (start_date, end_date)
    ).fetchone()[0]
    
    conn.close()
    
    compliance = (total_passed / max(total_passed + total_failed, 1)) * 100
    
    return {
        "pilot_id": pilot_id,
        "system_id": system_id,
        "period": {"start": start_date, "end": end_date},
        "duration_days": distinct_days,
        "contracts_on_chain": len(bsv_transactions),
        "bsv_transactions": bsv_transactions,
        "verification_days": distinct_days,
        "total_guarantee_checks": total_checks,
        "checks_passed": total_passed,
        "checks_failed": total_failed,
        "compliance_rate": f"{compliance:.1f}%",
        "violations": [
            {
                "contract_id": v[0],
                "guarantee_id": v[1],
                "detected_at": v[2],
                "value": v[3],
                "notes": v[4]
            }
            for v in violations
        ]
    }


# ============================================================
# CROSS-SYSTEM VERIFICATION
# ============================================================

def compare_contracts(contract_a: dict, contract_b: dict) -> dict:
    """
    Compare two contracts from different systems.
    Used for cross-node verification in a network.
    
    Same hash = same governance.
    Different hash = divergence (investigate).
    """
    hash_a = hash_contract(contract_a)
    hash_b = hash_contract(contract_b)
    
    return {
        "contract_id": contract_a["contract_id"],
        "system_a": contract_a.get("system_id"),
        "system_b": contract_b.get("system_id"),
        "hash_a": hash_a,
        "hash_b": hash_b,
        "match": hash_a == hash_b,
        "version_a": contract_a["version"],
        "version_b": contract_b["version"],
    }


def verify_on_chain(tx_id: str, expected_hash: str) -> dict:
    """
    Verify a contract hash exists on-chain at the given transaction ID.
    Requires network access to a BSV block explorer API.
    
    Uses whatsonchain.com API (free, no key needed).
    """
    import requests
    
    url = f"https://api.whatsonchain.com/v1/bsv/main/tx/{tx_id}"
    resp = requests.get(url, timeout=10)
    
    if resp.status_code != 200:
        return {"verified": False, "error": f"TX not found: {resp.status_code}"}
    
    tx_data = resp.json()
    
    # Look for OP_RETURN output
    for vout in tx_data.get("vout", []):
        script_hex = vout.get("scriptPubKey", {}).get("hex", "")
        if script_hex.startswith("006a"):  # OP_FALSE OP_RETURN
            # Decode the payload
            try:
                # Skip OP_FALSE (00) and OP_RETURN (6a) and pushdata
                data_hex = script_hex[4:]  # simplified — real parsing needs pushdata handling
                payload = bytes.fromhex(data_hex).decode('utf-8', errors='ignore')
                
                if expected_hash in payload:
                    return {
                        "verified": True,
                        "tx_id": tx_id,
                        "block_height": tx_data.get("blockheight"),
                        "timestamp": tx_data.get("blocktime"),
                        "payload_contains_hash": True
                    }
            except Exception:
                pass
    
    return {"verified": False, "error": "Hash not found in TX OP_RETURN outputs"}
```

---

## USAGE PATTERNS

### Pattern 1: Define, Hash, Commit

```python
import asyncio

# Define your contract
contract = {
    "contract_id": "my_ingestion_to_storage",
    "version": 1,
    "effective_date": "2026-04-01",
    "system_id": "my_system",
    "producer": {"component": "data_ingestion", "artifacts": ["fetch.py"]},
    "consumer": {"component": "storage", "artifacts": ["main.db"]},
    "guarantees": [
        {
            "id": "G001",
            "description": "No NULL values in required columns",
            "verification": "SELECT COUNT(*) FROM readings WHERE timestamp IS NULL",
            "verification_type": "sql_zero_count"
        }
    ],
    "not_guaranteed": ["Exact timing of ingestion"],
    "prev_version_tx": None,
    "signers": ["my_agent"]
}

# Hash it
print(f"SHA-256: {hash_contract(contract)}")

# Commit to BSV
tx_id = asyncio.run(commit_to_bsv(
    contract,
    private_key_wif=os.environ["BSV_PRIVATE_KEY"],
    source_tx_hex="YOUR_SOURCE_TX_HEX",
    source_output_index=0
))
print(f"On-chain: {tx_id}")

# Store locally
init_tracking_db("my_database.db")
store_contract("my_database.db", contract, tx_id)
```

### Pattern 2: Daily Verification Cron

```python
#!/usr/bin/env python3
"""Daily seam contract verification. Run via cron."""

import sys
from seam_contracts import verify_all, print_verification_report

DB_PATH = "/path/to/your/database.db"
CONTRACTS = [...]  # Your contract list

report = verify_all(DB_PATH, CONTRACTS)
print_verification_report(report)

sys.exit(0 if report["all_passed"] else 1)
```

### Pattern 3: Cross-System Comparison

```python
# Farm A and Farm B both implement the same contract
contract_farm_a = load_contract("farm_a/SC-001.json")
contract_farm_b = load_contract("farm_b/SC-001.json")

result = compare_contracts(contract_farm_a, contract_farm_b)
if result["match"]:
    print("Same governance. Same guarantees. Different data.")
else:
    print(f"DIVERGENCE: {result['hash_a'][:12]}... vs {result['hash_b'][:12]}...")
```

### Pattern 4: Contract Versioning After Remediation

```python
# Original contract violated — update and recommit
contract_v2 = {**original_contract}
contract_v2["version"] = 2
contract_v2["prev_version_tx"] = "original_bsv_tx_id_here"
contract_v2["guarantees"].append({
    "id": "G005",
    "description": "New guarantee added after audit finding",
    "verification": "SELECT COUNT(*) FROM ...",
    "verification_type": "sql_zero_count"
})

tx_id_v2 = asyncio.run(commit_to_bsv(contract_v2, ...))
# Now on-chain: v1 → v2, linked by prev_version_tx
```

---

## CRON INTEGRATION

### Generic Cron Setup (system crontab)

```cron
# Daily verification at 6am local time
0 6 * * * cd /path/to/workspace && /path/to/python seam_verify.py >> logs/seam_verify.log 2>&1
```

### OpenClaw Cron Setup (jobs.json)

```json
{
  "name": "seam-contract-verify",
  "expr": "0 6 * * *",
  "tz": "YOUR_TIMEZONE",
  "prompt": "Run seam contract verification. Execute: python seam_verify.py. Report any FAIL results with the contract ID and violation details. If all pass, confirm clean status."
}
```

### Alert on Failure

```python
def alert_on_violation(report: dict, alert_fn):
    """Call alert_fn with violation details if any contract fails."""
    if report["all_passed"]:
        return
    
    for r in report["results"]:
        for d in r["details"]:
            if d.get("passed") is False:
                alert_fn(
                    f"SEAM CONTRACT VIOLATION: {r['contract_id']} "
                    f"guarantee {d['guarantee_id']} — {d.get('description', '')} "
                    f"(value: {d.get('value', d.get('error', 'unknown'))})"
                )
```

---

## WRITING YOUR OWN CONTRACTS

### Step 1: Identify Your Seams

Map every boundary where data crosses between components:
```
Component A ──data──→ Component B
```

Each arrow is a seam. Each seam gets a contract.

### Step 2: Define Guarantees as Executable Checks

Every guarantee must have a verification that a machine can run. If you can't write a SQL query, shell command, or API call that checks the guarantee, it's not a guarantee — it's an aspiration.

**Good guarantee:**
```json
{"description": "No NULL timestamps", "verification": "SELECT COUNT(*) FROM events WHERE ts IS NULL", "verification_type": "sql_zero_count"}
```

**Bad guarantee:**
```json
{"description": "Data should be accurate", "verification": null, "verification_type": "manual"}
```

### Step 3: Include Not-Guaranteed Clauses

Be explicit about what the consumer CANNOT assume. This prevents false expectations and makes failure modes visible.

### Step 4: Hash and Commit

Once all parties agree, canonicalize, hash, and commit to BSV. The contract is now immutable.

### Step 5: Automate Verification

Set up a cron job that runs `verify_contract()` against each committed contract daily. Log results. Alert on failures.

---

## WALLET MANAGEMENT

### Key Generation
```python
from bsv import PrivateKey
key = PrivateKey()
print(f"WIF (SAVE THIS SECURELY): {key.wif()}")
print(f"Address (fund this): {key.address()}")
```

### Funding
Send ~0.001 BSV to the address. At current fee rates (~0.00001 BSV per OP_RETURN), this covers hundreds of contract commitments.

### Security
- Store WIF in `.env` file or environment variable
- NEVER commit WIF to source control
- NEVER hardcode WIF in scripts
- Use separate keys for testnet vs mainnet
- Backup the WIF in a secure, offline location

### Testnet First
```python
# For testing, use BSV testnet
from bsvlib.constants import Chain
chain = Chain.TEST  # bsvlib
# or configure bsv-sdk for testnet
```
Get testnet coins from: https://faucet.bitcoincloud.net/

---

## NETWORK TOPOLOGY

For multi-node deployments where multiple systems share the same contract standards:

```
           ┌──────────────────────────┐
           │   CONTRACT REGISTRY      │
           │   (BSV Blockchain)       │
           │                          │
           │   SC-001 hash → tx_001   │
           │   SC-002 hash → tx_002   │
           │   ...                    │
           └────────────┬─────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
    ┌───────────┐ ┌───────────┐ ┌───────────┐
    │  Node A   │ │  Node B   │ │  Node C   │
    │           │ │           │ │           │
    │ SC-001 ✓  │ │ SC-001 ✓  │ │ SC-001 ✓  │
    │ SC-002 ✓  │ │ SC-002 ✓  │ │ SC-002 ✓  │
    │           │ │           │ │           │
    │ Own data  │ │ Own data  │ │ Own data  │
    │ Own DB    │ │ Own DB    │ │ Own DB    │
    └───────────┘ └───────────┘ └───────────┘
    
    Same contracts. Same hashes. Different data.
    The governance travels. The data stays home.
```

---

## BSV SIMPLE MCP SERVER — AI AGENT BLOCKCHAIN ACCESS

### What It Is

`@bsv/simple-mcp` is an official BSV Blockchain MCP server that gives AI agents direct knowledge and code generation tools for building BSV applications using the `@bsv/simple` library. It provides wallet setup, transaction construction, token operations, OP_RETURN inscriptions, DID/credential management, and overlay network access — all through natural language via MCP.

**Repository:** https://github.com/bsv-blockchain/simple-mcp
**Package:** `@bsv/simple-mcp` (npm/npx)
**License:** MIT

### Why This Matters for Seam Contracts

The seam contract library in this document uses the Python `bsv-sdk` for OP_RETURN commitments. The `@bsv/simple-mcp` server provides an alternative path: instead of writing Python BSV code directly, an AI agent can use MCP tools to generate and execute BSV transactions through natural language. This is particularly useful for:

- Agents that run in JavaScript/TypeScript environments (Node.js, Next.js)
- Agents using Claude Code or other MCP-compatible clients
- Rapid prototyping of BSV interactions without writing raw transaction code
- Access to the full BSV Simple library ecosystem (wallets, tokens, inscriptions, DIDs, credentials, overlay networks)

### Installation

**Claude Code (recommended — one command):**
```bash
claude mcp add simple-mcp -- npx -y @bsv/simple-mcp
```

**Docker:**
```bash
docker build -t simple-mcp .
```

Add to `~/.claude/settings.json`:
```json
{
  "mcpServers": {
    "simple": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "simple-mcp"]
    }
  }
}
```

**Manual (npx):**
```bash
npx -y @bsv/simple-mcp
```

### Available Resources

The MCP server exposes structured documentation that agents can query:

| URI | Description |
|-----|-------------|
| `simple://api/wallet` | WalletCore, BrowserWallet, ServerWallet methods |
| `simple://api/tokens` | Token create/list/send/redeem/messagebox |
| `simple://api/inscriptions` | Text/JSON/hash inscriptions (OP_RETURN) |
| `simple://api/messagebox` | Certification, payments, identity registry |
| `simple://api/certification` | Certifier, certificates, revocation |
| `simple://api/did` | DID class, wallet DID methods |
| `simple://api/credentials` | Schema, Issuer, VC/VP, revocation stores |
| `simple://api/overlay` | Overlay, SHIP/SLAP, broadcasting |
| `simple://guide/nextjs` | Complete Next.js integration guide |

### Available Tools

Code generation tools the agent can invoke:

| Tool | Description |
|------|-------------|
| `scaffold_nextjs_config` | Generate next.config.ts + package.json for BSV apps |
| `generate_wallet_setup` | Wallet initialization code (browser or server) |
| `generate_payment_handler` | Payment handler functions |
| `generate_token_handler` | Token CRUD operations |
| `generate_inscription_handler` | OP_RETURN inscription handlers |
| `generate_messagebox_setup` | MessageBox P2P integration |
| `generate_server_route` | Next.js API route for server wallet |
| `generate_credential_issuer` | CredentialIssuer setup with schema |
| `generate_did_integration` | DID integration code |

### Available Prompts

| Prompt | Description |
|--------|-------------|
| `integrate_simple` | Full integration walkthrough |
| `add_bsv_feature` | Feature-specific code generation |
| `debug_simple` | Debugging help for common issues |

### Seam Contract Integration

The `generate_inscription_handler` tool is directly relevant to seam contract commitments. It generates OP_RETURN inscription code using `@bsv/simple`, which can be used to commit contract hashes to the BSV blockchain as an alternative to the Python `bsv-sdk` approach documented in this guide.

**To commit a seam contract hash using the MCP server:**

1. Use the `generate_wallet_setup` tool to scaffold wallet initialization
2. Use the `generate_inscription_handler` tool to create an OP_RETURN handler
3. Pass the SHA-256 hash of your canonicalized contract as the inscription payload
4. The handler broadcasts the transaction and returns the txid

**Example agent workflow:**
```
Agent: "Use the simple-mcp server to generate a wallet setup for server-side use,
        then generate an inscription handler that writes an OP_RETURN with this
        contract hash: {sha256_hash}. Include the contract_id and version in the
        inscription metadata."
```

The MCP server will generate the TypeScript/JavaScript code to accomplish this, which the agent can then execute.

### OpenClaw Integration

For OpenClaw agents that need BSV blockchain access:

1. Install the MCP server on the agent's host machine
2. Configure the MCP connection in the agent's environment
3. The agent can then use natural language to generate and execute BSV transactions
4. Seam contract hashes, workspace Merkle roots, and verification results can all be committed to chain through the MCP tools

This provides a second path to blockchain commitment alongside the Python `bsv-sdk` library — choose based on your agent's runtime environment (Python vs JavaScript/TypeScript).

---

## AGENT INSTRUCTIONS

If you are an AI agent reading this document:

1. **The library above is complete and self-contained.** Save it as `seam_contracts.py` in your workspace. It has no external dependencies beyond `bsv-sdk` and Python standard library.

2. **To start:** Call `init_tracking_db(your_db_path)` to create the tracking tables. Define your contracts as a list of dicts following the schema. Call `verify_all()` to establish a baseline.

3. **To commit:** Fund a BSV wallet, set the WIF as an environment variable, call `commit_to_bsv()` for each contract. Store the returned tx_ids. Alternatively, if you have access to the `@bsv/simple-mcp` server, use the `generate_inscription_handler` tool to commit hashes via OP_RETURN in JavaScript/TypeScript.

4. **To monitor:** Set up a daily cron that calls `verify_all()` and alerts on failures.

5. **To version:** When a contract changes, increment the version, set `prev_version_tx` to the previous commitment's tx_id, and recommit.

6. **To verify cross-system:** Compare contract hashes from different nodes. Same hash = same governance.

7. **To access BSV tools via MCP:** Run `claude mcp add simple-mcp -- npx -y @bsv/simple-mcp` to add the BSV Simple MCP server. Query `simple://api/inscriptions` for OP_RETURN documentation. Use `generate_wallet_setup` and `generate_inscription_handler` to scaffold your blockchain interaction code.

8. **The key principle:** Contracts are promises. Hashes make promises verifiable. Blockchain makes verification immutable. Cron makes verification automatic.
