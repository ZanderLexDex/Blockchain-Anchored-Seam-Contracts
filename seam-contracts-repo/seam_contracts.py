"""
Seam Contract Library v1.2 — Blockchain-Anchored Governance
Universal implementation for autonomous AI agent data pipelines.

Dependencies: pip install bsv-sdk pydantic
Optional:     pip install confusables (for sanitize_engine integration)

Reviewed by: Claude (Anthropic) + Gemini 3.1 + Grok 4
"""

import hashlib
import json
import sqlite3
import os
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Literal, Callable

try:
    from pydantic import BaseModel, Field, model_validator
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False


# ================================================================
# PYDANTIC MODELS (v1.2 — from Grok review, hardened)
# ================================================================

if HAS_PYDANTIC:
    class Guarantee(BaseModel):
        id: str = Field(pattern=r"^G[\w_]+$")
        description: str
        verification: Optional[str] = None
        verification_type: Literal[
            "sql_zero_count", "sql_non_empty", "command_exit_zero",
            "api_status_code", "ml_metric_threshold", "code_audit", "manual"
        ] = "manual"

    class SeamContract(BaseModel):
        contract_id: str
        version: int = Field(ge=1)
        effective_date: str
        system_id: str
        producer: dict
        consumer: dict
        guarantees: list[Guarantee]
        not_guaranteed: list[str] = Field(default_factory=list)
        prev_version_tx: Optional[str] = None
        signers: list[str] = Field(default_factory=list)
        network_id: Optional[str] = None
        protocol_version: str = "seam_v1"
        expiry_date: Optional[str] = None
        review_frequency_days: int = 30
        tags: list[str] = Field(default_factory=list)
        dependencies: list[str] = Field(default_factory=list)
        metadata: dict = Field(default_factory=dict)

        @model_validator(mode='after')
        def validate_guarantees(self):
            for g in self.guarantees:
                if g.verification_type not in ("manual", "code_audit") and not g.verification:
                    raise ValueError(f"Guarantee {g.id}: non-manual type requires verification field")
            return self


def validate_contract(contract: dict) -> dict:
    """Validate a contract dict against the schema. Returns validated dict or raises."""
    if HAS_PYDANTIC:
        model = SeamContract.model_validate(contract)
        return model.model_dump()
    return contract  # passthrough if pydantic not installed


# ================================================================
# HASHING
# ================================================================

def canonicalize(contract: dict) -> str:
    """Deterministic JSON serialization for hashing."""
    return json.dumps(contract, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def hash_contract(contract: dict) -> str:
    """SHA-256 hash of canonicalized contract."""
    if HAS_PYDANTIC and hasattr(contract, 'model_dump'):
        contract = contract.model_dump()
    return hashlib.sha256(canonicalize(contract).encode('utf-8')).hexdigest()


def verify_hash(contract: dict, expected_hash: str) -> bool:
    return hash_contract(contract) == expected_hash


# ================================================================
# BSV COMMITMENT
# ================================================================

async def commit_to_bsv(
    contract: dict,
    private_key_wif: str,
    source_tx_hex: str,
    source_output_index: int = 0,
    protocol_prefix: str = "seam_contract_v1"
) -> str:
    """Commit contract hash to BSV blockchain via OP_RETURN."""
    from bsv import PrivateKey, P2PKH, Transaction, TransactionInput, TransactionOutput, Script

    if HAS_PYDANTIC and hasattr(contract, 'model_dump'):
        contract = contract.model_dump()

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


# ================================================================
# LOCAL TRACKING
# ================================================================

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

CREATE TABLE IF NOT EXISTS security_event (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK(severity IN ('INFO','WARNING','CRITICAL')),
    context         TEXT,
    details_json    TEXT,
    resolved        INTEGER DEFAULT 0,
    detected_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_security_severity
    ON security_event(severity, detected_at);
"""


def init_tracking_db(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.executescript(TRACKING_SCHEMA)
    conn.commit()
    conn.close()


def store_contract(db_path: str, contract: dict, tx_id: Optional[str] = None):
    conn = sqlite3.connect(db_path)
    conn.execute(
        """INSERT OR REPLACE INTO seam_contract
           (contract_id, version, system_id, contract_json, sha256_hash, bsv_tx_id, prev_tx_id, status, committed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            contract["contract_id"], contract["version"], contract.get("system_id"),
            canonicalize(contract), hash_contract(contract), tx_id,
            contract.get("prev_version_tx"),
            "ACTIVE" if tx_id else "DRAFT",
            datetime.now(timezone.utc).isoformat() if tx_id else None,
        )
    )
    conn.commit()
    conn.close()


# ================================================================
# VERIFICATION ENGINE (expanded v1.2)
# ================================================================

# Registry for custom verification functions
_CUSTOM_VERIFIERS: dict[str, Callable] = {}

def register_verifier(name: str, fn: Callable):
    """Register a custom verification function: fn(check_string) -> bool"""
    _CUSTOM_VERIFIERS[name] = fn


def verify_guarantee(conn: sqlite3.Connection, guarantee: dict) -> dict:
    """Verify a single guarantee. Supports: sql_zero_count, sql_non_empty,
    command_exit_zero, api_status_code, ml_metric_threshold, manual."""
    g_id = guarantee["id"]
    g_type = guarantee.get("verification_type", "manual")
    g_check = guarantee.get("verification")

    if g_type in ("manual", "code_audit") or g_check is None:
        return {"guarantee_id": g_id, "passed": None, "note": "Manual/audit review required"}

    try:
        if g_type == "sql_zero_count":
            row = conn.execute(g_check).fetchone()
            value = row[0] if row else None
            return {"guarantee_id": g_id, "passed": (value == 0), "value": value,
                    "description": guarantee.get("description")}

        elif g_type == "sql_non_empty":
            row = conn.execute(g_check).fetchone()
            value = row[0] if row else None
            return {"guarantee_id": g_id, "passed": (value is not None and value != 0 and value != ""),
                    "value": value, "description": guarantee.get("description")}

        elif g_type == "command_exit_zero":
            import subprocess
            result = subprocess.run(g_check, shell=True, capture_output=True, timeout=30)
            return {"guarantee_id": g_id, "passed": (result.returncode == 0),
                    "value": result.returncode, "description": guarantee.get("description")}

        elif g_type == "api_status_code":
            import requests
            resp = requests.get(g_check, timeout=10)
            return {"guarantee_id": g_id, "passed": (resp.status_code == 200),
                    "value": resp.status_code, "description": guarantee.get("description")}

        elif g_type == "ml_metric_threshold":
            # g_check format: "command|threshold" e.g. "python check_accuracy.py|0.95"
            # NO eval() — structured parse only
            parts = g_check.split("|")
            if len(parts) != 2:
                return {"guarantee_id": g_id, "passed": False,
                        "error": "ml_metric_threshold format: 'command|threshold'"}
            cmd, threshold_str = parts[0].strip(), parts[1].strip()
            try:
                threshold = float(threshold_str)
            except ValueError:
                return {"guarantee_id": g_id, "passed": False, "error": f"Invalid threshold: {threshold_str}"}
            import subprocess
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=60, text=True)
            if result.returncode != 0:
                return {"guarantee_id": g_id, "passed": False, "error": f"Command failed: {result.stderr[:200]}"}
            try:
                value = float(result.stdout.strip())
            except ValueError:
                return {"guarantee_id": g_id, "passed": False, "error": f"Non-numeric output: {result.stdout[:100]}"}
            return {"guarantee_id": g_id, "passed": (value >= threshold),
                    "value": value, "threshold": threshold, "description": guarantee.get("description")}

        elif g_type in _CUSTOM_VERIFIERS:
            passed = _CUSTOM_VERIFIERS[g_type](g_check)
            return {"guarantee_id": g_id, "passed": bool(passed), "description": guarantee.get("description")}

        else:
            return {"guarantee_id": g_id, "passed": False, "error": f"Unknown type: {g_type}"}

    except Exception as e:
        return {"guarantee_id": g_id, "passed": False, "error": str(e),
                "description": guarantee.get("description")}


def verify_contract(db_path: str, contract: dict, log_results: bool = True) -> dict:
    """Run all guarantee checks for a seam contract."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")

    results = []
    for g in contract["guarantees"]:
        result = verify_guarantee(conn, g if isinstance(g, dict) else g.model_dump() if HAS_PYDANTIC else g)
        results.append(result)

        if log_results and result.get("passed") is not None:
            conn.execute(
                """INSERT INTO seam_verification
                   (contract_id, contract_version, guarantee_id, check_time, passed, result_value, expected)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (contract["contract_id"], contract["version"], result["guarantee_id"],
                 datetime.now(timezone.utc).isoformat(),
                 1 if result["passed"] else 0,
                 str(result.get("value", result.get("error", ""))),
                 g.get("verification_type", ""))
            )

    if log_results:
        conn.commit()
    conn.close()

    passed = sum(1 for r in results if r.get("passed") is True)
    failed = sum(1 for r in results if r.get("passed") is False)
    skipped = sum(1 for r in results if r.get("passed") is None)

    return {
        "contract_id": contract["contract_id"], "version": contract["version"],
        "check_time": datetime.now(timezone.utc).isoformat(),
        "total": len(results), "passed": passed, "failed": failed, "skipped": skipped,
        "all_passed": (failed == 0), "details": results
    }


def verify_all(db_path: str, contracts: list, log_results: bool = True) -> dict:
    """Verify all contracts against a database."""
    all_results = []
    for contract in contracts:
        if HAS_PYDANTIC and hasattr(contract, 'model_dump'):
            contract = contract.model_dump()
        result = verify_contract(db_path, contract, log_results)
        all_results.append(result)

    total_passed = sum(r["passed"] for r in all_results)
    total_failed = sum(r["failed"] for r in all_results)
    total_skipped = sum(r["skipped"] for r in all_results)

    return {
        "check_time": datetime.now(timezone.utc).isoformat(),
        "contracts_checked": len(contracts),
        "total_guarantees": total_passed + total_failed + total_skipped,
        "passed": total_passed, "failed": total_failed, "skipped": total_skipped,
        "compliance_rate": f"{(total_passed / max(total_passed + total_failed, 1)) * 100:.1f}%",
        "all_passed": (total_failed == 0), "results": all_results
    }


# ================================================================
# REPORTING
# ================================================================

def print_verification_report(report: dict):
    print(f"\n{'='*60}")
    print(f"SEAM CONTRACT VERIFICATION — {report['check_time']}")
    print(f"{'='*60}")
    print(f"Contracts: {report['contracts_checked']}")
    print(f"Guarantees: {report['total_guarantees']} | {report['passed']} passed | {report['failed']} failed | {report['skipped']} skipped")
    print(f"Compliance: {report['compliance_rate']}")
    print(f"Status: {'ALL PASSING' if report['all_passed'] else 'VIOLATIONS DETECTED'}")
    for r in report["results"]:
        status = "PASS" if r["all_passed"] else "FAIL"
        print(f"\n  [{status}] {r['contract_id']} v{r['version']} — {r['passed']}/{r['total']}")
        if not r["all_passed"]:
            for d in r["details"]:
                if d.get("passed") is False:
                    print(f"         VIOLATION: {d['guarantee_id']} — {d.get('description', '')} (got: {d.get('value', d.get('error', ''))})")
    print(f"\n{'='*60}\n")


def generate_pilot_report(db_path: str, pilot_id: str, system_id: str,
                          start_date: str, end_date: str, bsv_transactions: list) -> dict:
    conn = sqlite3.connect(db_path)
    total = conn.execute("SELECT COUNT(*) FROM seam_verification WHERE check_time BETWEEN ? AND ?", (start_date, end_date)).fetchone()[0]
    passed = conn.execute("SELECT COUNT(*) FROM seam_verification WHERE passed=1 AND check_time BETWEEN ? AND ?", (start_date, end_date)).fetchone()[0]
    failed = conn.execute("SELECT COUNT(*) FROM seam_verification WHERE passed=0 AND check_time BETWEEN ? AND ?", (start_date, end_date)).fetchone()[0]
    violations = conn.execute("SELECT contract_id, guarantee_id, check_time, result_value FROM seam_verification WHERE passed=0 AND check_time BETWEEN ? AND ? ORDER BY check_time", (start_date, end_date)).fetchall()
    days = conn.execute("SELECT COUNT(DISTINCT date(check_time)) FROM seam_verification WHERE check_time BETWEEN ? AND ?", (start_date, end_date)).fetchone()[0]
    conn.close()

    return {
        "pilot_id": pilot_id, "system_id": system_id,
        "period": {"start": start_date, "end": end_date}, "duration_days": days,
        "contracts_on_chain": len(bsv_transactions), "bsv_transactions": bsv_transactions,
        "total_checks": total, "passed": passed, "failed": failed,
        "compliance_rate": f"{(passed / max(passed + failed, 1)) * 100:.1f}%",
        "violations": [{"contract_id": v[0], "guarantee_id": v[1], "detected_at": v[2], "value": v[3]} for v in violations]
    }


# ================================================================
# CROSS-SYSTEM VERIFICATION
# ================================================================

def compare_contracts(contract_a: dict, contract_b: dict) -> dict:
    ha, hb = hash_contract(contract_a), hash_contract(contract_b)
    return {
        "contract_id": contract_a.get("contract_id"),
        "system_a": contract_a.get("system_id"), "system_b": contract_b.get("system_id"),
        "hash_a": ha, "hash_b": hb, "match": ha == hb,
        "version_a": contract_a.get("version"), "version_b": contract_b.get("version"),
    }


def verify_on_chain(tx_id: str, expected_hash: str) -> dict:
    """Verify a contract hash on-chain via WhatsOnChain API."""
    import requests
    resp = requests.get(f"https://api.whatsonchain.com/v1/bsv/main/tx/{tx_id}", timeout=10)
    if resp.status_code != 200:
        return {"verified": False, "error": f"TX not found: {resp.status_code}"}
    tx_data = resp.json()
    for vout in tx_data.get("vout", []):
        script_hex = vout.get("scriptPubKey", {}).get("hex", "")
        if script_hex.startswith("006a"):
            try:
                data_hex = script_hex[4:]
                payload = bytes.fromhex(data_hex).decode('utf-8', errors='ignore')
                if expected_hash in payload:
                    return {"verified": True, "tx_id": tx_id,
                            "block_height": tx_data.get("blockheight"),
                            "timestamp": tx_data.get("blocktime")}
            except Exception:
                pass
    return {"verified": False, "error": "Hash not found in TX OP_RETURN"}


# ================================================================
# CLI
# ================================================================

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="seam_contracts", description="Seam Contract Manager")
    sub = parser.add_subparsers(dest="command")

    p_init = sub.add_parser("init", help="Initialize tracking database")
    p_init.add_argument("--db", required=True)

    p_verify = sub.add_parser("verify", help="Verify contracts")
    p_verify.add_argument("--db", required=True)
    p_verify.add_argument("--contracts", required=True, help="Path to contracts JSON file")

    p_report = sub.add_parser("report", help="Print verification report")
    p_report.add_argument("--db", required=True)
    p_report.add_argument("--contracts", required=True)

    args = parser.parse_args()

    if args.command == "init":
        init_tracking_db(args.db)
        print(f"Initialized tracking database: {args.db}")

    elif args.command in ("verify", "report"):
        with open(args.contracts) as f:
            contracts = json.load(f)
        if not isinstance(contracts, list):
            contracts = [contracts]
        report = verify_all(args.db, contracts)
        print_verification_report(report)

    else:
        parser.print_help()
