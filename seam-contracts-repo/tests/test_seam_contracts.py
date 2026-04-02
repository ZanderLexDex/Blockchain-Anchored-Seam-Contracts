"""Tests for seam_contracts.py v1.2"""
import unittest, json, os, tempfile
from seam_contracts import (
    canonicalize, hash_contract, verify_hash, init_tracking_db,
    store_contract, verify_contract, verify_all, print_verification_report,
    compare_contracts
)

class TestHashing(unittest.TestCase):

    def test_canonicalize_deterministic(self):
        a = {"b": 2, "a": 1}
        b = {"a": 1, "b": 2}
        self.assertEqual(canonicalize(a), canonicalize(b))

    def test_hash_contract_consistent(self):
        contract = {"contract_id": "test", "version": 1}
        h1 = hash_contract(contract)
        h2 = hash_contract(contract)
        self.assertEqual(h1, h2)

    def test_hash_changes_with_content(self):
        c1 = {"contract_id": "test", "version": 1}
        c2 = {"contract_id": "test", "version": 2}
        self.assertNotEqual(hash_contract(c1), hash_contract(c2))

    def test_verify_hash(self):
        contract = {"contract_id": "test", "version": 1}
        h = hash_contract(contract)
        self.assertTrue(verify_hash(contract, h))
        self.assertFalse(verify_hash(contract, "wrong"))


class TestTracking(unittest.TestCase):

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        init_tracking_db(self.db_path)

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_init_creates_tables(self):
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = [t[0] for t in tables]
        self.assertIn("seam_contract", table_names)
        self.assertIn("seam_verification", table_names)
        self.assertIn("security_event", table_names)
        conn.close()

    def test_store_contract(self):
        contract = {"contract_id": "SC-001", "version": 1, "system_id": "test"}
        store_contract(self.db_path, contract)
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT contract_id, version, status FROM seam_contract").fetchone()
        self.assertEqual(row[0], "SC-001")
        self.assertEqual(row[1], 1)
        self.assertEqual(row[2], "DRAFT")
        conn.close()


class TestVerification(unittest.TestCase):

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        init_tracking_db(self.db_path)
        # Create a test table
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE records (id INTEGER, timestamp TEXT)")
        conn.execute("INSERT INTO records VALUES (1, '2026-01-01')")
        conn.execute("INSERT INTO records VALUES (2, '2026-01-02')")
        conn.commit()
        conn.close()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_sql_zero_count_pass(self):
        contract = {
            "contract_id": "test", "version": 1,
            "guarantees": [{
                "id": "G001", "description": "No NULL timestamps",
                "verification": "SELECT COUNT(*) FROM records WHERE timestamp IS NULL",
                "verification_type": "sql_zero_count"
            }]
        }
        result = verify_contract(self.db_path, contract)
        self.assertTrue(result["all_passed"])

    def test_sql_non_empty_pass(self):
        contract = {
            "contract_id": "test", "version": 1,
            "guarantees": [{
                "id": "G001", "description": "Records exist",
                "verification": "SELECT COUNT(*) FROM records",
                "verification_type": "sql_non_empty"
            }]
        }
        result = verify_contract(self.db_path, contract)
        self.assertTrue(result["all_passed"])


class TestCrossSystem(unittest.TestCase):

    def test_matching_contracts(self):
        c = {"contract_id": "SC-001", "version": 1, "system_id": "A"}
        result = compare_contracts(c, c)
        self.assertTrue(result["match"])

    def test_different_contracts(self):
        a = {"contract_id": "SC-001", "version": 1, "system_id": "A"}
        b = {"contract_id": "SC-001", "version": 2, "system_id": "B"}
        result = compare_contracts(a, b)
        self.assertFalse(result["match"])


if __name__ == "__main__":
    unittest.main()
