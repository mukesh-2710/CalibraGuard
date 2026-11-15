"""Transaction Rollback, Concurrency, and Audit Immutability Tests.
Proves:
1. Transaction rollback: Injected exceptions during processing roll back atomically with zero partial rows.
2. Concurrency safety: Multiple simultaneous threads attempting checks and calibrations serialize safely without deadlocks or corrupted counts.
3. Audit immutability: SQL triggers physically prevent UPDATE and DELETE on audit records.
"""
import concurrent.futures
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import generate
import loaddb
import rules
import server
from auth import USERS, create_token
from tests.test_api import TestHttpClient


class TestTransactionsAndConcurrency(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        generate.generate(seed=20261022, n_inst=50, n_cal=120, n_use=500, out=cls.tmpdir)
        import detect
        detect.run(cls.tmpdir)
        cls.db_path = loaddb.load(cls.tmpdir)

        server.conn = sqlite3.connect(cls.db_path, check_same_thread=False, isolation_level=None)
        server.conn.execute("PRAGMA foreign_keys=ON")
        server.ensure_tables()
        server.CTX = rules.build_contexts(server.frames())[0]

        cls.client = TestHttpClient()
        cls.qe_token = create_token(USERS["qe1"])
        cls.operator_token = create_token(USERS["operator1"])

    @classmethod
    def tearDownClass(cls):
        server.conn.close()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_audit_immutability_triggers(self):
        """Database triggers MUST abort any UPDATE or DELETE on audit_record."""
        audit_row = server.q("select audit_id from audit_record limit 1")[0]
        aid = audit_row["audit_id"]

        # Attempt UPDATE: must fail with trigger abort
        with self.assertRaises((sqlite3.OperationalError, sqlite3.IntegrityError)) as ctx:
            server.conn.execute("update audit_record set action='TAMPERED' where audit_id=?", (aid,))
        self.assertIn("audit_record is immutable", str(ctx.exception))

        # Attempt DELETE: must fail with trigger abort
        with self.assertRaises((sqlite3.OperationalError, sqlite3.IntegrityError)) as ctx2:
            server.conn.execute("delete from audit_record where audit_id=?", (aid,))
        self.assertIn("audit_record is immutable", str(ctx2.exception))

    def test_transaction_rollback_leaves_no_partial_records(self):
        """Simulate an error halfway through a transaction and verify complete rollback."""
        initial_use_count = server.conn.execute("select count(*) from production_use").fetchone()[0]
        initial_dec_count = server.conn.execute("select count(*) from use_decision").fetchone()[0]
        initial_audit_count = server.conn.execute("select count(*) from audit_record").fetchone()[0]

        orig_decide = server.decide

        def failing_decide(c, ts):
            # Force an unexpected python exception after transaction BEGIN
            raise RuntimeError("Injected unexpected engine failure during transaction")

        try:
            server.decide = failing_decide
            status, res = self.client.request(
                "POST",
                "/api/check",
                body={"instrument_id": "INS-000001", "timestamp": "2026-03-01T10:00:00"},
                token=self.operator_token,
            )
            self.assertEqual(status, 500)
            self.assertIn("Injected unexpected engine failure", res.get("error", ""))
        finally:
            server.decide = orig_decide

        # Verify exact counts: zero partial records inserted
        new_use_count = server.conn.execute("select count(*) from production_use").fetchone()[0]
        new_dec_count = server.conn.execute("select count(*) from use_decision").fetchone()[0]
        new_audit_count = server.conn.execute("select count(*) from audit_record").fetchone()[0]

        self.assertEqual(new_use_count, initial_use_count, "Rollback failed: partial row in production_use")
        self.assertEqual(new_dec_count, initial_dec_count, "Rollback failed: partial row in use_decision")
        self.assertEqual(new_audit_count, initial_audit_count, "Rollback failed: partial row in audit_record")

    def test_concurrency_safety(self):
        """10 concurrent threads simultaneously checking and recording usage."""
        insts = server.registry(status="COMPLIANT", limit=5)
        self.assertTrue(len(insts) > 0)

        initial_count = server.conn.execute("select count(*) from production_use").fetchone()[0]
        num_workers = 10

        def worker_task(idx):
            client = TestHttpClient()
            iid = insts[idx % len(insts)]["instrument_id"]
            status, res = client.request(
                "POST",
                "/api/check",
                body={
                    "instrument_id": iid,
                    "timestamp": f"2026-03-01T11:{idx:02d}:00",
                    "production_order_id": f"PO-CONCUR-{idx:04d}",
                },
                token=self.operator_token,
            )
            return status, res

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(worker_task, i) for i in range(num_workers)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All concurrent requests must succeed with 200 OK without deadlocks
        for status, res in results:
            self.assertEqual(status, 200)
            self.assertIn(res.get("decision"), ("ALLOW", "ALLOW_WITH_EXCEPTION", "BLOCK"))

        # Verify rows inserted match count of allowed decisions
        allowed_count = sum(1 for status, res in results if res.get("decision") in ("ALLOW", "ALLOW_WITH_EXCEPTION"))
        final_count = server.conn.execute("select count(*) from production_use").fetchone()[0]
        self.assertEqual(final_count, initial_count + allowed_count)


if __name__ == "__main__":
    unittest.main()
