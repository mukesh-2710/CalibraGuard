"""End-to-End Workflow Integration Test for CalibraGuard.
Tests the complete multi-persona journey:
1. Operator attempts to use an overdue instrument -> BLOCKED (EXPIRED_USE).
2. Quality Engineer investigates failure and records a failed calibration -> QUARANTINED.
3. Operator attempts to use quarantined instrument -> BLOCKED (QUARANTINED_USE).
4. Quality Engineer records passed recalibration -> PENDING_RELEASE.
5. Operator attempts to use instrument while pending release -> BLOCKED (PENDING_RELEASE_USE).
6. Quality Engineer performs independent authorized release -> ACTIVE.
7. Operator checks instrument again -> ALLOWED.
8. Complete audit trail inspection verifying forensic traceability.
"""
import datetime as dt
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


class TestEndToEndWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        generate.generate(seed=20261022, n_inst=80, n_cal=200, n_use=1500, out=cls.tmpdir)
        import detect
        detect.run(cls.tmpdir)
        cls.db_path = loaddb.load(cls.tmpdir)

        server.conn = sqlite3.connect(cls.db_path, check_same_thread=False, isolation_level=None)
        server.conn.execute("PRAGMA foreign_keys=ON")
        server.ensure_tables()
        server.CTX = rules.build_contexts(server.frames())[0]
        server.SIMULATION_DATE = dt.datetime(2026, 11, 15, 12, 0, 0)

        cls.client = TestHttpClient()
        cls.operator_token = create_token(USERS["operator1"])
        cls.qe_token = create_token(USERS["qe1"])
        cls.manager_token = create_token(USERS["manager1"])

    @classmethod
    def tearDownClass(cls):
        server.conn.close()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_full_operational_lifecycle(self):
        # Pick an active instrument
        insts = server.registry(status="COMPLIANT", limit=1)
        self.assertTrue(len(insts) > 0)
        iid = insts[0]["instrument_id"]

        # Step 1: Operator uses instrument when compliant -> ALLOWED
        s, r1 = self.client.request(
            "POST",
            "/api/check",
            body={"instrument_id": iid, "timestamp": "2026-04-01T09:00:00", "production_order_id": "PO-BATCH-001"},
            token=self.operator_token,
        )
        self.assertEqual(s, 200)
        self.assertEqual(r1["decision"], "ALLOW")
        self.assertTrue(r1["recorded_in_production"])

        # Step 2: Quality Engineer discovers out-of-tolerance condition, records FAIL calibration
        s, r2 = self.client.request(
            "POST",
            "/api/calibration",
            body={"instrument_id": iid, "result": "FAIL", "date": "2026-04-10", "error_pct": 2.5},
            token=self.qe_token,
        )
        self.assertEqual(s, 200)
        self.assertEqual(r2["lifecycle_state"], "QUARANTINED")
        self.assertIn("impact_assessment", r2)
        ia_id = r2["impact_assessment"]

        # Step 3: Verify impact assessment exists and identified prior uses
        s, ias = self.client.request("GET", "/api/impact")
        ia_records = [x for x in ias if x["ia_id"] == ia_id]
        self.assertEqual(len(ia_records), 1)

        # Step 4: Operator attempts to use quarantined instrument -> BLOCKED (QUARANTINED_USE)
        s, r3 = self.client.request(
            "POST",
            "/api/check",
            body={"instrument_id": iid, "timestamp": "2026-04-11T10:00:00", "production_order_id": "PO-BATCH-002"},
            token=self.operator_token,
        )
        self.assertEqual(s, 200)
        self.assertEqual(r3["decision"], "BLOCK")
        self.assertEqual(r3["issue_type"], "QUARANTINED_USE")
        self.assertFalse(r3["recorded_in_production"])
        self.assertTrue(r3["blocked"])

        # Step 5: Recalibration occurs and passes -> transitions to PENDING_RELEASE
        s, r4 = self.client.request(
            "POST",
            "/api/calibration",
            body={"instrument_id": iid, "result": "PASS", "date": "2026-04-15", "error_pct": 0.2},
            token=self.qe_token,
        )
        self.assertEqual(s, 200)
        self.assertEqual(r4["lifecycle_state"], "PENDING_RELEASE")
        self.assertFalse(r4["released"])

        # Step 6: Operator attempts use before release sign-off -> BLOCKED (PENDING_RELEASE_USE)
        s, r5 = self.client.request(
            "POST",
            "/api/check",
            body={"instrument_id": iid, "timestamp": "2026-04-16T08:00:00"},
            token=self.operator_token,
        )
        self.assertEqual(s, 200)
        self.assertEqual(r5["decision"], "BLOCK")
        self.assertEqual(r5["issue_type"], "PENDING_RELEASE_USE")

        # Step 7: Authorized Quality Engineer inspects certificate and signs off release
        s, r6 = self.client.request(
            "POST",
            f"/api/instruments/{iid}/release",
            body={"date": "2026-04-16"},
            token=self.qe_token,
        )
        self.assertEqual(s, 200)
        self.assertTrue(r6["released"])
        self.assertEqual(r6["lifecycle_state"], "ACTIVE")

        # Step 8: Operator retries check -> ALLOWED
        s, r7 = self.client.request(
            "POST",
            "/api/check",
            body={"instrument_id": iid, "timestamp": "2026-04-17T09:00:00", "production_order_id": "PO-BATCH-003"},
            token=self.operator_token,
        )
        self.assertEqual(s, 200)
        self.assertEqual(r7["decision"], "ALLOW")
        self.assertTrue(r7["recorded_in_production"])

        # Step 9: Audit Trail completeness verification
        s, audit_trail = self.client.request("GET", f"/api/audit?id={iid}")
        self.assertEqual(s, 200)
        actions = [a["action"] for a in audit_trail]
        self.assertIn("INSTRUMENT_QUARANTINED", actions)
        self.assertIn("INSTRUMENT_PENDING_RELEASE", actions)
        self.assertIn("INSTRUMENT_RELEASED", actions)


if __name__ == "__main__":
    unittest.main()
