"""Comprehensive API Integration Tests for CalibraGuard REST API.
Executes against server.H handler directly without external socket bindings,
providing fast, deterministic testing of all HTTP routes, headers, payloads, and status codes.
Tests:
- Authentication & Server-Side RBAC (Operator, Quality Engineer, Planner, Manager, Admin)
- Production use checking & separation of blocked attempts from actual production records
- Recalibration and independent authorized release lifecycle
- Dynamic simulation date handling
- Core endpoints (metrics, registry, workorders, audit, exceptions, attempts)
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
from auth import USERS, authenticate, create_token


class TestHttpClient:
    """In-memory HTTP client testing server.H handler directly."""
    def request(self, method, path, body=None, token=None, headers=None):
        req_headers = {"Content-Type": "application/json"}
        if token:
            req_headers["Authorization"] = f"Bearer {token}"
        if headers:
            req_headers.update(headers)

        body_bytes = json.dumps(body).encode("utf-8") if body is not None else b""
        req_headers["Content-Length"] = str(len(body_bytes))

        handler = server.H.__new__(server.H)
        handler.command = method
        handler.path = path
        handler.headers = req_headers
        handler.rfile = io.BytesIO(body_bytes)
        handler.wfile = io.BytesIO()
        handler.response_code = 200
        handler.response_headers = {}

        def mock_send_response(code, message=None):
            handler.response_code = code

        def mock_send_header(keyword, value):
            handler.response_headers[keyword] = value

        def mock_end_headers():
            pass

        handler.send_response = mock_send_response
        handler.send_header = mock_send_header
        handler.end_headers = mock_end_headers

        if method == "GET":
            handler.do_GET()
        elif method == "POST":
            handler.do_POST()
        elif method == "OPTIONS":
            handler.do_OPTIONS()

        out_bytes = handler.wfile.getvalue()
        try:
            res_payload = json.loads(out_bytes.decode("utf-8")) if out_bytes else {}
        except Exception:
            res_payload = out_bytes.decode("utf-8")

        return handler.response_code, res_payload


class TestApiIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        generate.generate(seed=20261022, n_inst=100, n_cal=250, n_use=2000, out=cls.tmpdir)
        import detect
        detect.run(cls.tmpdir)
        cls.db_path = loaddb.load(cls.tmpdir)

        # Configure server to use temp DB
        server.conn = sqlite3.connect(cls.db_path, check_same_thread=False, isolation_level=None)
        server.conn.execute("PRAGMA foreign_keys=ON")
        server.ensure_tables()
        server.CTX = rules.build_contexts(server.frames())[0]
        server.SIMULATION_DATE = dt.datetime(2026, 11, 15, 12, 0, 0)

        cls.client = TestHttpClient()

        # Pre-generate tokens
        cls.qe_token = create_token(USERS["qe1"])
        cls.operator_token = create_token(USERS["operator1"])
        cls.planner_token = create_token(USERS["planner1"])

    @classmethod
    def tearDownClass(cls):
        server.conn.close()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    # ---------- Authentication Tests ----------
    def test_login_success(self):
        status, res = self.client.request("POST", "/api/auth/login", body={"username": "qe1", "password": "Quality@123"})
        self.assertEqual(status, 200)
        self.assertIn("token", res)
        self.assertEqual(res["user"]["role"], "QUALITY_ENGINEER")

    def test_login_bad_credentials(self):
        status, res = self.client.request("POST", "/api/auth/login", body={"username": "qe1", "password": "WrongPassword"})
        self.assertEqual(status, 401)
        self.assertEqual(res.get("code"), "UNAUTHORIZED")

    def test_auth_me_authorized(self):
        status, res = self.client.request("GET", "/api/auth/me", token=self.qe_token)
        self.assertEqual(status, 200)
        self.assertEqual(res["user"]["sub"], "qe1")

    def test_auth_me_unauthorized(self):
        status, res = self.client.request("GET", "/api/auth/me")
        self.assertEqual(status, 401)

    # ---------- RBAC Tests ----------
    def test_calibration_rbac_rejection(self):
        """Plant operator cannot record calibration (must receive 403 Forbidden)."""
        body = {"instrument_id": "INS-000001", "result": "PASS"}
        status, res = self.client.request("POST", "/api/calibration", body=body, token=self.operator_token)
        self.assertEqual(status, 403)
        self.assertEqual(res.get("code"), "FORBIDDEN")

    def test_release_rbac_rejection(self):
        """Plant operator cannot release an instrument (must receive 403 Forbidden)."""
        status, res = self.client.request("POST", "/api/instruments/INS-000001/release", body={}, token=self.operator_token)
        self.assertEqual(status, 403)
        self.assertEqual(res.get("code"), "FORBIDDEN")

    # ---------- Production Use Check & Separation Tests ----------
    def test_check_allowed_use_records_in_production(self):
        """Allowed use is recorded in production_use and use_decision."""
        insts = server.registry(status="COMPLIANT", limit=1)
        iid = insts[0]["instrument_id"]

        status, res = self.client.request("POST", "/api/check", body={"instrument_id": iid, "timestamp": "2026-03-01T10:00:00"}, token=self.operator_token)
        self.assertEqual(status, 200)
        self.assertEqual(res["decision"], "ALLOW")
        self.assertTrue(res["recorded_in_production"])
        self.assertIn("use_id", res)

        # Verify DB has row in production_use
        row = server.q("select * from production_use where use_id=?", (res["use_id"],))
        self.assertEqual(len(row), 1)

    def test_check_blocked_use_stored_in_attempts_not_production(self):
        """Blocked use attempts are saved to usage_attempt and NOT to production_use."""
        insts = server.registry(limit=1)
        iid = insts[0]["instrument_id"]

        initial_prod_count = server.conn.execute("select count(*) from production_use where instrument_id=?", (iid,)).fetchone()[0]

        status, res = self.client.request("POST", "/api/check", body={"instrument_id": iid, "timestamp": "2025-01-01T10:00:00"}, token=self.operator_token)
        self.assertEqual(status, 200)
        self.assertEqual(res["decision"], "BLOCK")
        self.assertFalse(res["recorded_in_production"])
        self.assertTrue(res["blocked"])
        self.assertIn("attempt_id", res)

        # Verify production_use did NOT increase
        new_prod_count = server.conn.execute("select count(*) from production_use where instrument_id=?", (iid,)).fetchone()[0]
        self.assertEqual(new_prod_count, initial_prod_count)

        # Verify usage_attempt captured the blocked attempt
        attempt_row = server.q("select * from usage_attempt where attempt_id=?", (res["attempt_id"],))
        self.assertEqual(len(attempt_row), 1)
        self.assertEqual(attempt_row[0]["decision"], "BLOCK")

    # ---------- Recalibration & Authorized Release Workflow ----------
    def test_quarantine_recalibration_pending_release_lifecycle(self):
        """Full industrial lifecycle:
        1. Instrument fails calibration -> QUARANTINED, corrective WO opened, impact assessment created.
        2. Production check -> BLOCKED (QUARANTINED_USE).
        3. Recalibration PASS -> PENDING_RELEASE (cannot be used yet).
        4. Production check -> BLOCKED (PENDING_RELEASE_USE).
        5. Authorized Quality Engineer calls /release -> ACTIVE.
        6. Production check -> ALLOWED.
        """
        insts = server.registry(status="COMPLIANT", limit=1)
        iid = insts[0]["instrument_id"]

        # 1. Fail calibration
        status, cal_fail = self.client.request(
            "POST",
            "/api/calibration",
            body={"instrument_id": iid, "result": "FAIL", "date": "2026-06-01"},
            token=self.qe_token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(cal_fail["result"], "FAIL")
        self.assertEqual(cal_fail["lifecycle_state"], "QUARANTINED")
        self.assertIn("impact_assessment", cal_fail)
        self.assertIn("work_order", cal_fail)

        # 2. Check: must be BLOCKED
        status, chk1 = self.client.request("POST", "/api/check", body={"instrument_id": iid, "timestamp": "2026-06-02T10:00:00"}, token=self.operator_token)
        self.assertEqual(chk1["decision"], "BLOCK")
        self.assertEqual(chk1["issue_type"], "QUARANTINED_USE")

        # 3. Recalibration PASS
        status, cal_pass = self.client.request(
            "POST",
            "/api/calibration",
            body={"instrument_id": iid, "result": "PASS", "date": "2026-06-05"},
            token=self.qe_token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(cal_pass["result"], "PASS")
        self.assertEqual(cal_pass["lifecycle_state"], "PENDING_RELEASE")
        self.assertFalse(cal_pass["released"])

        # 4. Check while PENDING_RELEASE: must be BLOCKED with PENDING_RELEASE_USE
        status, chk2 = self.client.request("POST", "/api/check", body={"instrument_id": iid, "timestamp": "2026-06-06T10:00:00"}, token=self.operator_token)
        self.assertEqual(chk2["decision"], "BLOCK")
        self.assertEqual(chk2["issue_type"], "PENDING_RELEASE_USE")

        # 5. Authorized Release by Quality Engineer
        status, rel = self.client.request(
            "POST",
            f"/api/instruments/{iid}/release",
            body={"date": "2026-06-06"},
            token=self.qe_token,
        )
        self.assertEqual(status, 200)
        self.assertTrue(rel["released"])
        self.assertEqual(rel["lifecycle_state"], "ACTIVE")

        # 6. Check after release: must be ALLOWED
        status, chk3 = self.client.request("POST", "/api/check", body={"instrument_id": iid, "timestamp": "2026-06-07T10:00:00"}, token=self.operator_token)
        self.assertEqual(chk3["decision"], "ALLOW")

    # ---------- Simulation Date & Query Endpoints ----------
    def test_simulation_date_endpoints(self):
        status, res = self.client.request("GET", "/api/simulation-date")
        self.assertEqual(status, 200)
        self.assertIn("simulation_date", res)

        status, update_res = self.client.request("POST", "/api/simulation-date", body={"date": "2026-11-20T08:00:00"}, token=self.qe_token)
        self.assertEqual(status, 200)
        self.assertTrue(update_res["updated"])

        status, get_res = self.client.request("GET", "/api/simulation-date")
        self.assertEqual(get_res["simulation_date"], "2026-11-20T08:00:00")

    def test_query_endpoints(self):
        for path in ("/api/metrics", "/api/instruments", "/api/exceptions", "/api/workorders", "/api/impact", "/api/attempts"):
            status, res = self.client.request("GET", path)
            self.assertEqual(status, 200, f"Endpoint {path} failed with status {status}")


if __name__ == "__main__":
    unittest.main()
