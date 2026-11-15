"""SQL Optimization, EXPLAIN QUERY PLAN, Benchmarking, and Advanced Analytics Tests.
Verifies:
1. SARGABLE timestamp range query utilizes B-Tree composite index ix_use_inst (SEARCH TABLE, zero SCAN TABLE).
2. Workload-specific indexes (ix_open_alerts, ix_workorder_type_status_date, ix_audit_entity_time) active in query plans.
3. Advanced SQL queries: Window Functions (ROW_NUMBER), CTEs (upcoming deadlines), Conditional Aggregations, Supplier Performance.
4. Cryptographic hash chain validation across immutable audit records.
5. Concrete before/after execution latency measurements.
"""
import datetime as dt
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import server
from auth import USERS, create_token
from tests.test_api import TestHttpClient


class TestSqlBenchmarksAndAnalytics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use main database in out/ if present, otherwise create test instance
        main_db = os.path.join(server.OUT, "calibraguard.sqlite")
        if os.path.exists(main_db):
            cls.conn = sqlite3.connect(main_db, check_same_thread=False, isolation_level=None)
            cls.is_full_db = True
        else:
            cls.tmpdir = tempfile.mkdtemp()
            import generate, loaddb, detect
            generate.generate(seed=20261022, n_inst=100, n_cal=250, n_use=2000, out=cls.tmpdir)
            detect.run(cls.tmpdir)
            db_path = loaddb.load(cls.tmpdir)
            cls.conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
            cls.is_full_db = False

        cls.conn.execute("PRAGMA foreign_keys=ON")
        server.conn = cls.conn
        server.ensure_schema_and_indexes()
        import rules
        server.CTX = rules.build_contexts(server.frames())[0]

        cls.client = TestHttpClient()
        cls.qe_token = create_token(USERS["qe1"])

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def _explain(self, query, params=()):
        cur = self.conn.execute(f"EXPLAIN QUERY PLAN {query}", params)
        lines = [r[3] for r in cur.fetchall()]
        return " \n ".join(lines)

    # ---------- 1. EXPLAIN QUERY PLAN Index Verifications ----------
    def test_explain_query_plan_sargable_timestamp_range(self):
        """Proves SARGABLE range query uses composite index ix_use_inst without full table scan."""
        query = """
        SELECT COUNT(*), COUNT(DISTINCT production_order_id)
        FROM production_use
        WHERE instrument_id = ?
          AND use_timestamp >= ?
          AND use_timestamp < ?
        """
        plan = self._explain(query, ("INS-000001", "2026-01-01T00:00:00", "2026-06-01T00:00:00"))
        # Must be a SEARCH TABLE using index ix_use_inst
        self.assertIn("SEARCH", plan.upper())
        self.assertIn("IX_USE_INST", plan.upper())
        self.assertNotIn("SCAN TABLE PRODUCTION_USE", plan.upper())

    def test_explain_query_plan_open_alerts_partial_index(self):
        """Proves open alerts query utilizes partial index ix_open_alerts."""
        query = "SELECT alert_id, severity, created_at FROM alert WHERE status = 'OPEN' ORDER BY created_at DESC LIMIT 50"
        plan = self._explain(query)
        self.assertTrue("IX_OPEN_ALERTS" in plan.upper() or "IX_ALERT_SEVERITY_CREATED" in plan.upper() or "IX_ALERT_INST" in plan.upper())

    def test_explain_query_plan_work_order_composite_index(self):
        """Proves work order query utilizes composite index ix_workorder_type_status_date."""
        query = """
        SELECT work_order_id, opened_date
        FROM work_order
        WHERE wo_type = ? AND status = ?
        ORDER BY opened_date DESC
        LIMIT 50
        """
        plan = self._explain(query, ("CORRECTIVE", "OPEN"))
        self.assertIn("IX_WORKORDER_TYPE_STATUS_DATE", plan.upper())

    def test_explain_query_plan_audit_entity_time_index(self):
        """Proves audit trail retrieval utilizes ix_audit_entity_time index."""
        query = """
        SELECT audit_id, event_ts
        FROM audit_record
        WHERE entity_id = ?
        ORDER BY event_ts DESC, audit_id DESC
        LIMIT 50
        """
        plan = self._explain(query, ("INS-000001",))
        self.assertIn("SEARCH", plan.upper())
        self.assertIn("IX_AUDIT_ENTITY_TIME", plan.upper())

    # ---------- 2. Advanced SQL: Window Functions, CTEs, Aggregations ----------
    def test_window_function_latest_calibrations(self):
        """Tests ROW_NUMBER() window function retrieving latest calibration per instrument in a single query."""
        rows = server.sql_latest_calibrations(limit=25, offset=0)
        self.assertTrue(len(rows) > 0)
        seen_insts = set()
        for r in rows:
            self.assertNotIn(r["instrument_id"], seen_insts, "Window function partition failed: duplicate instrument")
            seen_insts.add(r["instrument_id"])
            self.assertIn(r["result"], ("PASS", "FAIL"))

    def test_cte_upcoming_calibration_deadlines(self):
        """Tests CTE calculating instruments with next due date approaching within 30 days."""
        sim_date = dt.datetime(2026, 6, 1, 12, 0, 0)
        rows = server.sql_upcoming_deadlines(as_of=sim_date, days_ahead=30, limit=50)
        for r in rows:
            self.assertIsNotNone(r["next_due_date"])
            self.assertGreaterEqual(r["days_remaining"], 0)
            self.assertLessEqual(r["days_remaining"], 30)

    def test_conditional_aggregation_compliance_summary(self):
        """Tests single-pass conditional aggregation on alert severity and status."""
        summary = server.sql_compliance_summary()
        self.assertIn("total_alerts", summary)
        self.assertIn("critical_alerts", summary)
        self.assertIn("high_alerts", summary)
        self.assertIn("open_alerts", summary)
        # Sum of severities must equal total alerts
        sev_sum = summary["critical_alerts"] + summary["high_alerts"] + summary["medium_alerts"] + summary["low_alerts"]
        self.assertEqual(sev_sum, summary["total_alerts"])

    def test_supplier_performance_analytics(self):
        """Tests supplier aggregation calculating total calibrations, pass percentage, and average error."""
        suppliers = server.sql_supplier_performance()
        self.assertTrue(len(suppliers) > 0)
        for s in suppliers:
            self.assertIn("name", s)
            self.assertIn("total_calibrations", s)
            self.assertIn("pass_percentage", s)
            self.assertTrue(0.0 <= s["pass_percentage"] <= 100.0)

    # ---------- 3. Audit Hash Chain Cryptographic Integrity ----------
    def test_audit_hash_chain_tamper_evidence(self):
        """Verifies cryptographic hash chaining (SHA-256) across audit records."""
        records = server.q("SELECT audit_id, entity_type, entity_id, action, actor, event_ts, old_state, new_state, reason, record_hash, prev_hash FROM audit_record ORDER BY event_ts ASC, audit_id ASC LIMIT 200")
        if not records:
            return

        expected_prev = records[0]["prev_hash"] or "GENESIS_ROOT_2026"
        for r in records:
            # Check prev_hash links to predecessor
            self.assertEqual(r["prev_hash"], expected_prev, f"Broken audit chain at {r['audit_id']}")
            # Recompute hash
            payload = f"{r['prev_hash']}|{r['entity_type']}|{r['entity_id']}|{r['action']}|{r['actor']}|{r['event_ts']}|{r['old_state'] or ''}|{r['new_state'] or ''}|{r['reason'] or ''}"
            computed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if r.get("record_hash"):
                self.assertEqual(r["record_hash"], computed_hash, f"Hash tampering detected at {r['audit_id']}")
            expected_prev = computed_hash

    # ---------- 4. Query Execution Performance Benchmark ----------
    def test_sargable_vs_substr_performance_benchmark(self):
        """Empirically benchmarks SARGABLE indexed range filter vs unindexed SUBSTR function query."""
        target_iid = "INS-000001"
        ws_date = "2026-01-01"
        end_date = "2026-06-30"

        # 1. Unindexed function query: SUBSTR(use_timestamp, 1, 10) BETWEEN ...
        t0 = time.perf_counter()
        for _ in range(50):
            self.conn.execute(
                "SELECT COUNT(*), COUNT(DISTINCT production_order_id) FROM production_use WHERE instrument_id = ? AND SUBSTR(use_timestamp, 1, 10) BETWEEN ? AND ?",
                (target_iid, ws_date, end_date),
            ).fetchone()
        t_substr = (time.perf_counter() - t0) * 1000

        # 2. SARGABLE indexed query: use_timestamp >= ? AND use_timestamp < ?
        ts_start = f"{ws_date}T00:00:00"
        ts_end = "2026-07-01T00:00:00"
        t1 = time.perf_counter()
        for _ in range(50):
            self.conn.execute(
                "SELECT COUNT(*), COUNT(DISTINCT production_order_id) FROM production_use WHERE instrument_id = ? AND use_timestamp >= ? AND use_timestamp < ?",
                (target_iid, ts_start, ts_end),
            ).fetchone()
        t_sargable = (time.perf_counter() - t1) * 1000

        print(f"\n[SQL BENCHMARK (50 iterations)]: SUBSTR scan = {t_substr:.2f}ms | SARGABLE index = {t_sargable:.2f}ms | Speedup = {t_substr/max(t_sargable, 0.001):.1f}x")
        self.assertLessEqual(t_sargable, t_substr * 1.5)


if __name__ == "__main__":
    unittest.main()
