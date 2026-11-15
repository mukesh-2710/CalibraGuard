"""Unit tests for enhanced rules in calibraguard/rules.py:
- Full certificate validation (instrument ID, asset ID, status, range)
- Effective-dated calibration plan resolution
- Independent recalibration pending release workflow
"""
import datetime as dt
import unittest
import pandas as pd
from calibraguard import rules


class TestEnhancedRules(unittest.TestCase):
    def setUp(self):
        self.d = dt.date

    def test_wrong_instrument_certificate(self):
        """Certificate has correct asset but wrong instrument_id."""
        c = {
            "asset": "AST-000001",
            "dates": [self.d(2026, 1, 1)],
            "maint": [],
            "ext": [],
            "ev": [(self.d(2026, 1, 1), "PASS", self.d(2026, 4, 1), "CAL-001", "WRONG_INSTRUMENT")],
        }
        dec, issue, reason, _ = rules.decide(c, self.d(2026, 2, 1))
        self.assertEqual(dec, rules.BLOCK)
        self.assertEqual(issue, "WRONG_INSTRUMENT_CERT_USE")

    def test_revoked_certificate(self):
        """Certificate status is REVOKED."""
        c = {
            "asset": "AST-000001",
            "dates": [self.d(2026, 1, 1)],
            "maint": [],
            "ext": [],
            "ev": [(self.d(2026, 1, 1), "PASS", self.d(2026, 4, 1), "CAL-001", "REVOKED")],
        }
        dec, issue, reason, _ = rules.decide(c, self.d(2026, 2, 1))
        self.assertEqual(dec, rules.BLOCK)
        self.assertEqual(issue, "CERT_REVOKED_USE")

    def test_superseded_certificate(self):
        """Certificate status is SUPERSEDED."""
        c = {
            "asset": "AST-000001",
            "dates": [self.d(2026, 1, 1)],
            "maint": [],
            "ext": [],
            "ev": [(self.d(2026, 1, 1), "PASS", self.d(2026, 4, 1), "CAL-001", "SUPERSEDED")],
        }
        dec, issue, reason, _ = rules.decide(c, self.d(2026, 2, 1))
        self.assertEqual(dec, rules.BLOCK)
        self.assertEqual(issue, "CERT_SUPERSEDED_USE")

    def test_out_of_range_certificate(self):
        """Certificate calibration range does not cover required operating range."""
        c = {
            "asset": "AST-000001",
            "dates": [self.d(2026, 1, 1)],
            "maint": [],
            "ext": [],
            "ev": [(self.d(2026, 1, 1), "PASS", self.d(2026, 4, 1), "CAL-001", "OUT_OF_RANGE")],
        }
        dec, issue, reason, _ = rules.decide(c, self.d(2026, 2, 1))
        self.assertEqual(dec, rules.BLOCK)
        self.assertEqual(issue, "CERT_RANGE_MISMATCH_USE")

    def test_pending_release_after_recalibration(self):
        """After failure, a PASS recalibration must require explicit authorized release."""
        c = {
            "asset": "AST-000001",
            "dates": [self.d(2026, 1, 1), self.d(2026, 2, 1)],
            "maint": [],
            "ext": [],
            "unreleased_cals": {"CAL-002"},
            "ev": [
                (self.d(2026, 1, 1), "FAIL", self.d(2026, 4, 1), "CAL-001", "NONE"),
                (self.d(2026, 2, 1), "PASS", self.d(2026, 5, 1), "CAL-002", "OK"),
            ],
        }
        # While CAL-002 is unreleased:
        dec, issue, reason, _ = rules.decide(c, self.d(2026, 2, 5))
        self.assertEqual(dec, rules.BLOCK)
        self.assertEqual(issue, "PENDING_RELEASE_USE")

        # After authorized release clears unreleased_cals:
        c["unreleased_cals"].clear()
        dec, issue, reason, _ = rules.decide(c, self.d(2026, 2, 5))
        self.assertEqual(dec, rules.ALLOW)

    def test_effective_dated_plan_resolution(self):
        """Build contexts with mid-year plan change and verify interval updates."""
        plans = pd.DataFrame([
            {"plan_id": "CPL-01", "interval_days": 90, "tolerance_pct": 1.0},
            {"plan_id": "CPL-02", "interval_days": 180, "tolerance_pct": 1.0},
        ])
        inst = pd.DataFrame([{"instrument_id": "INS-01", "asset_id": "AST-01"}])
        asg = pd.DataFrame([
            {"assignment_id": "ASG-01", "instrument_id": "INS-01", "plan_id": "CPL-01", "effective_from": "2026-01-01", "effective_to": "2026-06-30"},
            {"assignment_id": "ASG-02", "instrument_id": "INS-01", "plan_id": "CPL-02", "effective_from": "2026-07-01", "effective_to": ""},
        ])
        events = pd.DataFrame([
            {"calibration_id": "CAL-01", "instrument_id": "INS-01", "calibration_date": "2026-03-01", "result": "PASS", "plan_id": "CPL-01"},
            {"calibration_id": "CAL-02", "instrument_id": "INS-01", "calibration_date": "2026-08-01", "result": "PASS", "plan_id": "CPL-01"}, # old plan recorded on event
        ])
        certs = pd.DataFrame([
            {"cert_id": "CRT-01", "calibration_id": "CAL-01", "instrument_id": "INS-01", "asset_id": "AST-01", "status": "VALID", "range_max": 100, "version": 1},
            {"cert_id": "CRT-02", "calibration_id": "CAL-02", "instrument_id": "INS-01", "asset_id": "AST-01", "status": "VALID", "range_max": 100, "version": 1},
        ])
        T = {
            "calibration_plan": plans,
            "instrument": inst,
            "instrument_plan_assignment": asg,
            "calibration_event": events,
            "certificate": certs,
            "work_order": pd.DataFrame(),
            "extension": pd.DataFrame(),
        }
        ctx, _ = rules.build_contexts(T)
        c = ctx["INS-01"]
        # CAL-01 had 90 days: 2026-03-01 + 90 days = 2026-05-30
        self.assertEqual(c["ev"][0][2], self.d(2026, 5, 30))
        # CAL-02 happened on 2026-08-01, effective plan is CPL-02 with 180 days: 2026-08-01 + 180 days = 2027-01-28
        self.assertEqual(c["ev"][1][2], self.d(2027, 1, 28))


if __name__ == "__main__":
    unittest.main()
