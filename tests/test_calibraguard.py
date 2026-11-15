import datetime as dt, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import generate, detect, validate, rules

class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp(); generate.generate(20261022, 200, 500, 8000, cls.out); detect.run(cls.out); cls.M = validate.run(cls.out, skip_repro=True)
    def test_integrity(self): self.assertEqual((self.M["pk_errors"], self.M["fk_errors"], self.M["enum_errors"], self.M["lifecycle_errors"]), (0, 0, 0, 0))
    def test_detection_matches_ground_truth(self): self.assertEqual((self.M["precision"], self.M["recall"]), (1.0, 1.0))
    def test_prohibited_use(self): self.assertEqual(self.M["prohibited_use_detection_pct"], 100.0); self.assertEqual(self.M["false_blocks"], 0)
    def test_reproducible(self): self.assertTrue(validate.repro(dict(n_inst=200, n_cal=500, n_use=3000), 20261022))
    def test_rules(self):
        d = dt.date; c = {"asset": "A", "dates": [d(2026, 1, 1)], "maint": [], "ext": [], "ev": [(d(2026, 1, 1), "PASS", d(2026, 4, 1), "CAL-1", "OK")]}
        self.assertEqual(rules.decide(c, d(2026, 4, 1))[0], "ALLOW"); self.assertEqual(rules.decide(c, d(2026, 4, 2))[1], "EXPIRED_USE")
        c["ext"] = [("E1", d(2026, 4, 2), d(2026, 4, 5), "QUALITY_ENGINEER", "APPROVED")]; self.assertEqual(rules.decide(c, d(2026, 4, 3))[0], "ALLOW_WITH_EXCEPTION"); self.assertEqual(rules.decide(c, d(2026, 4, 6))[1], "EXTENSION_EXPIRED_USE")
        c["ext"] = [("E2", d(2026, 4, 2), d(2026, 4, 5), "PLANT_OPERATOR", "APPROVED")]; self.assertEqual(rules.decide(c, d(2026, 4, 3))[1], "EXT_UNAUTHORIZED_USE")
        c["ev"].append((d(2026, 4, 2), "FAIL", d(2026, 7, 1), "CAL-2", "NONE")); c["dates"].append(d(2026, 4, 2)); self.assertEqual(rules.decide(c, d(2026, 4, 3))[1], "QUARANTINED_USE")
if __name__ == "__main__": unittest.main()
