"""Unit tests for calibraguard/auth.py: authentication, token validation, and RBAC."""
import unittest
import time
from calibraguard.auth import (
    authenticate,
    create_token,
    verify_token,
    extract_user,
    has_permission,
    USERS,
)


class TestAuth(unittest.TestCase):
    def test_successful_login(self):
        user = authenticate("qe1", "Quality@123")
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "QUALITY_ENGINEER")
        self.assertEqual(user["username"], "qe1")
        self.assertIn("token", user)

    def test_failed_login_bad_password(self):
        user = authenticate("qe1", "WrongPassword")
        self.assertIsNone(user)

    def test_failed_login_unknown_user(self):
        user = authenticate("unknown_user", "AnyPassword")
        self.assertIsNone(user)

    def test_token_verification_valid(self):
        token = create_token(USERS["operator1"])
        payload = verify_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["sub"], "operator1")
        self.assertEqual(payload["role"], "PLANT_OPERATOR")

    def test_token_tampering_detected(self):
        token = create_token(USERS["operator1"])
        # Tamper payload part
        parts = token.split(".")
        tampered = parts[0][:-2] + "ab." + parts[1]
        self.assertIsNone(verify_token(tampered))

    def test_extract_user_from_headers(self):
        token = create_token(USERS["manager1"])
        headers = {"Authorization": f"Bearer {token}"}
        user = extract_user(headers)
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "PLANT_MANAGER")

    def test_rbac_permissions(self):
        self.assertTrue(has_permission("QUALITY_ENGINEER", "RELEASE_INSTRUMENT"))
        self.assertFalse(has_permission("PLANT_OPERATOR", "RELEASE_INSTRUMENT"))
        self.assertFalse(has_permission("PRODUCTION_PLANNER", "RECORD_CALIBRATION"))
        self.assertTrue(has_permission("PLANT_OPERATOR", "CHECK_USE"))


if __name__ == "__main__":
    unittest.main()
