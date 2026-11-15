"""CalibraGuard Authentication & Server-Side Role-Based Access Control (RBAC).
Security Hardening:
- PBKDF2-HMAC-SHA256 password hashing with 100,000 iterations and per-user cryptographic salts.
- HMAC-SHA256 cryptographically signed session tokens with constant-time comparison.
- Strict token expiration enforcement.
- Granular permission matrix across industrial personas.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time

SECRET_KEY = os.environ.get("CALIBRAGUARD_SECRET", "calibraguard-prod-secret-key-20261022-industrial-jwt").encode("utf-8")
TOKEN_TTL_SECONDS = 86400  # 24 hours
PBKDF2_ITERATIONS = 100_000


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Generates (salt, pbkdf2_hash) using PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS)
    return salt, key.hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """Verifies password using PBKDF2 with constant-time comparison."""
    _, computed_hash = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, expected_hash)


# Pre-seeded test & demonstration accounts (with distinct individual salts and PBKDF2 hashes)
# Passwords:
# operator1: Operator@123
# qe1:       Quality@123
# planner1:  Planner@123
# manager1:  Manager@123
# admin1:    Admin@123

_SEED_USERS_RAW = {
    "operator1": ("OP-0001", "PLANT_OPERATOR", "John Doe (Plant Operator)", "Operator@123", "salt_op_9831a2"),
    "qe1": ("U-QE-001", "QUALITY_ENGINEER", "Sarah Lin (Lead QE)", "Quality@123", "salt_qe_44b8f1"),
    "planner1": ("U-PL-001", "PRODUCTION_PLANNER", "Bob Smith (Production Planner)", "Planner@123", "salt_pl_19cd3e"),
    "manager1": ("U-PM-001", "PLANT_MANAGER", "Alice Wong (Plant Manager)", "Manager@123", "salt_pm_7822fe"),
    "admin1": ("U-AD-001", "OT_ADMIN", "Dave Miller (OT/IT Admin)", "Admin@123", "salt_ad_55a109"),
}

USERS = {}
for uname, (uid, role, name, pw, s) in _SEED_USERS_RAW.items():
    _, phash = hash_password(pw, s)
    USERS[uname] = {
        "user_id": uid,
        "username": uname,
        "salt": s,
        "password_hash": phash,
        "role": role,
        "name": name,
    }

ROLE_PERMISSIONS = {
    "PLANT_OPERATOR": {"CHECK_USE", "RECORD_USE", "VIEW_REGISTRY", "VIEW_METRICS"},
    "PRODUCTION_PLANNER": {"VIEW_REGISTRY", "VIEW_METRICS", "VIEW_WORK_ORDERS", "VIEW_PLANNING"},
    "QUALITY_ENGINEER": {
        "CHECK_USE", "RECORD_USE", "VIEW_REGISTRY", "VIEW_METRICS", "VIEW_WORK_ORDERS",
        "RECORD_CALIBRATION", "RELEASE_INSTRUMENT", "APPROVE_EXTENSION", "INVESTIGATE_FAILURE", "VIEW_AUDIT"
    },
    "PLANT_MANAGER": {
        "CHECK_USE", "RECORD_USE", "VIEW_REGISTRY", "VIEW_METRICS", "VIEW_WORK_ORDERS",
        "RECORD_CALIBRATION", "RELEASE_INSTRUMENT", "APPROVE_EXTENSION", "INVESTIGATE_FAILURE", "VIEW_AUDIT",
        "OVERRIDE_POLICY"
    },
    "OT_ADMIN": {
        "CHECK_USE", "RECORD_USE", "VIEW_REGISTRY", "VIEW_METRICS", "VIEW_WORK_ORDERS",
        "RECORD_CALIBRATION", "RELEASE_INSTRUMENT", "APPROVE_EXTENSION", "INVESTIGATE_FAILURE", "VIEW_AUDIT",
        "OVERRIDE_POLICY", "MANAGE_USERS", "MANAGE_POLICIES"
    },
}


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64_decode(s: str) -> bytes:
    padding = 4 - (len(s) % 4)
    if padding and padding < 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s.encode("utf-8"))


def create_token(user: dict, ttl: int = TOKEN_TTL_SECONDS) -> str:
    now = int(time.time())
    payload = {
        "sub": user["username"],
        "user_id": user["user_id"],
        "role": user["role"],
        "name": user["name"],
        "iat": now,
        "exp": now + ttl,
    }
    payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = _b64_encode(payload_json)
    sig = hmac.new(SECRET_KEY, payload_b64.encode("utf-8"), hashlib.sha256).digest()
    sig_b64 = _b64_encode(sig)
    return f"{payload_b64}.{sig_b64}"


def verify_token(token: str) -> dict | None:
    if not token or "." not in token:
        return None
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        expected_sig = hmac.new(SECRET_KEY, payload_b64.encode("utf-8"), hashlib.sha256).digest()
        actual_sig = _b64_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        payload = json.loads(_b64_decode(payload_b64).decode("utf-8"))
        if payload.get("exp", 0) < int(time.time()):
            return None  # Expired token
        return payload
    except Exception:
        return None


def authenticate(username: str, password: str) -> dict | None:
    user = USERS.get(username)
    if not user:
        return None
    if verify_password(password, user["salt"], user["password_hash"]):
        return {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "name": user["name"],
            "token": create_token(user),
        }
    return None


def extract_user(headers: dict) -> dict | None:
    """Extract authenticated user payload from Authorization: Bearer <token> or X-Auth-Token."""
    auth_header = headers.get("Authorization") or headers.get("authorization") or ""
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "X-Auth-Token" in headers:
        token = headers["X-Auth-Token"].strip()
    elif "x-auth-token" in headers:
        token = headers["x-auth-token"].strip()

    if not token:
        return None
    return verify_token(token)


def has_permission(user_role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(user_role, set())
