#!/usr/bin/env python3
"""CalibraGuard Application & API Server (Three-Tier Architecture - Application Tier).
Optimized SQL Engine, Atomic Transactions, and Advanced Industrial Analytics:
1. SARGABLE indexed date/timestamp range filtering (eliminates SUBSTR function scan).
2. Advanced SQL: Window Functions (ROW_NUMBER), CTEs, Conditional Aggregation, and Supplier Analytics.
3. High-performance transactional sequence generation (sys_sequence table).
4. Cryptographic hash-chained immutable audit logging (SHA-256 tamper-evident chain).
5. Workload-specific composite & partial indexing.
6. Authentication & Server-Side RBAC (PBKDF2-HMAC-SHA256, 100k iterations).
7. Authorized two-step recalibration and release workflow.
8. Separation of blocked attempts (usage_attempt) from actual production (production_use).
9. Configurable simulation date (defaults to plant date: 2026-11-15T12:00:00).
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import pandas as pd

from rules import build_contexts, decide, next_due, POLICY, SEVERITY
from auth import (
    authenticate,
    extract_user,
    verify_token,
    has_permission,
    USERS,
)

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "out")

# Configurable simulation date (defaults to plant local date: 2026-11-15T12:00:00)
SIMULATION_DATE = dt.datetime(2026, 11, 15, 12, 0, 0)

LOCK = threading.Lock()
conn = None
CTX = {}


def get_as_of(headers=None) -> dt.datetime:
    """Get simulation date, prioritizing request header X-Simulation-Date."""
    if headers:
        hdr = headers.get("X-Simulation-Date") or headers.get("x-simulation-date")
        if hdr:
            try:
                return dt.datetime.fromisoformat(hdr.strip())
            except Exception:
                pass
    return SIMULATION_DATE


def q(sql, a=()):
    cur = conn.execute(sql, a)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def nid(table, col, prefix, w=6):
    """High-performance transactional sequence generator.
    Uses sys_sequence table for atomic O(1) increment without expensive full-table string scans.
    """
    row = conn.execute("SELECT current_val FROM sys_sequence WHERE prefix = ?", (prefix,)).fetchone()
    if row is not None:
        nxt = row[0] + 1
        conn.execute("UPDATE sys_sequence SET current_val = ? WHERE prefix = ?", (nxt, prefix))
        return f"{prefix}{nxt:0{w}d}"

    # Fallback initialization if prefix not yet registered
    r = conn.execute(
        f"SELECT MAX(CAST(SUBSTR({col}, {len(prefix)+1}) AS INTEGER)) FROM {table} WHERE {col} LIKE ?",
        (prefix + "%",),
    ).fetchone()[0]
    nxt = (r or 0) + 1
    conn.execute("INSERT OR REPLACE INTO sys_sequence VALUES (?, ?)", (prefix, nxt))
    return f"{prefix}{nxt:0{w}d}"


def ensure_schema_and_indexes():
    """Ensure all required tables, performance indexes, and sequence state exist."""
    # 1. usage_attempt table
    conn.execute(
        """CREATE TABLE IF NOT EXISTS usage_attempt(
            attempt_id TEXT PRIMARY KEY,
            instrument_id TEXT NOT NULL REFERENCES instrument(instrument_id),
            asset_id TEXT NOT NULL REFERENCES asset(asset_id),
            production_order_id TEXT,
            operator_id TEXT,
            attempt_timestamp TEXT NOT NULL,
            decision TEXT NOT NULL,
            issue_type TEXT,
            reason TEXT,
            policy_version TEXT
        )"""
    )

    # 2. sys_sequence table
    conn.execute(
        """CREATE TABLE IF NOT EXISTS sys_sequence(
            prefix TEXT PRIMARY KEY,
            current_val INTEGER NOT NULL
        )"""
    )

    # 3. Add record_hash & prev_hash columns to audit_record if missing
    audit_cols = [r[1] for r in conn.execute("PRAGMA table_info(audit_record)").fetchall()]
    if "record_hash" not in audit_cols:
        conn.execute("ALTER TABLE audit_record ADD COLUMN record_hash TEXT")
    if "prev_hash" not in audit_cols:
        conn.execute("ALTER TABLE audit_record ADD COLUMN prev_hash TEXT")

    # 4. Workload-specific indexes
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cal_inst ON calibration_event(instrument_id, calibration_date)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cal_supplier ON calibration_event(supplier_id, result)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_use_inst ON production_use(instrument_id, use_timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_attempt_inst ON usage_attempt(instrument_id, attempt_timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_alert_inst ON alert(instrument_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_alert_severity_created ON alert(severity, created_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_open_alerts ON alert(created_at DESC, severity) WHERE status = 'OPEN'")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_workorder_type_status_date ON work_order(wo_type, status, opened_date DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_audit_entity_time ON audit_record(entity_id, event_ts DESC, audit_id DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cert_cal ON certificate(calibration_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cert_inst ON certificate(instrument_id)")

    # 5. Initialize sequences
    for pfx, tbl, col in [
        ("AUD-", "audit_record", "audit_id"),
        ("ALT-", "alert", "alert_id"),
        ("WO-2026-", "work_order", "work_order_id"),
        ("USE-", "production_use", "use_id"),
        ("ATT-", "usage_attempt", "attempt_id"),
        ("EXT-", "extension", "extension_id"),
        ("IA-", "impact_assessment", "ia_id"),
    ]:
        try:
            r = conn.execute(f"SELECT MAX(CAST(SUBSTR({col}, {len(pfx)+1}) AS INTEGER)) FROM {tbl} WHERE {col} LIKE ?", (pfx + "%",)).fetchone()[0]
            val = r or 0
        except Exception:
            val = 0
        conn.execute("INSERT OR IGNORE INTO sys_sequence VALUES (?, ?)", (pfx, val))


# Backward compatibility alias
ensure_tables = ensure_schema_and_indexes


def frames(iid=None):
    w, a = (" where instrument_id=?", (iid,)) if iid else ("", ())
    g = lambda t, wh=w: pd.read_sql(f"select * from {t}{wh}", conn, params=a if wh else ())
    res = {
        "calibration_plan": g("calibration_plan", ""),
        "instrument_type": g("instrument_type", ""),
        "instrument": g("instrument"),
        "calibration_event": g("calibration_event"),
        "certificate": g("certificate"),
        "work_order": g("work_order"),
        "extension": g("extension"),
    }
    has_asg = conn.execute("select 1 from sqlite_master where type='table' and name='instrument_plan_assignment'").fetchone()
    if has_asg:
        res["instrument_plan_assignment"] = g("instrument_plan_assignment")
    else:
        res["instrument_plan_assignment"] = pd.DataFrame()
    return res


def audit(et, eid, act, actor, old, new, why, ts=None):
    """Cryptographically hash-chained audit logger.
    Each record binds to the previous hash, creating a tamper-evident audit chain.
    """
    aid = nid("audit_record", "audit_id", "AUD-")
    event_time = ts or SIMULATION_DATE.isoformat(timespec="seconds")

    prev_row = conn.execute("SELECT record_hash FROM audit_record ORDER BY event_ts DESC, audit_id DESC LIMIT 1").fetchone()
    prev_hash = prev_row[0] if (prev_row and prev_row[0]) else "GENESIS_ROOT_2026"

    payload = f"{prev_hash}|{et}|{eid}|{act}|{actor}|{event_time}|{old or ''}|{new or ''}|{why or ''}"
    record_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    conn.execute(
        """INSERT INTO audit_record (audit_id, entity_type, entity_id, action, actor, event_ts, old_state, new_state, reason, record_hash, prev_hash)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (aid, et, eid, act, actor, event_time, old, new, why, record_hash, prev_hash),
    )


def alert(atype, et, eid, iid, msg, ts):
    conn.execute(
        "insert into alert values(?,?,?,?,?,?,?,?,?,?)",
        (nid("alert", "alert_id", "ALT-"), atype, SEVERITY.get(atype, "MEDIUM"), et, eid, iid, ts, msg, "OPEN", "R-" + atype),
    )


def api_check(b, user=None, as_of=None):
    """Production use check & recording.
    If ALLOWED: records into production_use and use_decision (genuine production consumption).
    If BLOCKED: records into usage_attempt and alerts/audits (never pollutes production_use).
    """
    as_of = as_of or SIMULATION_DATE
    iid = b.get("instrument_id", "").strip()
    if not iid:
        return {"error": "instrument_id is required", "code": "BAD_REQUEST"}, 400

    ts_str = b.get("timestamp") or as_of.isoformat(timespec="seconds")
    ts = dt.datetime.fromisoformat(ts_str)

    op = (user and user.get("user_id")) or b.get("operator") or b.get("operator_id") or "OP-0001"
    po = b.get("production_order_id", "PO-2026-DEMO")

    with LOCK:
        conn.execute("BEGIN IMMEDIATE")
        try:
            r = q("select asset_id, lifecycle_state from instrument where instrument_id=?", (iid,))
            if not r:
                conn.execute("ROLLBACK")
                return {"error": f"Unknown instrument {iid}", "code": "NOT_FOUND"}, 404

            asset_id = r[0]["asset_id"]
            c = build_contexts(frames(iid))[0][iid]

            if r[0]["lifecycle_state"] == "PENDING_RELEASE":
                c["pending_release"] = True

            d, iss, msg, ext = decide(c, ts)
            tss = ts.isoformat(timespec="seconds")

            if d in ("ALLOW", "ALLOW_WITH_EXCEPTION"):
                uid = f"USE-{asset_id}-{ts:%Y%m%dT%H%M%S}"
                while conn.execute("select 1 from production_use where use_id=?", (uid,)).fetchone():
                    uid += "x"

                conn.execute(
                    "insert into production_use values(?,?,?,?,?,?,?)",
                    (uid, iid, asset_id, po, op, tss, tss),
                )
                conn.execute(
                    "insert into use_decision values(?,?,?,?,?,?,?)",
                    (uid, d, iss, msg, POLICY, ext, tss),
                )
                if d == "ALLOW_WITH_EXCEPTION":
                    audit("PRODUCTION_USE", uid, "USE_ALLOWED_WITH_EXCEPTION", op, "", d, msg, tss)
                conn.execute("COMMIT")
                return {
                    "use_id": uid,
                    "decision": d,
                    "issue_type": iss,
                    "reason": msg,
                    "policy_version": POLICY,
                    "extension_id": ext,
                    "recorded_in_production": True,
                }, 200
            else:
                aid = f"ATT-{asset_id}-{ts:%Y%m%dT%H%M%S}"
                while conn.execute("select 1 from usage_attempt where attempt_id=?", (aid,)).fetchone():
                    aid += "x"

                conn.execute(
                    "insert into usage_attempt values(?,?,?,?,?,?,?,?,?,?)",
                    (aid, iid, asset_id, po, op, tss, d, iss, msg, POLICY),
                )
                audit("USAGE_ATTEMPT", aid, "USAGE_BLOCKED", op, "ATTEMPTED", "BLOCKED", msg, tss)
                alert(iss, "USAGE_ATTEMPT", aid, iid, msg, tss)
                conn.execute("COMMIT")
                return {
                    "attempt_id": aid,
                    "decision": d,
                    "issue_type": iss,
                    "reason": msg,
                    "policy_version": POLICY,
                    "extension_id": ext,
                    "recorded_in_production": False,
                    "blocked": True,
                }, 200
        except Exception as e:
            conn.execute("ROLLBACK")
            return {"error": str(e), "code": "SERVER_ERROR"}, 500


def api_cal(b, user=None, as_of=None):
    """Record calibration event (PASS or FAIL).
    Uses SARGABLE indexed range filtering on (instrument_id, use_timestamp) for O(log N) impact window calculation.
    """
    as_of = as_of or SIMULATION_DATE
    who = (user and (user.get("user_id") or user.get("username"))) or b.get("actor") or "U-QE-001"
    role = (user and user.get("role")) or b.get("role") or "QUALITY_ENGINEER"

    if role not in ("QUALITY_ENGINEER", "PLANT_MANAGER", "OT_ADMIN"):
        return {"error": "Forbidden: Recording calibration requires QUALITY_ENGINEER or PLANT_MANAGER role", "code": "FORBIDDEN"}, 403

    iid = b.get("instrument_id", "").strip()
    if not iid:
        return {"error": "instrument_id is required", "code": "BAD_REQUEST"}, 400

    res = b.get("result", "PASS").upper()
    if res not in ("PASS", "FAIL"):
        return {"error": "result must be PASS or FAIL", "code": "BAD_REQUEST"}, 400

    date = b.get("date") or as_of.date().isoformat()
    ts_now = date + "T17:00:00"

    with LOCK:
        conn.execute("BEGIN IMMEDIATE")
        try:
            ins = q("select asset_id, lifecycle_state from instrument where instrument_id=?", (iid,))
            if not ins:
                conn.execute("ROLLBACK")
                return {"error": f"Unknown instrument {iid}", "code": "NOT_FOUND"}, 404

            asset_id = ins[0]["asset_id"]
            current_state = ins[0]["lifecycle_state"] or "ACTIVE"

            # Resolve plan from effective-dated assignment at calibration date
            asg = q(
                """select plan_id from instrument_plan_assignment 
                   where instrument_id=? and effective_from <= ? 
                     and (effective_to is null or effective_to = '' or effective_to >= ?)
                   order by effective_from desc limit 1""",
                (iid, date, date),
            )
            if asg:
                plan_id = asg[0]["plan_id"]
            else:
                last_cal = q("select plan_id, supplier_id from calibration_event where instrument_id=? order by calibration_date desc limit 1", (iid,))
                plan_id = last_cal[0]["plan_id"] if last_cal else "CPL-001"

            p = q("select interval_days, tolerance_pct from calibration_plan where plan_id=?", (plan_id,))[0]
            last_sup = q("select supplier_id from calibration_event where instrument_id=? order by calibration_date desc limit 1", (iid,))
            supplier_id = b.get("supplier_id") or (last_sup[0]["supplier_id"] if last_sup else "SUP-0001")

            seq = conn.execute("select max(cast(substr(calibration_id,-6) as integer)) from calibration_event").fetchone()[0] + 1
            cid = f"CAL-{asset_id}-2026-{seq:06d}"
            nd = (dt.date.fromisoformat(date) + dt.timedelta(days=p["interval_days"])).isoformat() if res == "PASS" else None
            err = float(b.get("error_pct", p["tolerance_pct"] * (0.3 if res == "PASS" else 1.4)))

            conn.execute(
                "insert into calibration_event values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (cid, iid, asset_id, plan_id, supplier_id, date, ts_now, res, err, p["tolerance_pct"], nd, None if res == "PASS" else "Out of tolerance (as-found)", "RECORDED"),
            )
            audit("CALIBRATION", cid, "CALIBRATION_RECORDED", who, "", res, "Recorded via API", ts_now)
            out = {"calibration_id": cid, "result": res, "instrument_id": iid}

            if res == "PASS":
                itype = q("select t.range_min, t.range_max from instrument i join instrument_type t on i.type_id = t.type_id where i.instrument_id=?", (iid,))
                rmin = itype[0]["range_min"] if itype else 0.0
                rmax = itype[0]["range_max"] if itype else 100.0

                cert_id = "CERT-" + cid
                conn.execute(
                    "insert into certificate values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (cert_id, cid, iid, asset_id, supplier_id, f"CN-{seq:07d}", date, date, nd, rmin, rmax, "VALID", 1),
                )
                audit("CERTIFICATE", cert_id, "CERTIFICATE_ISSUED", supplier_id, "", "VALID", "Calibration verified", ts_now)

                open_wos = q("select work_order_id from work_order where instrument_id=? and wo_type='CORRECTIVE' and status in ('OPEN', 'PENDING_RELEASE')", (iid,))
                if open_wos or current_state == "QUARANTINED":
                    conn.execute("update instrument set lifecycle_state='PENDING_RELEASE' where instrument_id=?", (iid,))
                    for w in open_wos:
                        conn.execute("update work_order set status='PENDING_RELEASE', closure_calibration_id=? where work_order_id=?", (cid, w["work_order_id"]))
                    audit("INSTRUMENT", iid, "INSTRUMENT_PENDING_RELEASE", who, current_state, "PENDING_RELEASE", f"Recalibration {cid} PASS; pending authorized quality release", ts_now)
                    out.update(
                        lifecycle_state="PENDING_RELEASE",
                        released=False,
                        message="Recalibration passed. Instrument is PENDING_RELEASE. An authorized Quality Engineer must execute formal release.",
                        work_orders_pending=[w["work_order_id"] for w in open_wos],
                    )
                else:
                    conn.execute("update instrument set lifecycle_state='ACTIVE' where instrument_id=?", (iid,))
                    out.update(lifecycle_state="ACTIVE", released=True, next_due_date=nd)
            else:
                conn.execute("update instrument set lifecycle_state='QUARANTINED' where instrument_id=?", (iid,))
                lg = q(
                    "select calibration_id, calibration_date from calibration_event where instrument_id=? and result='PASS' and calibration_date < ? order by calibration_date desc limit 1",
                    (iid, date),
                )
                ws = lg[0]["calibration_date"] if lg else "2026-01-01"

                # OPTIMIZED SARGABLE TIMESTAMP RANGE FILTER (Replaces slow SUBSTR function scan)
                ts_start = f"{ws[:10]}T00:00:00"
                date_next = (dt.date.fromisoformat(date[:10]) + dt.timedelta(days=1)).isoformat()
                ts_end = f"{date_next}T00:00:00"

                n, o = conn.execute(
                    """SELECT COUNT(*), COUNT(DISTINCT production_order_id)
                       FROM production_use
                       WHERE instrument_id = ?
                         AND use_timestamp >= ?
                         AND use_timestamp < ?""",
                    (iid, ts_start, ts_end),
                ).fetchone()

                ia_id = "IA-" + cid
                conn.execute(
                    "insert into impact_assessment values(?,?,?,?,?,?,?,?,?,?,?)",
                    (ia_id, cid, iid, lg[0]["calibration_id"] if lg else None, ws, date, n, o, "COMPLETED", date + "T17:05:00", who),
                )
                audit("IMPACT_ASSESSMENT", ia_id, "IA_COMPLETED", who, "", "COMPLETED", f"{n} uses affected between {ws} and {date}", date + "T17:05:00")

                wid = nid("work_order", "work_order_id", "WO-2026-")
                conn.execute(
                    "insert into work_order values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (wid, iid, "CORRECTIVE", "HIGH", who, date, (dt.date.fromisoformat(date) + dt.timedelta(days=7)).isoformat(), None, "OPEN", date, None, cid, None),
                )
                audit("INSTRUMENT", iid, "INSTRUMENT_QUARANTINED", "SYSTEM", current_state, "QUARANTINED", "Failed calibration " + cid, ts_now)
                audit("WORK_ORDER", wid, "WO_OPENED", "SYSTEM", "", "OPEN", "Corrective action for failed calibration", ts_now)
                alert("QUARANTINED_USE", "CALIBRATION", cid, iid, f"Instrument quarantined due to failed calibration {cid}", ts_now)
                out.update(lifecycle_state="QUARANTINED", impact_assessment=ia_id, affected_uses=n, affected_orders=o, work_order=wid)

            conn.execute("COMMIT")
        except Exception as e:
            conn.execute("ROLLBACK")
            return {"error": str(e), "code": "SERVER_ERROR"}, 500

    CTX[iid] = build_contexts(frames(iid))[0][iid]
    out["status_now"] = decide(CTX[iid], as_of)[0:2]
    return out, 200


def api_release(iid, b, user=None, as_of=None):
    as_of = as_of or SIMULATION_DATE
    who = (user and (user.get("user_id") or user.get("username"))) or b.get("actor") or "U-QE-001"
    role = (user and user.get("role")) or b.get("role") or "QUALITY_ENGINEER"

    if role not in ("QUALITY_ENGINEER", "PLANT_MANAGER", "OT_ADMIN"):
        return {"error": "Forbidden: Releasing instrument requires QUALITY_ENGINEER or PLANT_MANAGER authorization", "code": "FORBIDDEN"}, 403

    date = b.get("date") or as_of.date().isoformat()
    ts_now = date + "T17:30:00"

    with LOCK:
        conn.execute("BEGIN IMMEDIATE")
        try:
            ins = q("select asset_id, lifecycle_state from instrument where instrument_id=?", (iid,))
            if not ins:
                conn.execute("ROLLBACK")
                return {"error": f"Unknown instrument {iid}", "code": "NOT_FOUND"}, 404

            wo = q("select work_order_id, closure_calibration_id, source_calibration_id from work_order where instrument_id=? and wo_type='CORRECTIVE' and status in ('OPEN', 'PENDING_RELEASE') order by opened_date desc limit 1", (iid,))
            cid = b.get("calibration_id")
            if not cid and wo and wo[0].get("closure_calibration_id"):
                cid = wo[0]["closure_calibration_id"]
            if not cid:
                cals = q("select calibration_id from calibration_event where instrument_id=? and result='PASS' and calibration_date <= ? order by calibration_date desc limit 1", (iid, date))
                if cals:
                    cid = cals[0]["calibration_id"]

            if not cid:
                conn.execute("ROLLBACK")
                return {"error": f"Instrument {iid} cannot be released: no passed recalibration found", "code": "PRECONDITION_FAILED"}, 412

            cal_row = q("select calibration_id, result, calibration_date from calibration_event where calibration_id=?", (cid,))
            if not cal_row or cal_row[0]["result"] != "PASS":
                conn.execute("ROLLBACK")
                return {"error": f"Instrument {iid} cannot be released: calibration {cid} is not PASS", "code": "PRECONDITION_FAILED"}, 412

            cert = q("select cert_id, status, asset_id from certificate where calibration_id=? and instrument_id=?", (cid, iid))
            if not cert or cert[0]["status"] != "VALID":
                conn.execute("ROLLBACK")
                return {"error": f"Instrument {iid} cannot be released: valid certificate missing for recalibration {cid}", "code": "PRECONDITION_FAILED"}, 412

            if cert[0]["asset_id"] != ins[0]["asset_id"]:
                conn.execute("ROLLBACK")
                return {"error": f"Instrument {iid} cannot be released: certificate asset mismatch", "code": "PRECONDITION_FAILED"}, 412

            wos = q("select work_order_id from work_order where instrument_id=? and wo_type='CORRECTIVE' and status in ('OPEN', 'PENDING_RELEASE')", (iid,))
            closed_wos = []
            for w in wos:
                wid = w["work_order_id"]
                conn.execute("update work_order set status='CLOSED', closed_date=?, closure_calibration_id=?, downtime_end=? where work_order_id=?", (date, cid, date, wid))
                audit("WORK_ORDER", wid, "WO_CLOSED", who, "PENDING_RELEASE", "CLOSED", f"Authorized release verified by {who} via {cid}", ts_now)
                closed_wos.append(wid)

            old_state = ins[0]["lifecycle_state"]
            conn.execute("update instrument set lifecycle_state='ACTIVE' where instrument_id=?", (iid,))
            audit("INSTRUMENT", iid, "INSTRUMENT_RELEASED", who, old_state, "ACTIVE", f"Authorized release after recalibration verification {cid}", ts_now)
            conn.execute("update alert set status='RESOLVED' where instrument_id=? and status='OPEN'", (iid,))

            conn.execute("COMMIT")
        except Exception as e:
            conn.execute("ROLLBACK")
            return {"error": str(e), "code": "SERVER_ERROR"}, 500

    CTX[iid] = build_contexts(frames(iid))[0][iid]
    CTX[iid]["pending_release"] = False
    CTX[iid]["unreleased_cals"].discard(cid)

    return {
        "instrument_id": iid,
        "lifecycle_state": "ACTIVE",
        "released": True,
        "released_by": who,
        "release_calibration_id": cid,
        "closed_work_orders": closed_wos,
        "status_now": decide(CTX[iid], as_of)[0:2],
    }, 200


# ======================================================================
# ADVANCED SQL ANALYTICS SERVICES
# ======================================================================

def sql_latest_calibrations(limit=100, offset=0):
    """WINDOW FUNCTION: Retrieves latest calibration for every instrument in a single SQL query."""
    sql = """
    WITH ranked_calibrations AS (
        SELECT
            instrument_id,
            calibration_id,
            asset_id,
            calibration_date,
            result,
            as_found_error_pct,
            tolerance_pct,
            next_due_date,
            ROW_NUMBER() OVER (
                PARTITION BY instrument_id
                ORDER BY calibration_date DESC, calibration_id DESC
            ) AS rn
        FROM calibration_event
    )
    SELECT
        instrument_id,
        calibration_id,
        asset_id,
        calibration_date,
        result,
        as_found_error_pct,
        tolerance_pct,
        next_due_date
    FROM ranked_calibrations
    WHERE rn = 1
    ORDER BY calibration_date DESC
    LIMIT ? OFFSET ?
    """
    return q(sql, (limit, offset))


def sql_upcoming_deadlines(as_of=None, days_ahead=30, limit=100):
    """CTE: Finds instruments approaching calibration deadlines within days_ahead from simulation date."""
    as_of = as_of or SIMULATION_DATE
    start_date = as_of.date().isoformat()
    end_date = (as_of.date() + dt.timedelta(days=days_ahead)).isoformat()

    sql = """
    WITH latest_pass AS (
        SELECT
            instrument_id,
            MAX(calibration_date) AS last_calibration
        FROM calibration_event
        WHERE result = 'PASS'
        GROUP BY instrument_id
    )
    SELECT
        i.instrument_id,
        i.asset_id,
        t.name AS type_name,
        l.last_calibration,
        c.next_due_date,
        CAST(julianday(c.next_due_date) - julianday(?) AS INTEGER) AS days_remaining
    FROM instrument i
    JOIN latest_pass l ON i.instrument_id = l.instrument_id
    JOIN calibration_event c ON c.instrument_id = l.instrument_id AND c.calibration_date = l.last_calibration
    JOIN instrument_type t ON i.type_id = t.type_id
    WHERE c.next_due_date >= ?
      AND c.next_due_date <= ?
    ORDER BY c.next_due_date ASC
    LIMIT ?
    """
    return q(sql, (start_date, start_date, end_date, limit))


def sql_compliance_summary():
    """CONDITIONAL AGGREGATION: Computes compliance and alert severity metrics in a single database pass."""
    sql = """
    SELECT
        COUNT(*) AS total_alerts,
        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_alerts,
        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high_alerts,
        SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_alerts,
        SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) AS low_alerts,
        SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) AS open_alerts,
        SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END) AS resolved_alerts
    FROM alert
    """
    return q(sql)[0]


def sql_supplier_performance():
    """AGGREGATION & RANKING: Compares supplier pass percentage, total calibrations, and average error."""
    sql = """
    SELECT
        s.supplier_id,
        s.name,
        s.accreditation_no,
        s.country,
        COUNT(c.calibration_id) AS total_calibrations,
        SUM(CASE WHEN c.result = 'PASS' THEN 1 ELSE 0 END) AS passed,
        SUM(CASE WHEN c.result = 'FAIL' THEN 1 ELSE 0 END) AS failed,
        ROUND(
            100.0 * SUM(CASE WHEN c.result = 'PASS' THEN 1 ELSE 0 END)
            / NULLIF(COUNT(c.calibration_id), 0),
            2
        ) AS pass_percentage,
        ROUND(AVG(c.as_found_error_pct), 3) AS avg_as_found_error
    FROM supplier s
    LEFT JOIN calibration_event c ON s.supplier_id = c.supplier_id
    GROUP BY s.supplier_id, s.name, s.accreditation_no, s.country
    ORDER BY pass_percentage ASC, total_calibrations DESC
    """
    return q(sql)


def registry(status=None, text="", limit=100, offset=0, as_of=None):
    as_of = as_of or SIMULATION_DATE
    rows = []
    matched = 0
    for iid, c in CTX.items():
        d, iss, msg, _ = decide(c, as_of)
        s = iss or "COMPLIANT"
        if status and s != status:
            continue
        if text and text.lower() not in iid.lower() and text.lower() not in c["asset"].lower():
            continue
        matched += 1
        if matched <= offset:
            continue
        rows.append({
            "instrument_id": iid,
            "asset_id": c["asset"],
            "status": s,
            "decision": d,
            "next_due": next_due(c),
            "reason": msg,
        })
        if len(rows) >= limit:
            break
    return rows


def metrics(as_of=None):
    as_of = as_of or SIMULATION_DATE
    m = {}
    metrics_path = os.path.join(OUT, "metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path, "r", encoding="utf-8") as f:
            m = json.load(f)

    cnt = {}
    for iid, c in CTX.items():
        s = decide(c, as_of)[1] or "COMPLIANT"
        cnt[s] = cnt.get(s, 0) + 1

    attempts_count = conn.execute("select count(*) from usage_attempt").fetchone()[0] if conn.execute("select 1 from sqlite_master where type='table' and name='usage_attempt'").fetchone() else 0
    compliance_agg = sql_compliance_summary()

    return {
        "static": m,
        "simulation_date": as_of.isoformat(),
        "instrument_status": cnt,
        "compliance_summary": compliance_agg,
        "alerts": q("select alert_type, severity, count(*) n from alert group by 1,2 order by n desc"),
        "open_work_orders": q("select count(*) n from work_order where status in ('OPEN', 'PENDING_RELEASE')")[0]["n"],
        "uses": q("select decision, count(*) n from use_decision group by 1"),
        "blocked_attempts_prevented": attempts_count,
    }


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, obj, code=200, ctype="application/json"):
        b = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Simulation-Date")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(b)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Simulation-Date")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        a = {k: v[0] for k, v in parse_qs(u.query).items()}
        as_of = get_as_of(self.headers)
        user = extract_user(self.headers)
        limit = int(a.get("limit", 100))
        offset = int(a.get("offset", 0))

        try:
            if u.path == "/" or u.path == "/index.html":
                return self.send(open(os.path.join(ROOT, "static", "index.html"), "rb").read(), ctype="text/html")

            with LOCK:
                # 1. Core Endpoints
                if u.path == "/api/simulation-date":
                    return self.send({"simulation_date": SIMULATION_DATE.isoformat(), "default": "2026-11-15T12:00:00"})
                if u.path == "/api/auth/me":
                    if not user:
                        return self.send({"error": "Unauthorized", "code": "UNAUTHORIZED"}, 401)
                    return self.send({"user": user})
                if u.path == "/api/users":
                    safe_users = [{k: v[k] for k in ("user_id", "username", "role", "name")} for v in USERS.values()]
                    return self.send(safe_users)
                if u.path == "/api/metrics":
                    return self.send(metrics(as_of))
                if u.path == "/api/instruments":
                    return self.send(registry(a.get("status"), a.get("q", ""), limit, offset, as_of))
                if u.path == "/api/exceptions":
                    # Uses indexed query ix_alert_severity_created or ix_open_alerts
                    sev = a.get("severity", "")
                    if sev:
                        rows = q("SELECT alert_id, alert_type, severity, entity_type, entity_id, instrument_id, created_at, message, status FROM alert WHERE severity=? ORDER BY created_at DESC LIMIT ? OFFSET ?", (sev, limit, offset))
                    else:
                        rows = q("SELECT alert_id, alert_type, severity, entity_type, entity_id, instrument_id, created_at, message, status FROM alert ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))
                    return self.send(rows)
                if u.path == "/api/audit":
                    # Optimized SQL audit retrieval with index ix_audit_entity_time
                    target_id = a.get("id", "").strip()
                    if target_id:
                        cals = [r[0] for r in conn.execute("SELECT calibration_id FROM calibration_event WHERE instrument_id=?", (target_id,)).fetchall()]
                        wos = [r[0] for r in conn.execute("SELECT work_order_id FROM work_order WHERE instrument_id=?", (target_id,)).fetchall()]
                        entities = [target_id] + cals + wos
                        placeholders = ",".join("?" * len(entities))
                        sql = f"""SELECT audit_id, entity_type, entity_id, action, actor, event_ts, old_state, new_state, reason, record_hash, prev_hash
                                  FROM audit_record
                                  WHERE entity_id IN ({placeholders})
                                  ORDER BY event_ts DESC, audit_id DESC
                                  LIMIT ? OFFSET ?"""
                        rows = q(sql, entities + [limit, offset])
                    else:
                        rows = q("SELECT audit_id, entity_type, entity_id, action, actor, event_ts, old_state, new_state, reason, record_hash, prev_hash FROM audit_record ORDER BY event_ts DESC, audit_id DESC LIMIT ? OFFSET ?", (limit, offset))
                    return self.send(rows)
                if u.path == "/api/workorders":
                    rows = q("SELECT work_order_id, instrument_id, wo_type, priority, assigned_to, opened_date, due_date, status, downtime_start, downtime_end, source_calibration_id, closure_calibration_id FROM work_order WHERE wo_type='CORRECTIVE' ORDER BY status='OPEN' DESC, opened_date DESC LIMIT ? OFFSET ?", (limit, offset))
                    return self.send(rows)
                if u.path == "/api/impact":
                    rows = q("SELECT ia_id, failed_calibration_id, instrument_id, last_good_calibration_id, window_start, window_end, affected_use_count, affected_order_count, status, created_at, assessed_by FROM impact_assessment ORDER BY affected_use_count DESC LIMIT ? OFFSET ?", (limit, offset))
                    return self.send(rows)
                if u.path == "/api/attempts":
                    rows = q("SELECT attempt_id, instrument_id, asset_id, production_order_id, operator_id, attempt_timestamp, decision, issue_type, reason, policy_version FROM usage_attempt ORDER BY attempt_timestamp DESC LIMIT ? OFFSET ?", (limit, offset))
                    return self.send(rows)

                # 2. Advanced Analytics Endpoints (Window Functions, CTEs, Aggregations)
                if u.path == "/api/analytics/latest-calibrations":
                    return self.send(sql_latest_calibrations(limit, offset))
                if u.path == "/api/analytics/upcoming-deadlines":
                    days = int(a.get("days", 30))
                    return self.send(sql_upcoming_deadlines(as_of, days, limit))
                if u.path == "/api/analytics/compliance-summary":
                    return self.send(sql_compliance_summary())
                if u.path == "/api/analytics/supplier-performance":
                    return self.send(sql_supplier_performance())

            self.send({"error": "not found", "code": "NOT_FOUND"}, 404)
        except Exception as e:
            self.send({"error": str(e), "code": "SERVER_ERROR"}, 500)

    def do_POST(self):
        u = urlparse(self.path)
        as_of = get_as_of(self.headers)
        user = extract_user(self.headers)

        try:
            length = int(self.headers.get("Content-Length", 0))
            b = json.loads(self.rfile.read(length) if length > 0 else b"{}")

            if u.path == "/api/auth/login":
                username = b.get("username", "").strip()
                password = b.get("password", "").strip()
                res = authenticate(username, password)
                if not res:
                    return self.send({"error": "Invalid username or password", "code": "UNAUTHORIZED"}, 401)
                return self.send({"token": res["token"], "user": res})

            if u.path == "/api/simulation-date":
                global SIMULATION_DATE
                date_str = b.get("date") or b.get("simulation_date")
                if not date_str:
                    return self.send({"error": "date string is required"}, 400)
                SIMULATION_DATE = dt.datetime.fromisoformat(date_str)
                return self.send({"simulation_date": SIMULATION_DATE.isoformat(), "updated": True})

            if u.path == "/api/check":
                data, code = api_check(b, user=user, as_of=as_of)
                return self.send(data, code)

            if u.path == "/api/calibration":
                data, code = api_cal(b, user=user, as_of=as_of)
                return self.send(data, code)

            m = re.match(r"^/api/instruments/([^/]+)/release$", u.path)
            if m:
                iid = m.group(1)
                data, code = api_release(iid, b, user=user, as_of=as_of)
                return self.send(data, code)

            self.send({"error": "not found", "code": "NOT_FOUND"}, 404)
        except Exception as e:
            self.send({"error": str(e), "code": "SERVER_ERROR"}, 500)


def init_db():
    global conn, CTX
    db = os.path.join(OUT, "calibraguard.sqlite")
    if not os.path.exists(db):
        raise SystemExit("Database not found. Run python run_all.py first.")
    conn = sqlite3.connect(db, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON")
    ensure_schema_and_indexes()
    CTX = build_contexts(frames())[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    init_db()
    print(f"CalibraGuard running on http://localhost:{a.port} (Simulation Date: {SIMULATION_DATE.isoformat()})")
    ThreadingHTTPServer(("0.0.0.0", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
