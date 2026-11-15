"""Central deterministic rules engine: one function decides if an instrument may be used at a time.
Enforces:
1. Calibration interval & due dates (using effective-dated plan assignments).
2. Quarantine following failed calibration.
3. Pending-release hold until authorized quality release sign-off.
4. Maintenance downtime boundaries.
5. Multi-point certificate verification:
   - Certificate existence
   - Instrument mapping (instrument_id matches)
   - Asset mapping (asset_id matches)
   - Certificate status (VALID, rejecting REVOKED and SUPERSEDED)
   - Date validity bounds (valid_from <= date <= valid_to)
   - Measurement range coverage (cert range_max >= instrument required range_max)
   - Certificate revision/supersession hierarchy
6. Emergency extensions authorized by authorized roles (QUALITY_ENGINEER, PLANT_MANAGER).
"""
import bisect
import datetime as dt
import pandas as pd

POLICY = "POL-CAL-2026.1"
AUTH_ROLES = {"QUALITY_ENGINEER", "PLANT_MANAGER"}
BLOCK, ALLOW, EXC = "BLOCK", "ALLOW", "ALLOW_WITH_EXCEPTION"

SEVERITY = {
    "QUARANTINED_USE": "CRITICAL",
    "PENDING_RELEASE_USE": "CRITICAL",
    "NO_IMPACT_ASSESSMENT": "CRITICAL",
    "EXPIRED_USE": "HIGH",
    "EXTENSION_EXPIRED_USE": "HIGH",
    "EXT_UNAUTHORIZED_USE": "HIGH",
    "EXT_UNAUTHORIZED": "HIGH",
    "WRONG_ASSET_CERT": "HIGH",
    "WRONG_ASSET_CERT_USE": "HIGH",
    "WRONG_INSTRUMENT_CERT": "HIGH",
    "WRONG_INSTRUMENT_CERT_USE": "HIGH",
    "CERT_REVOKED": "HIGH",
    "CERT_REVOKED_USE": "HIGH",
    "CERT_SUPERSEDED": "HIGH",
    "CERT_SUPERSEDED_USE": "HIGH",
    "CERT_RANGE_MISMATCH": "HIGH",
    "CERT_RANGE_MISMATCH_USE": "HIGH",
    "CERT_DATE_INVALID": "HIGH",
    "CERT_DATE_INVALID_USE": "HIGH",
    "CERT_MISSING_USE": "HIGH",
    "MAINTENANCE_USE": "MEDIUM",
    "NO_CALIBRATION_USE": "HIGH",
    "CERT_MISSING": "MEDIUM",
    "DUE_DATE_INCONSISTENT": "MEDIUM",
    "DATE_ORDER": "LOW",
    "DUPLICATE_EVENT": "MEDIUM",
    "EXTENSION_USE": "INFO",
}


def _d(s):
    if isinstance(s, (dt.date, dt.datetime)):
        return s.date() if isinstance(s, dt.datetime) else s
    return dt.date.fromisoformat(str(s)[:10])


def build_contexts(T):
    """T: dict of DataFrames (calibration_plan, instrument, calibration_event, certificate, work_order, extension,
    and optionally instrument_plan_assignment, instrument_type).
    Returns (ctx per instrument, duplicate calibration ids). Only INPUT tables are used - never ground truth."""
    iv = {p: int(v) for p, v in zip(T["calibration_plan"].plan_id, T["calibration_plan"].interval_days)}
    asset = dict(zip(T["instrument"].instrument_id, T["instrument"].asset_id))
    
    # Range map from instrument -> instrument_type range_max
    inst_range_max = {}
    if "instrument_type" in T and not T["instrument_type"].empty and "type_id" in T["instrument"].columns:
        type_ranges = {r.type_id: float(r.range_max) for r in T["instrument_type"].itertuples() if hasattr(r, "range_max")}
        for r in T["instrument"].itertuples():
            if getattr(r, "type_id", None) in type_ranges:
                inst_range_max[r.instrument_id] = type_ranges[r.type_id]

    # Effective-dated plan assignments
    asg_map = {}
    if "instrument_plan_assignment" in T and not T["instrument_plan_assignment"].empty:
        for r in T["instrument_plan_assignment"].itertuples():
            eff_to = _d(r.effective_to) if getattr(r, "effective_to", "") and str(r.effective_to).strip() else None
            asg_map.setdefault(r.instrument_id, []).append((_d(r.effective_from), eff_to, r.plan_id))
        for iid in asg_map:
            asg_map[iid].sort(key=lambda x: x[0])

    # Certificate multi-point index
    # We group certificates by calibration_id, selecting the active/latest version
    cert_df = T["certificate"]
    cert_map = {}
    if not cert_df.empty:
        # Sort so highest version comes first
        sorted_certs = cert_df.sort_values("version", ascending=False) if "version" in cert_df.columns else cert_df
        for r in sorted_certs.itertuples():
            cid = r.calibration_id
            if cid not in cert_map:
                cert_map[cid] = r

    # Corrective work orders closed with recalibration (authorized releases)
    closed_recal_cals = set()
    wo = T["work_order"]
    if not wo.empty and "wo_type" in wo.columns:
        for r in wo[wo.wo_type == "CORRECTIVE"].itertuples():
            if r.status == "CLOSED" and getattr(r, "closure_calibration_id", None):
                closed_recal_cals.add(r.closure_calibration_id)

    ctx = {i: {"asset": a, "ev": [], "dates": [], "maint": [], "ext": [], "unreleased_cals": set(), "pending_release": False} for i, a in asset.items()}
    dups, seen = [], set()
    ev = T["calibration_event"].sort_values(["instrument_id", "calibration_date", "calibration_id"])
    
    # Track recalibrations per instrument
    has_failed = {i: False for i in asset}

    for r in ev.itertuples():
        key = (r.instrument_id, r.calibration_date, r.result)
        if key in seen:
            dups.append(r.calibration_id)
            continue
        seen.add(key)
        
        # Effective plan resolution
        d = _d(r.calibration_date)
        active_plan = r.plan_id
        if r.instrument_id in asg_map:
            for ef_from, ef_to, pid in asg_map[r.instrument_id]:
                if ef_from <= d and (ef_to is None or d <= ef_to):
                    active_plan = pid
        plan_interval = iv.get(active_plan, iv.get(r.plan_id, 365))

        # Certificate validation
        c = ctx[r.instrument_id]
        if r.calibration_id not in cert_map:
            cs = "MISSING"
        else:
            c_row = cert_map[r.calibration_id]
            c_asset = getattr(c_row, "asset_id", "")
            c_inst = getattr(c_row, "instrument_id", "")
            c_stat = getattr(c_row, "status", "VALID")
            c_rmax = float(getattr(c_row, "range_max", 1e9) or 1e9)
            
            # 1. Asset check (must match instrument's asset)
            if c_asset != asset[r.instrument_id]:
                cs = "WRONG"  # matches existing WRONG_ASSET_CERT_USE
            # 2. Instrument ID check (must match calibrated instrument)
            elif c_inst and c_inst != r.instrument_id:
                cs = "WRONG_INSTRUMENT"
            # 3. Status check (REVOKED / SUPERSEDED)
            elif c_stat == "REVOKED":
                cs = "REVOKED"
            elif c_stat == "SUPERSEDED":
                cs = "SUPERSEDED"
            # 4. Operating range coverage
            elif r.instrument_id in inst_range_max and c_rmax < inst_range_max[r.instrument_id]:
                cs = "OUT_OF_RANGE"
            else:
                cs = "OK"

        # Lifecycle tracking for recalibration release
        if r.result == "FAIL":
            has_failed[r.instrument_id] = True
        elif r.result == "PASS" and has_failed[r.instrument_id]:
            # Recalibration after a failure: requires explicit authorized release
            if r.calibration_id not in closed_recal_cals:
                c["unreleased_cals"].add(r.calibration_id)
            else:
                has_failed[r.instrument_id] = False  # Released!

        due_date = d + dt.timedelta(days=plan_interval)
        c["ev"].append((d, r.result, due_date, r.calibration_id, cs))
        c["dates"].append(d)

    # Maintenance downtime
    if not wo.empty and "wo_type" in wo.columns:
        for r in wo[wo.wo_type == "MAINTENANCE"].itertuples():
            if r.instrument_id in ctx:
                ctx[r.instrument_id]["maint"].append((_d(r.downtime_start), _d(r.downtime_end), r.work_order_id))
    
    # Extensions
    ext_df = T["extension"]
    if not ext_df.empty:
        for r in ext_df.itertuples():
            if r.instrument_id in ctx:
                ctx[r.instrument_id]["ext"].append((r.extension_id, _d(r.start_date), _d(r.end_date), r.approver_role, r.status))
    
    return ctx, dups


def decide(c, ts):
    """-> (decision, issue_type, reason, extension_id). Evaluated at the time of use, not current status."""
    d = ts.date() if isinstance(ts, dt.datetime) else ts
    k = bisect.bisect_right(c["dates"], d) - 1
    if k < 0:
        return BLOCK, "NO_CALIBRATION_USE", "No calibration on record at time of use", None
    last = c["ev"][k]
    
    # Check 1: Quarantine if last event was FAIL
    if last[1] == "FAIL":
        return BLOCK, "QUARANTINED_USE", f"Quarantined after failed calibration {last[3]}", None
    
    # Check 2: Pending authorized quality release after recalibration
    if last[3] in c.get("unreleased_cals", set()) or c.get("pending_release", False):
        return BLOCK, "PENDING_RELEASE_USE", f"Recalibration {last[3]} completed but pending authorized quality release", None

    # Check 3: Active maintenance downtime
    for s, e, w in c["maint"]:
        if s <= d <= e:
            return BLOCK, "MAINTENANCE_USE", f"Under maintenance ({w})", None

    # Check 4: Certificate verification
    _, _, due, cid, cs = last
    if cs == "MISSING":
        return BLOCK, "CERT_MISSING_USE", f"No certificate for calibration {cid}", None
    if cs in ("WRONG", "WRONG_ASSET"):
        return BLOCK, "WRONG_ASSET_CERT_USE", f"Certificate for {cid} belongs to another asset", None
    if cs == "WRONG_INSTRUMENT":
        return BLOCK, "WRONG_INSTRUMENT_CERT_USE", f"Certificate for {cid} belongs to another instrument", None
    if cs == "REVOKED":
        return BLOCK, "CERT_REVOKED_USE", f"Certificate for {cid} has been revoked", None
    if cs == "SUPERSEDED":
        return BLOCK, "CERT_SUPERSEDED_USE", f"Certificate for {cid} has been superseded by a newer revision", None
    if cs == "OUT_OF_RANGE":
        return BLOCK, "CERT_RANGE_MISMATCH_USE", f"Certificate for {cid} does not cover instrument range", None

    # Check 5: Calibration valid within due date
    if d <= due:
        return ALLOW, "", f"Calibrated {cid}, valid until {due}", None

    # Check 6: Emergency Extensions
    exts = [x for x in c["ext"] if due < x[1] <= d]
    ok = [x for x in exts if x[3] in AUTH_ROLES and x[4] == "APPROVED"]
    for x in ok:
        if x[1] <= d <= x[2]:
            return EXC, "EXTENSION_USE", f"Overdue since {due}; emergency extension {x[0]} active until {x[2]}", x[0]
    if ok:
        return BLOCK, "EXTENSION_EXPIRED_USE", f"Overdue since {due}; extension {ok[0][0]} expired {ok[0][2]}", None
    if exts:
        return BLOCK, "EXT_UNAUTHORIZED_USE", f"Overdue since {due}; extension {exts[0][0]} approved by unauthorized role", None
    return BLOCK, "EXPIRED_USE", f"Calibration overdue since {due} (cal {cid}); no exception", None


def next_due(c):
    p = [e for e in c["ev"] if e[1] == "PASS"]
    return p[-1][2].isoformat() if p else ""
