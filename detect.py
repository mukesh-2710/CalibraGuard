"""Runs the rules engine over INPUT tables only; writes findings, use_decision and alert tables."""
import datetime as dt, os, sys
import pandas as pd
from rules import build_contexts, decide, SEVERITY, POLICY, AUTH_ROLES

def load(data):
    return {f[:-4]: pd.read_csv(os.path.join(data, f), dtype=str, keep_default_na=False) for f in os.listdir(data) if f.endswith(".csv")}

def run(out="out"):
    data = os.path.join(out, "data"); T = load(data); T["calibration_plan"]["interval_days"] = T["calibration_plan"].interval_days.astype(int)
    ctx, dups = build_contexts(T); F = []
    U = T["production_use"]; dec = []
    for uid, iid, ts in zip(U.use_id, U.instrument_id, U.use_timestamp):
        d, iss, msg, x = decide(ctx[iid], dt.datetime.fromisoformat(ts)); dec.append((uid, d, iss, msg, POLICY, x or "", ts))
        if iss: F.append((uid, "PRODUCTION_USE", iss, d, iid, ts, msg))
    ud = pd.DataFrame(dec, columns=["use_id", "decision", "issue_type", "reason", "policy_version", "extension_id", "decided_at"])
    E = T["calibration_event"]; iv = dict(zip(T["calibration_plan"].plan_id, T["calibration_plan"].interval_days))
    certs = dict(zip(T["certificate"].calibration_id, T["certificate"].asset_id)); asset = dict(zip(T["instrument"].instrument_id, T["instrument"].asset_id))
    ia = set(T["impact_assessment"].failed_calibration_id); dset = set(dups)
    for r in E.itertuples():
        t = r.created_at
        if r.calibration_id in dset: F.append((r.calibration_id, "CALIBRATION", "DUPLICATE_EVENT", "REJECT", r.instrument_id, t, "Duplicate of an existing calibration event")); continue
        if r.created_at[:10] < r.calibration_date: F.append((r.calibration_id, "CALIBRATION", "DATE_ORDER", "FLAG", r.instrument_id, t, "Calibration date is after event creation"))
        if r.result == "PASS":
            exp = (dt.date.fromisoformat(r.calibration_date) + dt.timedelta(days=iv[r.plan_id])).isoformat()
            if r.next_due_date != exp: F.append((r.calibration_id, "CALIBRATION", "DUE_DATE_INCONSISTENT", "FLAG", r.instrument_id, t, f"Stored due {r.next_due_date} != plan-derived {exp}"))
            if r.calibration_id not in certs: F.append((r.calibration_id, "CALIBRATION", "CERT_MISSING", "BLOCK", r.instrument_id, t, "Passed calibration has no certificate"))
        elif r.calibration_id not in ia: F.append((r.calibration_id, "CALIBRATION", "NO_IMPACT_ASSESSMENT", "ESCALATE", r.instrument_id, t, "Failed calibration without impact assessment"))
    for r in T["certificate"].itertuples():
        if r.asset_id != asset[r.instrument_id]: F.append((r.cert_id, "CERTIFICATE", "WRONG_ASSET_CERT", "REJECT", r.instrument_id, r.issue_date + "T12:00:00", f"Certificate asset {r.asset_id} != instrument asset {asset[r.instrument_id]}"))
    for r in T["extension"].itertuples():
        if r.approver_role not in AUTH_ROLES: F.append((r.extension_id, "EXTENSION", "EXT_UNAUTHORIZED", "REJECT", r.instrument_id, r.start_date + "T08:30:00", f"Approver role {r.approver_role} not authorised"))
    fd = pd.DataFrame(F, columns=["record_id", "record_type", "issue_type", "decision", "instrument_id", "ts", "message"])
    fd["severity"] = fd.issue_type.map(lambda x: SEVERITY.get(x, "MEDIUM")); fd.to_csv(os.path.join(out, "findings.csv"), index=False, lineterminator="\n")
    al = fd[fd.issue_type != "EXTENSION_USE"].sort_values(["ts", "record_id", "issue_type"], kind="stable").reset_index(drop=True)
    alert = pd.DataFrame({"alert_id": [f"ALT-{i+1:06d}" for i in range(len(al))], "alert_type": al.issue_type, "severity": al.severity, "entity_type": al.record_type,
        "entity_id": al.record_id, "instrument_id": al.instrument_id, "created_at": al.ts, "message": al.message, "status": "OPEN", "rule_id": "R-" + al.issue_type})
    ud.to_csv(os.path.join(data, "use_decision.csv"), index=False, lineterminator="\n"); alert.to_csv(os.path.join(data, "alert.csv"), index=False, lineterminator="\n")
    return fd, ud, alert

if __name__ == "__main__":
    fd, ud, al = run(sys.argv[1] if len(sys.argv) > 1 else "out"); print(f"findings={len(fd)} alerts={len(al)} blocked_uses={(ud.decision=='BLOCK').sum()}")
