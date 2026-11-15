#!/usr/bin/env python3
"""CalibraGuard deterministic synthetic data generator.
Valid baseline first -> labelled injections -> ground truth (separate file). Same seed => identical bytes."""
import argparse, datetime as dt, hashlib, json, os, sys
import numpy as np, pandas as pd
from rules import POLICY, AUTH_ROLES

START = dt.date(2026, 1, 1); ND = 365
INTERVALS = [90, 95, 120, 135, 150, 180, 270, 365]
ISSUE = {1: "EXPIRED_USE", 2: "CERT_MISSING_USE", 3: "WRONG_ASSET_CERT_USE", 4: "NO_CALIBRATION_USE",
         5: "MAINTENANCE_USE", 6: "QUARANTINED_USE", 7: "EXTENSION_USE"}


def D(i): return START + dt.timedelta(days=int(i))
def TS(i, h=9, m=0, s=0): return f"{D(i).isoformat()}T{h:02d}:{m:02d}:{s:02d}"


def timeline(events, maint):
    """Independent day-level status model (0 ok,1 overdue,2 cert missing,3 wrong cert,5 maint,6 quarantine)."""
    a = np.full(ND, 4, np.int8); wins = []
    ps = [k for k, e in enumerate(events) if e[1] == "PASS"]
    for n, k in enumerate(ps):
        d, _, iv, cs = events[k]
        end = events[ps[n + 1]][0] - 1 if n + 1 < len(ps) else ND - 1
        if cs == "MISSING": a[d:end + 1] = 2
        elif cs == "WRONG": a[d:end + 1] = 3
        else:
            due = d + iv; a[d:min(due, end) + 1] = 0
            if due < end: a[due + 1:end + 1] = 1; wins.append((due + 1, end))
    for k, e in enumerate(events):
        if e[1] == "FAIL":
            nxt = next((events[m][0] for m in range(k + 1, len(events)) if events[m][1] == "PASS"), ND)
            a[e[0]:nxt] = 6
    for s, e in maint:
        sl = a[s:e + 1]; sl[sl != 6] = 5
    return a, wins


def generate(seed=20261022, n_inst=2000, n_cal=5000, n_use=100000, out="out"):
    assert n_inst <= n_cal <= 4 * n_inst
    rng = np.random.default_rng(seed)
    sc = lambda x: max(1, round(x * n_cal / 5000))
    n_ast, n_sup, n_typ = max(10, n_inst // 4), max(5, min(25, n_inst // 80)), 20
    # ---------- master data ----------
    sup = pd.DataFrame({"supplier_id": [f"SUP-{i+1:04d}" for i in range(n_sup)], "name": [f"CalLab {i+1}" for i in range(n_sup)],
        "accreditation_no": [f"ISO17025-{100000+int(x)}" for x in rng.integers(0, 899999, n_sup)],
        "country": rng.choice(["IN", "DE", "US", "SG"], n_sup), "status": "ACTIVE"})
    tn = ["Pressure Transmitter", "RTD Sensor", "Flow Meter", "Torque Wrench", "Digital Caliper", "pH Meter", "Load Cell", "Level Sensor", "Multimeter", "Thermocouple"]
    un = ["bar", "degC", "m3/h", "Nm", "mm", "pH", "kg", "mm", "V", "degC"]
    crit = rng.choice(["LOW", "MEDIUM", "HIGH"], n_typ, p=[.3, .45, .25]); rmax = rng.integers(10, 1000, n_typ)
    typ = pd.DataFrame({"type_id": [f"ITY-{i+1:03d}" for i in range(n_typ)], "name": [f"{tn[i%10]} Class {i//10+1}" for i in range(n_typ)],
        "unit": [un[i % 10] for i in range(n_typ)], "range_min": 0, "range_max": rmax, "criticality": crit})
    ast_ids = [f"AST-{i+1:06d}" for i in range(n_ast)]
    asset = pd.DataFrame({"asset_id": ast_ids, "name": [f"Equipment {i+1}" for i in range(n_ast)],
        "plant": rng.choice(["PLANT-HYD", "PLANT-PUN", "PLANT-CHN"], n_ast), "line": [f"LINE-{x}" for x in rng.integers(1, 9, n_ast)], "status": "ACTIVE"})
    plans = pd.DataFrame([{"plan_id": f"CPL-{k*2+t+1:03d}", "interval_days": iv, "tolerance_pct": [1.0, 0.5][t], "tier": ["STANDARD", "STRICT"][t],
        "effective_from": "2026-01-01", "effective_to": "", "policy_version": POLICY} for k, iv in enumerate(INTERVALS) for t in (0, 1)])
    ai, ti = rng.integers(0, n_ast, n_inst), rng.integers(0, n_typ, n_inst)
    ins_ids = [f"INS-{i+1:06d}" for i in range(n_inst)]; ast_of = [ast_ids[a] for a in ai]
    # ---------- calibration events ----------
    cnt = np.ones(n_inst, int); left = n_cal - n_inst
    while left > 0:
        for i in rng.integers(0, n_inst, left):
            if cnt[i] < 4 and left > 0: cnt[i] += 1; left -= 1
    ev, first, plan_of = [], [], []
    for i in range(n_inst):
        n, s = int(cnt[i]), int(rng.integers(0, 31)); res, k = [], 0
        while k < n:
            if k < n - 1 and rng.random() < .075: res += ["FAIL", "PASS"]; k += 2
            else: res.append("PASS"); k += 1
        pairs = res.count("FAIL"); r = n - pairs
        lo = (364 - s) / r; hi = (364 - s - 10 * pairs) / (r - 1) - 20 if r > 1 else 1e9
        opts = [v for v in INTERVALS if lo <= v <= hi] or [min([v for v in INTERVALS if v >= lo] or [365])]
        iv = int(opts[rng.integers(len(opts))]); tier = 1 if crit[ti[i]] == "HIGH" else 0
        pid = f"CPL-{INTERVALS.index(iv)*2+tier+1:03d}"; plan_of.append(pid)
        tol = [1.0, 0.5][tier]; d = s; ds = []
        for k in range(n):
            if k > 0:
                d += int(rng.integers(2, 11)) if res[k-1] == "FAIL" else iv - int(rng.integers(0, 4)) + (int(rng.integers(1, 21)) if rng.random() < .10 else 0)
            ds.append(d)
        ds[-1] = min(ds[-1], 364)
        for k in range(n - 2, -1, -1): ds[k] = min(ds[k], ds[k+1] - 2)
        first.append(ds[0])
        for k in range(n):
            f = res[k] == "FAIL"
            err = tol * float(rng.uniform(1.05, 2.0)) if f else min(abs(float(rng.normal(0, tol / 3))), tol * .98)
            ev.append(dict(i=i, d=ds[k], res=res[k], iv=iv, plan=pid, err=round(err, 4), tol=tol,
                cs="NONE" if f else ("MISSING" if rng.random() < .02 else "OK"), sup=int(rng.integers(0, n_sup)),
                reason="Out of tolerance (as-found)" if f else "", dup=False, due_off=0, early=0, wrong=False))
    ev.sort(key=lambda e: (e["d"], e["i"]))
    for n, e in enumerate(ev, 1): e["cal"] = f"CAL-{ast_of[e['i']]}-2026-{n:06d}"
    # ---------- labelled injections on calibration events ----------
    truth = []
    def T_(rid, rtype, issue, dec, inst, inj=1): truth.append((rid, rtype, issue, dec, inst, inj))
    pool = [j for j, e in enumerate(ev) if e["res"] == "PASS" and e["cs"] == "OK"]
    perm = list(rng.permutation(pool)); take = lambda k: [perm.pop() for _ in range(min(k, len(perm)))]
    for j in take(sc(40)): ev[j]["cs"] = "WRONG"
    for j in take(sc(50)): ev[j]["due_off"] = int(rng.choice([-1, 1]) * rng.integers(3, 21))
    for j in take(sc(20)): ev[j]["early"] = int(rng.integers(1, 6))
    dups = []
    for j in take(sc(20)):
        c = dict(ev[j]); c["dup"] = True; c["cs"] = "NONE"; c["due_off"] = 0; c["early"] = 0; c["src"] = ev[j]["cal"]; dups.append(c)
    for n, c in enumerate(dups, len(ev) + 1): c["cal"] = f"CAL-{ast_of[c['i']]}-2026-{n:06d}"
    allev = ev + dups
    ins_ev = [[] for _ in range(n_inst)]
    for e in ev: ins_ev[e["i"]].append(e)
    rows = []
    for e in allev:
        p = e["res"] == "PASS"; dd = D(e["d"]) + dt.timedelta(days=e["iv"] + e["due_off"])
        rows.append(dict(calibration_id=e["cal"], instrument_id=ins_ids[e["i"]], asset_id=ast_of[e["i"]], plan_id=e["plan"], supplier_id=sup.supplier_id[e["sup"]],
            calibration_date=D(e["d"]).isoformat(), created_at=(f"{D(e['d'] - e['early'])}T09:00:00" if e["early"] else TS(e["d"] + 1)), result=e["res"],
            as_found_error_pct=e["err"], tolerance_pct=e["tol"], next_due_date=dd.isoformat() if p else "", failure_reason=e["reason"], status="RECORDED"))
        i = ins_ids[e["i"]]
        if e["dup"]: T_(e["cal"], "CALIBRATION", "DUPLICATE_EVENT", "REJECT", i)
        if e["due_off"]: T_(e["cal"], "CALIBRATION", "DUE_DATE_INCONSISTENT", "FLAG", i)
        if e["early"]: T_(e["cal"], "CALIBRATION", "DATE_ORDER", "FLAG", i)
        if e["cs"] == "MISSING": T_(e["cal"], "CALIBRATION", "CERT_MISSING", "BLOCK", i, 0)
    cal = pd.DataFrame(rows)
    crow = []
    for n, e in enumerate(ev, 1):
        if e["cs"] in ("OK", "WRONG"):
            a = ast_of[e["i"]] if e["cs"] == "OK" else ast_ids[(int(ai[e["i"]]) + 1) % n_ast]
            if e["cs"] == "WRONG": T_("CERT-" + e["cal"], "CERTIFICATE", "WRONG_ASSET_CERT", "REJECT", ins_ids[e["i"]])
            rg = int(typ.range_max[ti[e["i"]]])
            crow.append(dict(cert_id="CERT-" + e["cal"], calibration_id=e["cal"], instrument_id=ins_ids[e["i"]], asset_id=a, supplier_id=sup.supplier_id[e["sup"]],
                certificate_number=f"CN-{n:07d}", issue_date=D(e["d"] + int(rng.integers(0, 4))).isoformat(), valid_from=D(e["d"]).isoformat(),
                valid_to=(D(e["d"]) + dt.timedelta(days=e["iv"])).isoformat(), range_min=0, range_max=rg, status="VALID", version=1))
    cert = pd.DataFrame(crow)
    # ---------- maintenance + timelines + extensions ----------
    first_a = np.array(first); maint, mrows = [[] for _ in range(n_inst)], []
    for _ in range(round(.35 * n_inst)):
        i = int(rng.integers(0, n_inst)); s = int(rng.integers(first[i], 360)); e = min(s + int(rng.integers(1, 5)) - 1, 364)
        maint[i].append((s, e)); mrows.append((s, i, e))
    codes = np.zeros((n_inst, ND), np.int8); tags = np.zeros((n_inst, ND), np.int8); cand = []
    for i in range(n_inst):
        a, w = timeline([(e["d"], e["res"], e["iv"], e["cs"]) for e in ins_ev[i]], maint[i]); codes[i] = a
        cand += [(i, s, e) for s, e in w if (a[s:e + 1] == 1).any()]
    erows, nov = [], []
    for (i, s, e) in cand:
        if rng.random() < .30:
            end = min(e, s + int(rng.integers(2, 10))); sl = codes[i, s:end + 1]; sl[sl == 1] = 7; tags[i, s:e + 1] = 1
            erows.append((s, i, end, ["QUALITY_ENGINEER", "PLANT_MANAGER"][int(rng.integers(0, 2))], "Emergency production demand; interim verification done"))
        else: nov.append((i, s, e))
    for j in (rng.choice(len(nov), min(sc(20), len(nov)), replace=False) if nov else []):
        i, s, e = nov[int(j)]; tags[i, s:e + 1] = 2
        erows.append((s, i, min(e, s + 5), "PLANT_OPERATOR", "Operator self-approved extension"))
    erows.sort(); ext = []
    for n, (s, i, end, role, why) in enumerate(erows, 1):
        ext.append(dict(extension_id=f"EXT-{n:06d}", instrument_id=ins_ids[i], start_date=D(s).isoformat(), end_date=D(end).isoformat(),
            approved_by=f"U-{role[:2]}-{int(rng.integers(1,30)):03d}", approver_role=role, reason=why, evidence_ref=f"EVD-{n:06d}",
            scope="SINGLE_LINE", status="APPROVED", policy_version=POLICY))
        if role not in AUTH_ROLES: T_(f"EXT-{n:06d}", "EXTENSION", "EXT_UNAUTHORIZED", "REJECT", ins_ids[i])
    ext = pd.DataFrame(ext, columns=["extension_id", "instrument_id", "start_date", "end_date", "approved_by", "approver_role", "reason", "evidence_ref", "scope", "status", "policy_version"])
    # ---------- production use ----------
    inj_i, inj_d = [], []
    for mask, k in [((codes == 1) & (tags == 0), sc(150)), ((codes == 1) & (tags == 1), sc(60)), ((codes == 1) & (tags == 2), sc(40)),
                    (codes == 5, sc(60)), (codes == 6, sc(60))]:
        c = np.argwhere(mask)
        if len(c): p = c[rng.integers(0, len(c), k)]; inj_i += list(p[:, 0]); inj_d += list(p[:, 1])
    nn = n_use - len(inj_i)
    ni = rng.integers(0, n_inst, nn); day = first_a[ni] + (rng.random(nn) * (ND - first_a[ni])).astype(int)
    sec = rng.integers(6 * 3600, 22 * 3600, n_use)
    ni = np.r_[ni, np.array(inj_i, int)]; day = np.r_[day, np.array(inj_d, int)]; isinj = np.r_[np.zeros(nn, int), np.ones(len(inj_i), int)]
    po = rng.integers(1, max(2, n_use // 4), n_use); late = rng.random(n_use) < .01; lh = rng.integers(1, 72, n_use); opn = rng.integers(1, 400, n_use)
    key = day.astype(np.int64) * 86400 + sec; o = np.argsort(key, kind="stable")
    ni, day, isinj, po, late, lh, opn, key = ni[o], day[o], isinj[o], po[o], late[o], lh[o], opn[o], key[o]
    seen, urows, uts = set(), [], []
    for q in range(n_use):
        a = ast_of[ni[q]]; t = int(key[q])
        while (a, t) in seen: t += 1
        seen.add((a, t)); dd, ss = divmod(t, 86400); st = TS(dd, ss // 3600, ss % 3600 // 60, ss % 60)
        ing = (dt.datetime.fromisoformat(st) + dt.timedelta(hours=int(lh[q]))).isoformat() if late[q] else st
        urows.append((f"USE-{a}-{D(dd):%Y%m%d}T{ss//3600:02d}{ss%3600//60:02d}{ss%60:02d}", ins_ids[ni[q]], a, f"PO-2026-{po[q]:06d}", f"OP-{opn[q]:04d}", st, ing))
    use = pd.DataFrame(urows, columns=["use_id", "instrument_id", "asset_id", "production_order_id", "operator_id", "use_timestamp", "ingestion_timestamp"])
    cd, tg = codes[ni, day], tags[ni, day]
    for q in np.flatnonzero(cd != 0):
        c = int(cd[q]); iss = ISSUE[c]
        if c == 1 and tg[q] == 1: iss = "EXTENSION_EXPIRED_USE"
        if c == 1 and tg[q] == 2: iss = "EXT_UNAUTHORIZED_USE"
        if c == 4: continue
        T_(urows[q][0], "PRODUCTION_USE", iss, "ALLOW_WITH_EXCEPTION" if c == 7 else "BLOCK", urows[q][1], int(isinj[q]) if c != 7 else 0)
    # ---------- impact assessments, work orders ----------
    o2 = np.lexsort((day, ni)); ni_s, day_s, po_s = ni[o2], day[o2], po[o2]
    lo, hi = np.searchsorted(ni_s, np.arange(n_inst), "left"), np.searchsorted(ni_s, np.arange(n_inst), "right")
    def between(i, d0, d1):
        dd = day_s[lo[i]:hi[i]]; a = lo[i] + np.searchsorted(dd, d0, "left"); b = lo[i] + np.searchsorted(dd, d1, "right")
        return int(b - a), len(set(po_s[a:b]))
    fails = [(i, k) for i in range(n_inst) for k, e in enumerate(ins_ev[i]) if e["res"] == "FAIL"]
    skip = set(int(x) for x in (rng.choice(len(fails), min(sc(30), len(fails)), replace=False) if fails else []))
    iarows, wo = [], [dict(opened=s, i=i, type="MAINTENANCE", pri="MEDIUM", due=min(e, 364), closed=e, status="CLOSED", ds=s, de=e, src="", clo="") for s, i, e in mrows]
    for n, (i, k) in enumerate(fails):
        f = ins_ev[i][k]; recal = ins_ev[i][k + 1]
        lg = next((x for x in reversed(ins_ev[i][:k]) if x["res"] == "PASS"), None)
        wo.append(dict(opened=f["d"], i=i, type="CORRECTIVE", pri="HIGH" if crit[ti[i]] == "HIGH" else "MEDIUM", due=min(f["d"] + 7, 364), closed=recal["d"],
            status="CLOSED", ds=f["d"], de=recal["d"], src=f["cal"], clo=recal["cal"]))
        if n in skip: T_(f["cal"], "CALIBRATION", "NO_IMPACT_ASSESSMENT", "ESCALATE", ins_ids[i]); continue
        ws = lg["d"] if lg else 0; cnt_, ord_ = between(i, ws, f["d"])
        iarows.append(dict(ia_id="IA-" + f["cal"], failed_calibration_id=f["cal"], instrument_id=ins_ids[i], last_good_calibration_id=lg["cal"] if lg else "",
            window_start=D(ws).isoformat(), window_end=D(f["d"]).isoformat(), affected_use_count=cnt_, affected_order_count=ord_,
            status="COMPLETED", created_at=TS(f["d"] + 1, 10), assessed_by=f"U-QE-{int(rng.integers(1,30)):03d}"))
    ia = pd.DataFrame(iarows, columns=["ia_id", "failed_calibration_id", "instrument_id", "last_good_calibration_id", "window_start", "window_end", "affected_use_count", "affected_order_count", "status", "created_at", "assessed_by"])
    wo.sort(key=lambda w: (w["opened"], w["i"]))
    wodf = pd.DataFrame([dict(work_order_id=f"WO-2026-{n:06d}", instrument_id=ins_ids[w["i"]], wo_type=w["type"], priority=w["pri"], assigned_to=f"U-QE-{(w['i'] % 29)+1:03d}",
        opened_date=D(w["opened"]).isoformat(), due_date=D(w["due"]).isoformat(), closed_date=D(w["closed"]).isoformat(), status=w["status"],
        downtime_start=D(w["ds"]).isoformat(), downtime_end=D(w["de"]).isoformat(), source_calibration_id=w["src"], closure_calibration_id=w["clo"]) for n, w in enumerate(wo, 1)])
    # ---------- audit ----------
    au = []
    for e in allev:
        i = ins_ids[e["i"]]; t0 = TS(e["d"], 9) if not e["early"] else TS(e["d"] - e["early"], 9)
        au.append((t0, "CALIBRATION", e["cal"], "CALIBRATION_RECORDED", "U-TECH-%03d" % (e["sup"] + 1), "", e["res"], e["reason"] or "Scheduled calibration"))
        if e["cs"] in ("OK", "WRONG"): au.append((TS(e["d"], 12), "CERTIFICATE", "CERT-" + e["cal"], "CERTIFICATE_ISSUED", "SUPPLIER", "", "VALID", ""))
        if e["res"] == "FAIL": au.append((TS(e["d"], 9, 1), "INSTRUMENT", i, "INSTRUMENT_QUARANTINED", "SYSTEM", "ACTIVE", "QUARANTINED", f"Failed calibration {e['cal']}"))
    for w in wodf.itertuples():
        au.append((w.opened_date + "T08:00:00", "WORK_ORDER", w.work_order_id, "WO_OPENED", "SYSTEM", "", "OPEN", w.wo_type))
        au.append((w.closed_date + "T17:00:00", "WORK_ORDER", w.work_order_id, "WO_CLOSED", w.assigned_to, "OPEN", "CLOSED", w.closure_calibration_id or "Maintenance complete"))
        if w.wo_type == "CORRECTIVE": au.append((w.closed_date + "T17:05:00", "INSTRUMENT", w.instrument_id, "INSTRUMENT_RELEASED", w.assigned_to, "QUARANTINED", "ACTIVE", "Recalibration verified " + w.closure_calibration_id))
    for x in ext.itertuples(): au.append((x.start_date + "T08:30:00", "EXTENSION", x.extension_id, "EXTENSION_APPROVED", x.approved_by, "", "APPROVED", x.reason))
    for x in ia.itertuples(): au.append((x.created_at, "IMPACT_ASSESSMENT", x.ia_id, "IA_COMPLETED", x.assessed_by, "", "COMPLETED", f"{x.affected_use_count} uses in window"))
    au.sort(); audit = pd.DataFrame([(f"AUD-{n:06d}",) + a for n, a in enumerate(au, 1)], columns=["audit_id", "event_ts", "entity_type", "entity_id", "action", "actor", "old_state", "new_state", "reason"])
    audit = audit[["audit_id", "entity_type", "entity_id", "action", "actor", "event_ts", "old_state", "new_state", "reason"]]
    inst = pd.DataFrame({"instrument_id": ins_ids, "asset_id": ast_of, "type_id": typ.type_id.values[ti], "serial_no": [f"SN-{100000+i}" for i in range(n_inst)],
        "commissioned_date": [D(f).isoformat() for f in first], "lifecycle_state": "ACTIVE"})
    asg = pd.DataFrame({"assignment_id": [f"ASG-{i+1:06d}" for i in range(n_inst)], "instrument_id": ins_ids, "plan_id": plan_of,
        "effective_from": [D(f).isoformat() for f in first], "effective_to": ""})
    gt = pd.DataFrame(truth, columns=["record_id", "record_type", "issue_type", "expected_decision", "instrument_id", "injected"])
    gt["severity"] = gt.issue_type.map(lambda x: __import__("rules").SEVERITY.get(x, "MEDIUM"))
    # ---------- write ----------
    dd_ = os.path.join(out, "data"); os.makedirs(dd_, exist_ok=True); man = {"seed": seed, "params": dict(n_inst=n_inst, n_cal=n_cal, n_use=n_use), "files": {}}
    tabs = dict(supplier=sup, asset=asset, instrument_type=typ, calibration_plan=plans, instrument=inst, instrument_plan_assignment=asg, calibration_event=cal,
                certificate=cert, work_order=wodf, extension=ext, impact_assessment=ia, production_use=use, audit_record=audit)
    def w(df, path):
        df.to_csv(path, index=False, lineterminator="\n")
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    for k, df in tabs.items(): man["files"][k + ".csv"] = {"rows": len(df), "sha256": w(df, os.path.join(dd_, k + ".csv"))}
    man["files"]["ground_truth.csv"] = {"rows": len(gt), "sha256": w(gt, os.path.join(out, "ground_truth.csv"))}
    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump(man, f, indent=1)
    return man


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--seed", type=int, default=20261022); ap.add_argument("--instruments", type=int, default=2000)
    ap.add_argument("--calibrations", type=int, default=5000); ap.add_argument("--uses", type=int, default=100000); ap.add_argument("--out", default="out")
    a = ap.parse_args(); m = generate(a.seed, a.instruments, a.calibrations, a.uses, a.out)
    print({k: v["rows"] for k, v in m["files"].items()})
