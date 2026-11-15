"""Data validation, ground-truth scoring, KPIs and reproducibility proof.
Supports configurable simulation date alignment with the application server.
"""
import datetime as dt
import json
import os
import shutil
import sys
import tempfile
import pandas as pd
from detect import load
from rules import build_contexts, decide

FK = [
    ("instrument", "asset_id", "asset", "asset_id"),
    ("instrument", "type_id", "instrument_type", "type_id"),
    ("instrument_plan_assignment", "instrument_id", "instrument", "instrument_id"),
    ("instrument_plan_assignment", "plan_id", "calibration_plan", "plan_id"),
    ("calibration_event", "instrument_id", "instrument", "instrument_id"),
    ("calibration_event", "asset_id", "asset", "asset_id"),
    ("calibration_event", "plan_id", "calibration_plan", "plan_id"),
    ("calibration_event", "supplier_id", "supplier", "supplier_id"),
    ("certificate", "calibration_id", "calibration_event", "calibration_id"),
    ("certificate", "instrument_id", "instrument", "instrument_id"),
    ("certificate", "asset_id", "asset", "asset_id"),
    ("certificate", "supplier_id", "supplier", "supplier_id"),
    ("work_order", "instrument_id", "instrument", "instrument_id"),
    ("work_order", "source_calibration_id", "calibration_event", "calibration_id"),
    ("work_order", "closure_calibration_id", "calibration_event", "calibration_id"),
    ("extension", "instrument_id", "instrument", "instrument_id"),
    ("impact_assessment", "failed_calibration_id", "calibration_event", "calibration_id"),
    ("impact_assessment", "last_good_calibration_id", "calibration_event", "calibration_id"),
    ("production_use", "instrument_id", "instrument", "instrument_id"),
    ("production_use", "asset_id", "asset", "asset_id"),
    ("use_decision", "use_id", "production_use", "use_id"),
    ("alert", "instrument_id", "instrument", "instrument_id"),
]

PK = {
    "supplier": "supplier_id",
    "asset": "asset_id",
    "instrument_type": "type_id",
    "calibration_plan": "plan_id",
    "instrument": "instrument_id",
    "instrument_plan_assignment": "assignment_id",
    "calibration_event": "calibration_id",
    "certificate": "cert_id",
    "work_order": "work_order_id",
    "extension": "extension_id",
    "impact_assessment": "ia_id",
    "production_use": "use_id",
    "use_decision": "use_id",
    "alert": "alert_id",
    "audit_record": "audit_id",
}

ENUM = {
    ("calibration_event", "result"): {"PASS", "FAIL"},
    ("work_order", "wo_type"): {"MAINTENANCE", "CORRECTIVE"},
    ("work_order", "status"): {"OPEN", "CLOSED", "PENDING_RELEASE"},
    ("certificate", "status"): {"VALID", "REVOKED", "SUPERSEDED"},
    ("use_decision", "decision"): {"ALLOW", "BLOCK", "ALLOW_WITH_EXCEPTION"},
    ("alert", "status"): {"OPEN", "ACKNOWLEDGED", "RESOLVED"},
}


def repro(params, seed):
    from generate import generate
    a, b = tempfile.mkdtemp(), tempfile.mkdtemp()
    try:
        ma, mb = generate(seed, out=a, **params), generate(seed, out=b, **params)
        return ma["files"] == mb["files"]
    finally:
        shutil.rmtree(a)
        shutil.rmtree(b)


def run(out="out", skip_repro=False, as_of_date=None):
    T = load(os.path.join(out, "data"))
    gt = pd.read_csv(os.path.join(out, "ground_truth.csv"), dtype=str, keep_default_na=False)
    fd = pd.read_csv(os.path.join(out, "findings.csv"), dtype=str, keep_default_na=False)

    with open(os.path.join(out, "manifest.json"), "r", encoding="utf-8") as f:
        man = json.load(f)

    # 1. Structural and Relational Integrity Checks
    pk = sum(int(T[t][c].duplicated().sum()) for t, c in PK.items())
    fkerr = fkn = 0
    for ct, cc, pt, pc in FK:
        v = T[ct][cc]
        v = v[v != ""]
        fkn += len(v)
        fkerr += int((~v.isin(set(T[pt][pc]))).sum())

    enum = sum(int((~T[t][c].isin(s)).sum()) for (t, c), s in ENUM.items())
    ev = T["calibration_event"]
    dateerr = int((ev.created_at.str[:10] < ev.calibration_date).sum())
    wo = T["work_order"]
    cw = wo[wo.wo_type == "CORRECTIVE"]
    res = dict(zip(ev.calibration_id, ev.result))
    cd = dict(zip(ev.calibration_id, ev.calibration_date))

    life = int(sum(1 for r in cw.itertuples() if r.status == "CLOSED" and not (res.get(r.closure_calibration_id) == "PASS" and cd.get(r.closure_calibration_id, "") >= cd.get(r.source_calibration_id, ""))))
    life += int(sum(1 for r in T["production_use"].itertuples() if r.ingestion_timestamp < r.use_timestamp))

    # 2. Confusion Matrix & Detection Metrics against Ground Truth
    pred = set(zip(fd.record_id, fd.issue_type))
    truth = set(zip(gt.record_id, gt.issue_type))
    tp = len(pred & truth)
    P, R = tp / max(len(pred), 1), tp / max(len(truth), 1)
    F1 = 2 * P * R / max(P + R, 1e-9)

    per = {}
    for it in sorted({i for _, i in truth} | {i for _, i in pred}):
        a = {x for x in pred if x[1] == it}
        b = {x for x in truth if x[1] == it}
        t = len(a & b)
        per[it] = (len(b), t, round(t / max(len(a), 1), 4), round(t / max(len(b), 1), 4))

    ud = T["use_decision"]
    blk = set(gt[(gt.record_type == "PRODUCTION_USE") & (gt.expected_decision == "BLOCK")].record_id)
    det = set(ud[ud.decision == "BLOCK"].use_id)
    inj = gt[gt.injected == "1"]
    injd = len({(r, i) for r, i in zip(inj.record_id, inj.issue_type)} & pred)

    # 3. Dynamic Simulation Date Alignment
    # Defaults to 2026-11-15 (matching application server), while also computing 2026-12-31 year-end benchmark
    if as_of_date:
        asof = dt.date.fromisoformat(str(as_of_date)[:10])
    else:
        asof = dt.date(2026, 11, 15)

    T["calibration_plan"]["interval_days"] = T["calibration_plan"].interval_days.astype(int)
    ctx, dups = build_contexts(T)

    # Compliance at configured simulation date (2026-11-15)
    st = {i: decide(c, asof)[1] for i, c in ctx.items()}
    n = len(st)
    allow = sum(1 for v in st.values() if v in ("", "EXTENSION_USE"))
    over = sum(1 for v in st.values() if v in ("EXPIRED_USE", "EXTENSION_EXPIRED_USE", "EXT_UNAUTHORIZED_USE"))

    # Also compute year-end (2026-12-31) for comparison
    asof_ye = dt.date(2026, 12, 31)
    st_ye = {i: decide(c, asof_ye)[1] for i, c in ctx.items()}
    allow_ye = sum(1 for v in st_ye.values() if v in ("", "EXTENSION_USE"))

    passes = ev[(ev.result == "PASS") & (~ev.calibration_id.isin(dups))]
    okc = int(passes.calibration_id.isin(set(T["certificate"].calibration_id)).sum()) - int((fd.issue_type == "WRONG_ASSET_CERT").sum())
    fails = ev[(ev.result == "FAIL")]
    ia = fails.calibration_id.isin(set(T["impact_assessment"].failed_calibration_id)).sum()
    rep = None if skip_repro else repro(man["params"], man["seed"])
    uses_ok = ud.decision.value_counts()

    M = {
        "counts": {k: v["rows"] for k, v in man["files"].items()},
        "pk_errors": pk,
        "fk_errors": fkerr,
        "fk_total": fkn,
        "enum_errors": enum,
        "date_order_rows": dateerr,
        "lifecycle_errors": life,
        "simulation_date": asof.isoformat(),
        "calibration_compliance_pct": round(100 * allow / n, 2),
        "year_end_compliance_pct": round(100 * allow_ye / n, 2),
        "overdue_rate_pct": round(100 * over / n, 2),
        "certificate_completeness_pct": round(100 * okc / len(passes), 2),
        "prohibited_use_detection_pct": round(100 * len(blk & det) / max(len(blk), 1), 2),
        "prohibited_use_total": len(blk),
        "false_blocks": len(det - blk),
        "impact_assessment_coverage_pct": round(100 * ia / max(len(fails), 1), 2),
        "failed_calibrations": len(fails),
        "data_integrity_pct": round(100 * (fkn - fkerr) / fkn, 2),
        "injected_detected_pct": round(100 * injd / max(len(inj), 1), 2),
        "precision": round(P, 4),
        "recall": round(R, 4),
        "f1": round(F1, 4),
        "reproducible": rep,
        "use_decisions": {k: int(v) for k, v in uses_ok.items()},
        "per_issue": per,
    }

    c = M["counts"]
    L = [
        "CALIBRAGUARD DATA VALIDATION",
        "=" * 60,
        f"Instruments:            {c['instrument.csv']:>8,}",
        f"Calibration Events:     {c['calibration_event.csv']:>8,}  (incl. {len(dups)} labelled duplicates)",
        f"Production Uses:        {c['production_use.csv']:>8,}",
        f"Certificates:           {c['certificate.csv']:>8,}",
        f"Work Orders:            {c['work_order.csv']:>8,}",
        f"Alerts / Audit:         {len(T['alert']):,} / {len(T['audit_record']):,}",
        "",
        f"Primary Key Errors:         {pk}",
        f"Foreign Key Errors:         {fkerr} / {fkn}",
        f"Enum Errors:                {enum}",
        f"Lifecycle Errors:           {life}",
        f"Date-order rows (injected): {dateerr}",
        "",
        "KPIs",
        "-" * 60,
        f"Calibration compliance (simulation date {asof}): {M['calibration_compliance_pct']}%  (year-end {asof_ye}: {M['year_end_compliance_pct']}%)",
        f"Overdue rate: {M['overdue_rate_pct']}%",
        f"Certificate completeness: {M['certificate_completeness_pct']}%",
        f"Prohibited-use detection: {M['prohibited_use_detection_pct']}% of {len(blk)} (false blocks: {M['false_blocks']})",
        f"Impact-assessment coverage: {M['impact_assessment_coverage_pct']}% of {len(fails)} failed calibrations (30 deliberate negative cases)",
        f"Data integrity (valid FK): {M['data_integrity_pct']}%",
        "",
        f"Injected anomalies detected: {M['injected_detected_pct']}%  ({injd}/{len(inj)})",
        f"Anomaly detection: precision={P:.4f}  recall={R:.4f}  F1={F1:.4f}",
        "",
        f"{'issue_type':<26}{'truth':>7}{'TP':>7}{'prec':>8}{'rec':>8}",
    ] + [f"{k:<26}{v[0]:>7}{v[1]:>7}{v[2]:>8}{v[3]:>8}" for k, v in per.items()]
    L += ["", f"Reproducibility (2 regenerations, same seed, identical SHA-256): {'SKIPPED' if rep is None else ('PASS' if rep else 'FAIL')}"]

    txt = "\n".join(L)
    with open(os.path.join(out, "validation_report.txt"), "w", encoding="utf-8") as f:
        f.write(txt + "\n")
    with open(os.path.join(out, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(M, f, indent=1)

    print(txt)
    return M


if __name__ == "__main__":
    out_dir = next((a for a in sys.argv[1:] if not a.startswith("--")), "out")
    skip_rep = "--skip-repro" in sys.argv
    asof_arg = None
    for arg in sys.argv:
        if arg.startswith("--as-of="):
            asof_arg = arg.split("=", 1)[1]
    run(out_dir, skip_rep, asof_arg)
