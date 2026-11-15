import hashlib
import os
import sqlite3
import sys
import pandas as pd

ORDER = "supplier asset instrument_type calibration_plan instrument instrument_plan_assignment calibration_event certificate work_order extension impact_assessment production_use use_decision usage_attempt alert audit_record".split()

PREFIX_TABLES = [
    ("AUD-", "audit_record", "audit_id"),
    ("ALT-", "alert", "alert_id"),
    ("WO-2026-", "work_order", "work_order_id"),
    ("USE-", "production_use", "use_id"),
    ("ATT-", "usage_attempt", "attempt_id"),
    ("EXT-", "extension", "extension_id"),
    ("IA-", "impact_assessment", "ia_id"),
]

def load(out="out", dump_sql=False):
    db = os.path.join(out, "calibraguard.sqlite")
    if os.path.exists(db): os.remove(db)
    c = sqlite3.connect(db)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")) as f:
        c.executescript(f.read())
    c.execute("PRAGMA foreign_keys=ON")

    for t in ORDER:
        csv_path = os.path.join(out, "data", t + ".csv")
        if not os.path.exists(csv_path):
            continue
        cols = [r[1] for r in c.execute(f"PRAGMA table_info({t})")]
        df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)

        # Handle hash chaining if loading audit_record
        if t == "audit_record" and "record_hash" not in df.columns:
            prev = "GENESIS_ROOT_2026"
            hashes, prevs = [], []
            for r in df.itertuples(index=False):
                payload = f"{prev}|{r.entity_type}|{r.entity_id}|{r.action}|{r.actor}|{r.event_ts}|{r.old_state}|{r.new_state}|{r.reason}"
                h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                hashes.append(h)
                prevs.append(prev)
                prev = h
            df["record_hash"] = hashes
            df["prev_hash"] = prevs

        for col in cols:
            if col not in df.columns:
                df[col] = ""

        df_aligned = df[cols]
        c.executemany(f"INSERT INTO {t} VALUES ({','.join('?'*len(cols))})", [tuple(None if v == "" else v for v in r) for r in df_aligned.itertuples(index=False)])

    # Initialize sys_sequence with warm sequence counters
    for pfx, tbl, col in PREFIX_TABLES:
        try:
            r = c.execute(f"SELECT MAX(CAST(SUBSTR({col}, {len(pfx)+1}) AS INTEGER)) FROM {tbl} WHERE {col} LIKE ?", (pfx + "%",)).fetchone()[0]
            val = r or 0
        except Exception:
            val = 0
        c.execute("INSERT OR REPLACE INTO sys_sequence VALUES (?, ?)", (pfx, val))

    c.commit()
    if dump_sql:
        with open(os.path.join(out, "calibraguard_seed.sql"), "w") as f:
            for l in c.iterdump(): f.write(l + "\n")
    c.close()
    return db

if __name__ == "__main__": print(load(sys.argv[1] if len(sys.argv) > 1 else "out"))
