CREATE TABLE supplier(
    supplier_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    accreditation_no TEXT,
    country TEXT,
    status TEXT CHECK(status IN('ACTIVE','SUSPENDED','REVOKED'))
);

CREATE TABLE asset(
    asset_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    plant TEXT NOT NULL,
    line TEXT NOT NULL,
    status TEXT
);

CREATE TABLE instrument_type(
    type_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    unit TEXT,
    range_min REAL DEFAULT 0,
    range_max REAL NOT NULL,
    criticality TEXT CHECK(criticality IN('LOW','MEDIUM','HIGH')),
    CONSTRAINT chk_type_range CHECK(range_min <= range_max)
);

CREATE TABLE calibration_plan(
    plan_id TEXT PRIMARY KEY,
    interval_days INTEGER NOT NULL CHECK(interval_days > 0),
    tolerance_pct REAL NOT NULL CHECK(tolerance_pct > 0),
    tier TEXT,
    effective_from TEXT NOT NULL,
    effective_to TEXT,
    policy_version TEXT
);

CREATE TABLE instrument(
    instrument_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES asset(asset_id),
    type_id TEXT NOT NULL REFERENCES instrument_type(type_id),
    serial_no TEXT UNIQUE,
    commissioned_date TEXT,
    lifecycle_state TEXT CHECK(lifecycle_state IN('ACTIVE','QUARANTINED','PENDING_RELEASE','MAINTENANCE','RETIRED'))
);

CREATE TABLE instrument_plan_assignment(
    assignment_id TEXT PRIMARY KEY,
    instrument_id TEXT NOT NULL REFERENCES instrument(instrument_id),
    plan_id TEXT NOT NULL REFERENCES calibration_plan(plan_id),
    effective_from TEXT NOT NULL,
    effective_to TEXT
);

CREATE TABLE calibration_event(
    calibration_id TEXT PRIMARY KEY,
    instrument_id TEXT NOT NULL REFERENCES instrument(instrument_id),
    asset_id TEXT NOT NULL REFERENCES asset(asset_id),
    plan_id TEXT NOT NULL REFERENCES calibration_plan(plan_id),
    supplier_id TEXT NOT NULL REFERENCES supplier(supplier_id),
    calibration_date TEXT NOT NULL,
    created_at TEXT NOT NULL,
    result TEXT CHECK(result IN('PASS','FAIL')),
    as_found_error_pct REAL,
    tolerance_pct REAL,
    next_due_date TEXT,
    failure_reason TEXT,
    status TEXT
);

CREATE TABLE certificate(
    cert_id TEXT PRIMARY KEY,
    calibration_id TEXT NOT NULL REFERENCES calibration_event(calibration_id),
    instrument_id TEXT NOT NULL REFERENCES instrument(instrument_id),
    asset_id TEXT NOT NULL REFERENCES asset(asset_id),
    supplier_id TEXT NOT NULL REFERENCES supplier(supplier_id),
    certificate_number TEXT UNIQUE,
    issue_date TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    range_min REAL DEFAULT 0,
    range_max REAL NOT NULL,
    status TEXT CHECK(status IN('VALID','REVOKED','SUPERSEDED')),
    version INTEGER DEFAULT 1,
    CONSTRAINT chk_cert_dates CHECK(valid_from <= valid_to),
    CONSTRAINT chk_cert_range CHECK(range_min <= range_max)
);

CREATE TABLE work_order(
    work_order_id TEXT PRIMARY KEY,
    instrument_id TEXT NOT NULL REFERENCES instrument(instrument_id),
    wo_type TEXT CHECK(wo_type IN('MAINTENANCE','CORRECTIVE')),
    priority TEXT,
    assigned_to TEXT,
    opened_date TEXT NOT NULL,
    due_date TEXT,
    closed_date TEXT,
    status TEXT CHECK(status IN('OPEN','CLOSED','PENDING_RELEASE')),
    downtime_start TEXT,
    downtime_end TEXT,
    source_calibration_id TEXT REFERENCES calibration_event(calibration_id),
    closure_calibration_id TEXT REFERENCES calibration_event(calibration_id)
);

CREATE TABLE extension(
    extension_id TEXT PRIMARY KEY,
    instrument_id TEXT NOT NULL REFERENCES instrument(instrument_id),
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    approver_role TEXT NOT NULL,
    reason TEXT,
    evidence_ref TEXT,
    scope TEXT,
    status TEXT,
    policy_version TEXT,
    CONSTRAINT chk_ext_dates CHECK(start_date <= end_date)
);

CREATE TABLE impact_assessment(
    ia_id TEXT PRIMARY KEY,
    failed_calibration_id TEXT NOT NULL REFERENCES calibration_event(calibration_id),
    instrument_id TEXT NOT NULL REFERENCES instrument(instrument_id),
    last_good_calibration_id TEXT REFERENCES calibration_event(calibration_id),
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    affected_use_count INTEGER DEFAULT 0,
    affected_order_count INTEGER DEFAULT 0,
    status TEXT,
    created_at TEXT NOT NULL,
    assessed_by TEXT
);

CREATE TABLE production_use(
    use_id TEXT PRIMARY KEY,
    instrument_id TEXT NOT NULL REFERENCES instrument(instrument_id),
    asset_id TEXT NOT NULL REFERENCES asset(asset_id),
    production_order_id TEXT,
    operator_id TEXT,
    use_timestamp TEXT NOT NULL,
    ingestion_timestamp TEXT
);

CREATE TABLE use_decision(
    use_id TEXT PRIMARY KEY REFERENCES production_use(use_id),
    decision TEXT CHECK(decision IN('ALLOW','BLOCK','ALLOW_WITH_EXCEPTION')),
    issue_type TEXT,
    reason TEXT,
    policy_version TEXT,
    extension_id TEXT REFERENCES extension(extension_id),
    decided_at TEXT
);

CREATE TABLE usage_attempt(
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
);

CREATE TABLE alert(
    alert_id TEXT PRIMARY KEY,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    instrument_id TEXT REFERENCES instrument(instrument_id),
    created_at TEXT NOT NULL,
    message TEXT,
    status TEXT CHECK(status IN('OPEN','ACKNOWLEDGED','RESOLVED')),
    rule_id TEXT
);

CREATE TABLE audit_record(
    audit_id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    event_ts TEXT NOT NULL,
    old_state TEXT,
    new_state TEXT,
    reason TEXT,
    record_hash TEXT,
    prev_hash TEXT
);

CREATE TABLE sys_sequence(
    prefix TEXT PRIMARY KEY,
    current_val INTEGER NOT NULL
);

-- Immutable Audit Triggers
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_record BEGIN SELECT RAISE(ABORT,'audit_record is immutable'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_record BEGIN SELECT RAISE(ABORT,'audit_record is immutable'); END;

-- Performance Indexes (Targeting Hot Query Access Paths)
CREATE INDEX ix_cal_inst ON calibration_event(instrument_id, calibration_date);
CREATE INDEX ix_cal_supplier ON calibration_event(supplier_id, result);
CREATE INDEX ix_use_inst ON production_use(instrument_id, use_timestamp);
CREATE INDEX ix_attempt_inst ON usage_attempt(instrument_id, attempt_timestamp);
CREATE INDEX ix_alert_inst ON alert(instrument_id);
CREATE INDEX ix_alert_severity_created ON alert(severity, created_at DESC);
CREATE INDEX ix_open_alerts ON alert(created_at DESC, severity) WHERE status = 'OPEN';
CREATE INDEX ix_workorder_type_status_date ON work_order(wo_type, status, opened_date DESC);
CREATE INDEX ix_audit_entity_time ON audit_record(entity_id, event_ts DESC, audit_id DESC);
CREATE INDEX ix_cert_cal ON certificate(calibration_id);
CREATE INDEX ix_cert_inst ON certificate(instrument_id);
CREATE INDEX ix_asg_inst_dates ON instrument_plan_assignment(instrument_id, effective_from, effective_to);
CREATE INDEX ix_impact_failed ON impact_assessment(failed_calibration_id);
