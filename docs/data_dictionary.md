# CalibraGuard data dictionary (summary; authoritative DDL in `schema.sql`)
IDs are immutable and zero-padded: `AST-000001`, `INS-000001`, `CAL-<asset-id>-2026-000001`, `CERT-<calibration-id>`, `WO-2026-000001`, `USE-<asset-id>-<YYYYMMDD>T<HHMMSS>`, `EXT-/IA-<cal>/ALT-/AUD-`.
All dates ISO-8601; timestamps `YYYY-MM-DDTHH:MM:SS` (plant local). Intervals in days; tolerance and error in % of reading.

| Entity | PK | FKs (cardinality) | Key fields / allowed values / rules |
|---|---|---|---|
| supplier | supplier_id | – | status ACTIVE/SUSPENDED/REVOKED; accreditation_no unique-ish |
| asset | asset_id | – | plant, line, status |
| instrument_type | type_id | – | unit, range_min<range_max, criticality LOW/MEDIUM/HIGH |
| calibration_plan | plan_id | – | interval_days>0, tolerance_pct, tier STANDARD/STRICT (HIGH-criticality types), effective_from/to, policy_version |
| instrument | instrument_id | asset (N:1), type (N:1) | serial_no unique, lifecycle_state; asset 1:N instruments |
| instrument_plan_assignment (bridge) | assignment_id | instrument (N:1), plan (N:1) | effective_from required, effective_to nullable ⇒ plan history, no overwrite |
| calibration_event | calibration_id | instrument, asset, plan, supplier (all N:1) | result PASS/FAIL; next_due_date = calibration_date + plan interval (PASS only); created_at ≥ calibration_date; (instrument,date,result) unique |
| certificate | cert_id | calibration_event (1:0..1), instrument, asset, supplier | issued only for PASS; asset_id must equal instrument's asset; status VALID/REVOKED/SUPERSEDED; `version` supports 1:N revisions |
| work_order | work_order_id | instrument; source_calibration_id, closure_calibration_id (optional) | wo_type MAINTENANCE/CORRECTIVE; downtime_start ≤ downtime_end; CORRECTIVE closed only by a later PASS |
| extension | extension_id | instrument | approver_role must be QUALITY_ENGINEER/PLANT_MANAGER; start/end dates, reason, evidence_ref, scope, policy_version |
| impact_assessment | ia_id | failed calibration (1:1), last_good calibration (optional), instrument | window = last good calibration → failure; counts derived from production_use |
| production_use | use_id | instrument, asset | use_timestamp; production_order_id; ingestion_timestamp ≥ use_timestamp (late OT arrivals) |
| use_decision | use_id | production_use (1:1) | decision ALLOW/BLOCK/ALLOW_WITH_EXCEPTION, issue_type, reason, policy_version, extension_id — evaluated **at time of use** |
| alert | alert_id | instrument | derived from findings; severity; status OPEN/ACKNOWLEDGED/RESOLVED |
| audit_record | audit_id | entity (polymorphic) | append-only (SQLite triggers reject UPDATE/DELETE) |

Lifecycle: ACTIVE → (FAIL) QUARANTINED → (PASS recal + closed corrective WO) ACTIVE; MAINTENANCE downtime blocks use.
`ground_truth.csv` (separate, never read by the engine): record_id, record_type, issue_type, expected_decision, instrument_id, injected, severity.
