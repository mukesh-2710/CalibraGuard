# CalibraGuard

Industrial calibration, instrument eligibility, and production-compliance tracking in a lightweight Python and SQLite application.

CalibraGuard brings instrument status, calibration evidence, production-use decisions, and exception history into one workflow. It helps plant operators check equipment before use and gives quality teams traceable controls for failures, recalibration, and release.

> **Evaluation/demo software.** The included data is synthetic, and the seeded accounts and default authentication configuration are for local demonstration only. Do not deploy this application with demo credentials or secrets.

## Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Technology](#technology)
- [Run locally](#run-locally)
- [Tests and benchmarks](#tests-and-benchmarks)
- [Screenshots](#screenshots)
- [Limitations and next steps](#limitations-and-next-steps)

## Overview

Calibration lapses can make production measurements unreliable and create compliance and traceability gaps. CalibraGuard provides a central instrument register and evaluates whether equipment is eligible for use using its calibration history, plan, certificate, lifecycle state, maintenance windows, and authorized release status.

The application includes role-aware portals, an HTTP JSON API, a SQLite data store, generated demonstration data, anomaly checks, and operational analytics. It is designed to demonstrate engineering workflows and is not a validated quality-management system.

## Features

- **Use eligibility:** checks the instrument at the requested simulation time and returns an allow/block decision with a reason.
- **Calibration evidence:** evaluates calibration dates, effective-dated plans, certificate-to-instrument and certificate-to-asset mappings, validity, status, and measurement-range coverage.
- **Failure lifecycle:** failed calibrations quarantine instruments and support impact-assessment and corrective-work-order workflows.
- **Controlled release:** a passing recalibration moves an instrument to pending release; an authorized quality or management user must release it before production use is allowed.
- **Production traceability:** allowed uses are recorded separately from blocked usage attempts.
- **Role-based access:** operator, planner, quality engineer, plant manager, and OT administrator personas have different server-enforced permissions.
- **Audit and analytics:** audit records include a SHA-256 hash chain; analytics include supplier summaries, upcoming deadlines, latest calibrations, and alert summaries.
- **Reproducible demo data:** data generation uses a fixed seed by default and writes generated files under `out/`.

### Main workflow

1. An operator checks an instrument and production order in the Operator Portal.
2. The eligibility rules return an allow or block decision and record the attempt.
3. A calibration failure quarantines the instrument and supports impact review.
4. A quality engineer records a recalibration; a passing result remains pending release.
5. An authorized user releases the instrument, after which eligible use can resume.

### Roles

| Role | Typical capabilities |
| --- | --- |
| Plant operator | Check instruments and record production use |
| Production planner | View registry, metrics, work orders, and planning information |
| Quality engineer | Record calibration, investigate failures, approve extensions, release instruments, and view audit history |
| Plant manager | Quality workflows plus policy override permissions |
| OT administrator | Administrative and policy-management permissions |

Actual permissions are defined in [`auth.py`](auth.py) and enforced by the server.

## Architecture

| Layer | Components | Responsibility |
| --- | --- | --- |
| Presentation | [`static/index.html`](static/index.html) | Browser dashboard, operator and quality workflows, and analytics views |
| Application | [`server.py`](server.py), [`rules.py`](rules.py), [`auth.py`](auth.py) | HTTP JSON API, eligibility rules, authentication, authorization, and workflow handling |
| Data | [`schema.sql`](schema.sql), SQLite | Relational records, constraints, indexes, transactions, and audit history |

Supporting scripts generate data, detect issues, load SQLite, and validate results: [`generate.py`](generate.py), [`detect.py`](detect.py), [`loaddb.py`](loaddb.py), [`validate.py`](validate.py), and [`run_all.py`](run_all.py).

## Technology

- Python 3.10 or later
- SQLite
- pandas and NumPy
- HTML, CSS, and browser JavaScript
- Python `unittest`; optional Playwright browser-test specification

Dependencies are listed in [`requirements.txt`](requirements.txt). The application does not require a separate frontend build step.

## Run locally

### 1. Create an environment and install dependencies

```bash
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# macOS/Linux
source .venv/bin/activate
```

Then install dependencies:

```bash
python -m pip install -r requirements.txt
```

### 2. Generate data and initialize the database

For a smaller local dataset:

```bash
python run_all.py --small --skip-repro
```

For the default dataset and full validation:

```bash
python run_all.py
```

Generated CSV files, reports, and the SQLite database are written to `out/`. This directory is intentionally ignored by Git; rerun the generation command to recreate it.

### 3. Start the application

```bash
python server.py
```

Open [http://localhost:8000](http://localhost:8000). The server expects the database created in the previous step. To use a different port, run `python server.py --port 8080`.

### 4. Run automated tests

```bash
python -m unittest discover -s tests
```

The test suite covers data integrity and rules, authentication and permissions, API workflows, transaction/concurrency behavior, analytics, audit-chain validation, and SQL query plans. One test file describes an optional Playwright browser journey; that browser test requires Playwright and Chromium and is not included in the standard `unittest` command.

## Tests and benchmarks

The repository includes **43 `unittest` cases** across eight test modules. The suite has passed in the development environment; run the command above to verify the current checkout.

SQL-focused tests check that:

- Timestamp range queries can use the `(instrument_id, use_timestamp)` index rather than applying a function to the filtered timestamp column.
- Work-order, alert, and audit lookup indexes are available to their query patterns.
- The analytics use window functions, CTEs, and conditional aggregation.
- The audit hash chain can be recomputed and checked.
- A benchmark compares an indexed range query with a `SUBSTR()`-based query.

Benchmark timings depend on the machine, SQLite build, and dataset. They are local measurements, not production-scale latency or throughput guarantees. Likewise, anomaly-detection scores from generated data describe the synthetic test set only; they do not establish accuracy on real plant data.

## Screenshots

Add current screenshots captured from the running application under `docs/screenshots/`. Useful views include the executive dashboard, instrument-use decision, quality/release workflow, and SQL analytics. Only include screenshots that reflect the current application and use sanitized demonstration data.

## Limitations and next steps

- The generated dataset is synthetic and should not be used to make operational decisions.
- Seeded demo users and any built-in fallback secret are unsuitable for production. Configure secret management, replace demo credentials, and review token/session policies before deployment.
- SQLite and the built-in HTTP server are suitable for local demonstration, not a substitute for a hardened production service, managed identity, deployment controls, or operational monitoring.
- Database triggers and a hash chain provide tamper evidence within the database design, but do not protect against a privileged actor who can rewrite the database and recompute the chain. Production audit retention should use restricted access and independently protected backups or external append-only storage.
- Validate the workflows, retention policy, and quality-system requirements with the organization before any regulated use.

Potential follow-up work includes browser-based end-to-end testing in CI, migration and backup/restore testing, workload-specific performance testing, and production-grade authentication, authorization, monitoring, and audit storage.
