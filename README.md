# CalibraGuard

**Industrial calibration, instrument eligibility, and production-compliance tracking.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Tests](https://img.shields.io/badge/Tests-unittest-2088FF)](#testing)

CalibraGuard helps plant operators verify instruments before production use and gives quality teams traceable workflows for calibration failures, impact review, recalibration, and authorized release.

> [!IMPORTANT]
> **Demo and evaluation software.** The included data is synthetic, and seeded accounts or default authentication configuration are for local demonstration only. Do not deploy with demo credentials or secrets. CalibraGuard is not a validated quality-management system.

## Contents

- [At a glance](#at-a-glance)
- [Features](#features)
- [Workflow](#workflow)
- [Roles](#roles)
- [Architecture](#architecture)
- [Technology](#technology)
- [Getting started](#getting-started)
- [Testing](#testing)
- [SQL and performance](#sql-and-performance)
- [Screenshots](#screenshots)
- [Limitations and future work](#limitations-and-future-work)

## At a glance

Calibration lapses can make production measurements unreliable and create compliance and traceability gaps. CalibraGuard maintains an instrument register and evaluates eligibility using calibration history, plans, certificates, lifecycle state, maintenance windows, and release status.

The application includes a browser dashboard, an HTTP JSON API, a SQLite data store, generated demonstration data, anomaly checks, and operational analytics.

## Features

- **Use eligibility:** evaluates an instrument at the requested simulation time and returns an allow/block decision with a reason.
- **Calibration evidence:** checks calibration dates, effective-dated plans, certificate-to-instrument and certificate-to-asset mappings, certificate status and validity, and measurement-range coverage.
- **Failure lifecycle:** failed calibrations quarantine instruments and support impact-assessment and corrective-work-order workflows.
- **Controlled release:** a passing recalibration moves an instrument to pending release. An authorized user must release it before production use can resume.
- **Production traceability:** allowed production uses are recorded separately from blocked usage attempts.
- **Role-based access:** operator, planner, quality engineer, plant manager, and OT administrator permissions are enforced server-side.
- **Audit and analytics:** audit records use a SHA-256 hash chain; analytics include supplier summaries, upcoming deadlines, latest calibrations, and alert summaries.
- **Reproducible demo data:** data generation uses a fixed seed by default and writes generated files to `out/`.

## Workflow

1. An operator checks an instrument and production order in the Operator Portal.
2. The eligibility rules return a decision and record the attempt.
3. A calibration failure quarantines the instrument and supports impact review.
4. A quality engineer records recalibration. A passing result remains pending release.
5. An authorized user releases the instrument, allowing eligible production use to resume.

## Roles

| Role | Typical capabilities |
| --- | --- |
| Plant operator | Check instruments and record production use |
| Production planner | View the registry, metrics, work orders, and planning information |
| Quality engineer | Record calibration, investigate failures, approve extensions, release instruments, and view audit history |
| Plant manager | Quality workflows and policy override permissions |
| OT administrator | Administrative and policy-management permissions |

Actual permissions are defined in [`auth.py`](auth.py) and enforced by [`server.py`](server.py).

## Architecture

| Layer | Components | Responsibility |
| --- | --- | --- |
| Presentation | [`static/index.html`](static/index.html) | Browser dashboard, operator and quality workflows, and analytics views |
| Application | [`server.py`](server.py), [`rules.py`](rules.py), [`auth.py`](auth.py) | HTTP JSON API, eligibility rules, authentication, authorization, and workflow handling |
| Data | [`schema.sql`](schema.sql), SQLite | Relational records, constraints, indexes, transactions, and audit history |

Supporting scripts generate data, detect issues, load SQLite, and validate results: [`generate.py`](generate.py), [`detect.py`](detect.py), [`loaddb.py`](loaddb.py), [`validate.py`](validate.py), and [`run_all.py`](run_all.py).

## Technology

- Python 3.10+
- SQLite
- pandas and NumPy
- HTML, CSS, and browser JavaScript
- Python `unittest`; optional Playwright browser-test specification

Dependencies are listed in [`requirements.txt`](requirements.txt). The frontend does not require a separate build step.

## Getting started

### Prerequisites

- Python 3.10 or later
- pip

### 1. Create a virtual environment

```shell
python -m venv .venv
```

Activate it:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```shell
# macOS/Linux
source .venv/bin/activate
```

### 2. Install dependencies

```shell
python -m pip install -r requirements.txt
```

### 3. Generate data and initialize the database

For a smaller local dataset:

```shell
python run_all.py --small --skip-repro
```

For the default dataset and full validation:

```shell
python run_all.py
```

Generated CSV files, reports, and the SQLite database are written to `out/`. This generated directory is ignored by Git and can be recreated by rerunning the command.

### 4. Start the application

```shell
python server.py
```

Open [http://localhost:8000](http://localhost:8000). The server expects the database created in the previous step. To use another port, run:

```shell
python server.py --port 8080
```

## Testing

Run the automated test suite from the repository root:

```shell
python -m unittest discover -s tests
```

The repository contains **43 `unittest` cases** across eight test modules, covering data integrity and rules, authentication and permissions, API workflows, transaction and concurrency behavior, analytics, audit-chain validation, and SQL query plans.

[`tests/test_playwright_e2e.py`](tests/test_playwright_e2e.py) describes an optional browser workflow. It requires Playwright and Chromium and is not run by the standard `unittest` command.

## SQL and performance

The SQL-focused tests exercise:

- Indexed timestamp-range filtering without applying a function to the filtered timestamp column.
- Indexes for alert, work-order, and audit lookup patterns.
- Window functions, common table expressions, and conditional aggregation.
- Supplier-performance summaries and upcoming calibration deadlines.
- Recalculation of the audit hash chain.
- A local comparison of indexed range filtering with a `SUBSTR()`-based query.

Benchmark timings depend on the machine, SQLite build, and dataset. They are local measurements, not production-scale latency or throughput guarantees. Anomaly-detection results from generated data describe the synthetic test set only; they do not establish accuracy on real plant data.

## Screenshots

Add current screenshots captured from the running application under `docs/screenshots/`. Useful views include the executive dashboard, instrument-use decision, quality/release workflow, and SQL analytics. Use sanitized demonstration data only.

## Limitations and future work

- Generated data is synthetic and must not be used to make operational decisions.
- Seeded demo users and any built-in fallback secret are unsuitable for production. Use managed secret storage, replace demo credentials, and review token/session policies before deployment.
- SQLite and the built-in HTTP server are for local demonstration, not a substitute for a hardened production service, managed identity, deployment controls, or operational monitoring.
- Database triggers and a hash chain provide tamper evidence within the database design, but do not protect against a privileged actor who can rewrite the database and recompute the chain. Production audit retention should use restricted access and independently protected backups or external append-only storage.
- Validate workflows, retention policy, and quality-system requirements with the organization before any regulated use.

Potential next steps include browser-based end-to-end testing in CI, migration and backup/restore testing, workload-specific performance testing, and production-grade authentication, authorization, monitoring, and audit storage.
