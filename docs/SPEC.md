# Vigil: Technical Specifications

**Vigil** is a lightweight CLI tool for security log analysis. It reads SSH logs (OpenSSH `auth.log` format), normalizes them into a unified event model, stores them in SQLite, and detects suspicious patterns based on YAML-defined rules.

*This is a living document. When a technical decision changes, the document is updated in the same commit as the code.*

## 1. Goal and Scope

**Goal:** A tool that can be executed on a standard laptop to analyze a log file and produce a clear, understandable list of suspicious events along with explanations of why they are flagged.

### What Vigil does:

* Parses OpenSSH logs (initially), followed by additional log sources.

* Stores events in SQLite.

* Executes detection rules defined in YAML files.

* Correlates events with each other (post-MVP).

* SPEC.md

* Provides a JSON API and web dashboard (after stabilizing the CLI).

### What Vigil does NOT do (at least in v1.0):

* Does NOT block IP addresses or alter system configurations.

* Does NOT capture network traffic (pcap) or operate as a network sensor.

* Does NOT serve as a full-featured multi-user SIEM platform.

* Does NOT include authentication (as it is designed as a local tool).

* Does NOT guarantee full coverage of the MITRE ATT&CK framework.

*Core Principle: Fewer features, but every single feature is fully tested and honestly documented.*

## 2. Target Audience

* Students and security newcomers who want to understand how detection works on real-world logs.

* Developers looking for an example of a clean Python CLI project with tests, CI/CD, and release management.

* The author, as a portfolio project for future recruiters or educators.

## 3. Functional Requirements

### 3.1 Parsing

* **FR-P1.** The OpenSSH parser must recognize at least the following log line types:

  * `Failed password for <user> from <ip> port <port>`

  * `Failed password for invalid user <user> from <ip> port <port>`

  * `Invalid user <user> from <ip>`

  * `Accepted password for <user> from <ip> port <port>`

  * `Accepted publickey for <user> from <ip> port <port>`

  * `Connection closed by authenticating user <user> <ip> port <port>`

* **FR-P2.** Unrecognized lines must not halt processing. They are counted and reported in the run summary.

* **FR-P3.** Standard syslog formats do not include the year. The year is specified via the `--year` option or defaults to the file's last modified timestamp. This is documented as a key assumption.

* **FR-P4.** All timestamps are normalized to UTC. The default local timezone is assumed to be UTC unless explicitly configured otherwise.

* **FR-P5.** Files are processed line-by-line using streaming to prevent loading the entire file into memory.

### 3.2 Event Model

Unified `Event` data structure (`dataclass`) used across parsers, storage engine, and detection rules:

| Field | Type | Description | 
| ----- | ----- | ----- | 
| `timestamp` | `datetime` (UTC) | Event timestamp | 
| `host` | `str` | Hostname from the log line | 
| `service` | `str` | Service name (e.g., `sshd`) | 
| `event_type` | `str` | `failed_login`, `accepted_login`, `invalid_user`, `connection_closed` | 
| `user` | `str | None` | Target username | 
| `source_ip` | `str | None` | Originating IP address | 
| `port` | `int | None` | Source port number | 
| `raw` | `str` | Original raw log string | 

*Detection rules must strictly evaluate fields within the Event structure and never parse raw text directly.*

### 3.3 Data Storage

* **FR-S1.** SQLite database with a single `events` table and a single `alerts` table.

* **FR-S2.** Indexes configured on `timestamp`, `source_ip`, and `event_type`.

* **FR-S3.** Re-scanning the same log file must be idempotent (no duplicate events created). Handled via line content hash or file offset tracking.

* **FR-S4.** All SQL queries must be parameterized.

* **FR-S5.** The database path is set via the `--db` option or the `VIGIL_DB` environment variable (defaults to `./vigil.db`).

#### Database Schema (SQLite):

```
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,       -- ISO 8601, UTC
    host        TEXT,
    service     TEXT,
    event_type  TEXT NOT NULL,
    user        TEXT,
    source_ip   TEXT,
    port        INTEGER,
    raw         TEXT NOT NULL,
    line_hash   TEXT NOT NULL UNIQUE -- Idempotency key
);

CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_source_ip ON events(source_ip);
CREATE INDEX idx_events_type ON events(event_type);

CREATE TABLE alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL,       -- low | medium | high
    source_ip   TEXT,
    count       INTEGER NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

```

### 3.4 Detection Rules

* **FR-R1.** Rules are stored as YAML files in the `rules/` directory.

* **FR-R2.** Rule specification format:

```
id: ssh_bruteforce
title: Multiple failed SSH login attempts from a single IP
source: auth
match:
  event_type: failed_login
group_by: source_ip
threshold: 10
window: 5m
severity: high

```

* **FR-R3.** Supported `match` criteria: exact field equality on `Event` attributes. Regular expressions are excluded from v1.0.

* **FR-R4.** The `window` field must follow the format `<number><s|m|h>`. Any other format triggers a validation error with a descriptive message.

* **FR-R5.** Invalid YAML rule files must not crash the application: an error is logged with the file name, and remaining rules continue to process.

* **FR-R6.** Alerts store the `rule_id`, `source_ip`, total event count, and first/last occurrence timestamps.

*The `ssh_bruteforce` rule serves as the baseline rule and must be documented with an example in `docs/rules.md`.*

### 3.5 Correlation Engine (v0.6)

* **FR-C1.** Supports sequential rule definitions: "N failed login attempts followed by a successful login from the same IP within T minutes".

* **FR-C2.** Correlation is built as a dedicated module rather than extending the basic YAML rule syntax.

### 3.6 CLI Interface
**Command Structure (v0.5):**

```
v0.2  vigil parse   --input auth.log [--year 2026] [--format json]
v0.5  vigil scan    --input auth.log [--db ./vigil.db] [--rules ./rules]
v0.5  vigil events  [--ip 10.0.0.1] [--type failed_login] [--limit 50] [--db ./vigil.db]
v0.5  vigil alerts  [--severity high] [--db ./vigil.db] [--format json]
v0.5  vigil version
v0.7  vigil report  --out report.html [--db ./vigil.db]

```

* **FR-CLI1.** Exit codes: 0 success, 1 user error (invalid flags, missing file), 2 internal error.

* **FR-CLI2.** `--format json` produces machine-readable output on stdout for scripting. Default output is a human-readable table.

* **FR-CLI3.** Diagnostics and errors go to `stderr`. Results go to `stdout`.

* **FR-CLI4.** Every command that reads or writes the database accepts `--db` and respects `VIGIL_DB`.

### 3.7 Reporting (v0.7)

* **FR-REP1.** HTML report generation featuring an alert list table and an event-by-hour distribution chart (rendered via SVG or matplotlib).

* **FR-REP2.** Single-command report generation: `vigil report --out report.html`.

### 3.8 REST API (v0.8)

Endpoints provided via FastAPI (bound to `127.0.0.1` by default without auth):

* `GET /api/events?limit=&offset=`

* `GET /api/alerts?limit=&offset=`

* `GET /api/ips/{ip}`

### 3.9 Web Dashboard (v0.9)

* High-level metrics overview: counters for total events, alerts, and unique IPs.

* Events table with filter controls for event type and IP.

* Dedicated alerts view page.

* Detailed IP view page with historical activity timelines.

* Built using Jinja2 templates and vanilla CSS with CSS variables (no external CSS frameworks).

## 4. Non-Functional Requirements

* **NFR-1. Platform Compatibility:** Python 3.10+. CI test matrix covers both Ubuntu and Windows environments.

* **NFR-2. Performance:** Stream processing of 1,000,000 log lines without loading the entire dataset into memory; processing time target is under 60 seconds on standard hardware. Benchmarks tracked in `docs/benchmarks.md`.

* **NFR-3. Testing:** Complete test coverage for parser functions and detection rules. Detection rules must include both positive and negative test cases to combat false positives.

* **NFR-4. Documentation:** `README.md` with execution examples, `docs/rules.md`, `docs/architecture.md`, and a comprehensive `CHANGELOG.md`.

* **NFR-5. Data Privacy:** Logs are processed locally and never sent over the network. Real third-party user log data is strictly prohibited in the repository; test fixtures rely on synthetic data or LogHub.

* **NFR-6. Licensing:** Released under the open-source MIT License.

* **NFR-7. Dependencies:** Minimal core dependencies (`pyyaml`). Extra modules like `FastAPI` and `matplotlib` are isolated under optional extras dependencies.

## 5. Architecture

```
src/vigil/
├── __init__.py
├── models/          # Event and Alert dataclasses            (v0.2)
├── parsers/         # Parser interface, openssh.py           (v0.2)
├── storage/         # SQLite schema, inserts, queries        (v0.3)
├── rules/           # loader.py (YAML), engine.py            (v0.4)
├── correlation/     # Sequence detection                     (v0.6)
├── reports/         # HTML report generation                 (v0.7)
├── api/             # FastAPI application                    (v0.8)
├── web/             # Jinja2 templates and static assets     (v0.9)
└── cli/             # main.py: entry point for `vigil`       (v0.5)

rules/               # Example rule files shipped with the tool
docs/                # SPEC.md, rules.md, architecture.md, benchmarks.md
tests/
├── fixtures/        # Small synthetic log samples
├── test_parsers/
├── test_storage/
├── test_rules/
├── test_correlation/
└── test_cli/
data/                # Local datasets, ignored by git

```

**Data Flow Pipeline:**
```text
log file → parser → Event → storage (events)
                    ↓
              rules engine → Alert → storage (alerts)
                                      ↓
                           CLI / report / API / web
```

*Dependency Rule: Higher-level modules (CLI, API, Web) depend on Core components, but Core components have zero dependencies on higher-level layers.*

## 6. Testing & CI/CD Pipeline

* **Local Execution:** Run `pytest` locally prior to committing changes.

* **Continuous Integration:** GitHub Actions matrix running `ubuntu-latest` and `windows-latest` across Python versions 3.10 and 3.14. Status badge embedded in `README`.

* **Test Fixtures:** Synthetic logs with pre-calculated expected results (e.g., "Given 3 attack lines from IP 10.0.0.66, expect exactly one `ssh_bruteforce` alert").

* **LogHub OpenSSH Dataset:** Used for parser integration tests and performance benchmarking.

## 7. Datasets

| Source | Purpose | Version Target | 
| ----- | ----- | ----- | 
| **Synthetic Logs (script)** | Rule validation tests with expected outputs | v0.2 | 
| **LogHub: OpenSSH 2k** | Fast integration testing for log parsers | v0.2 | 
| **LogHub: OpenSSH Full** | Performance & memory footprint benchmarking | v0.4 | 
| **LogHub: Linux** | Robustness verification against non-SSH log lines | v0.4 | 
| **Local auth.log (WSL/Ubuntu)** | Manual testing (excluded from repository commit) | As needed | 

#### 8. Development Roadmap and Releases

Versioning follows SemVer. Each release is a tag `vX.Y.Z`, with a GitHub Release and an entry in `CHANGELOG.md`. Each release has a GitHub Milestone of the same name.

**v0.1.0: Project skeleton (completed)**

- Repository layout, `pyproject.toml`, `.gitignore`, MIT license.
- Smoke test and CI on Ubuntu and Windows.
- **Done:** `pytest` passes locally and in CI.

**v0.2.0: Event model and OpenSSH parser**

- `models/event.py`: `Event` dataclass.
- `parsers/openssh.py`: all six line types from FR-P1.
- Unrecognized lines are counted, not fatal (FR-P2). Year injection (FR-P3) and UTC normalization (FR-P4).
- Fixtures and tests for every line type.
- **Done:** `vigil parse --input tests/fixtures/auth_sample.log` prints parsed events, and tests cover every line type plus unrecognized lines.

**v0.3.0: Storage engine**

- `storage/sqlite.py` with the schema from 3.3.
- Idempotent inserts (FR-S3), indexes (FR-S2), parameterized queries (FR-S4).
- **Done:** running `scan` twice on the same file produces the same row count in `events`.

**v0.4.0: Rule engine**

- `rules/loader.py`: YAML loading and validation (FR-R4, FR-R5).
- `rules/engine.py`: grouping by `group_by` within `window` (FR-R2).
- `rules/ssh_bruteforce.yml` as the baseline rule.
- Positive and negative tests for the rule.
- Benchmark on the full OpenSSH dataset, recorded in `docs/benchmarks.md`.
- **Done:** the rule fires on the synthetic attack set, does not fire on normal traffic, and the benchmark is recorded.

**v0.5.0: Command-line interface**

- Commands `parse`, `scan`, `events`, `alerts`, `version` (3.6).
- Exit codes, `--format json`, stdout/stderr separation.
- **Done:** the `scan` → `alerts` flow works end to end on Ubuntu and Windows in CI.

**v0.6.0: Correlation**

- `correlation/` module: “N failed logins followed by a success from the same IP within T minutes” (FR-C1, FR-C2).
- Tests for event order and for the time window.
- **Done:** the correlation fires on the full sequence and stays silent when the order is broken or the window is exceeded.

**v0.7.0: HTML report**

- `vigil report --out report.html` (FR-REP1, FR-REP2).
- **Done:** the report opens in a browser and contains the alert table and the hourly chart.

**v0.8.0: REST API**

- FastAPI endpoints from 3.8, bound to `127.0.0.1`.
- Tests with `TestClient`.
- **Done:** all three endpoints return correct data in tests, and the README has `curl` examples.

**v0.9.0: Web dashboard**

- Views from 3.9, built from a separate visual brief.
- Contrast and keyboard-focus checks.
- **Done:** all four views render from real database data, and the dashboard passes a basic contrast check.

**v1.0.0: Stable release**

- Public interfaces frozen and documented.
- README with architecture overview, full example, and screenshots from real or LogHub data.
- Repository social preview image (1280×640).
- **Done:** `pip install .` followed by the README workflow works on Ubuntu and Windows.

## 9. GitHub Workflow and Guidelines

* **Branching Strategy:** `main` remains the production-stable branch. Feature work is done in short-lived branches (`feat/...`, `fix/...`, `docs/...`).

* **Commit Messages:** Imperative mood titles in English (e.g., `Add OpenSSH parser for failed password lines`). One logical change per commit.

* **Issues & Milestones:** Tasks map to individual GitHub Issues with labels (`parser`, `storage`, `rules`, `cli`, `docs`, `bug`) and release Milestones.

* **Changelog:** Adheres to the Keep a Changelog standard (`Added`, `Changed`, `Fixed`).

## 10. Out of Scope (Future Considerations)

* Support for additional log sources (Nginx, Windows Event Logs, router syslogs).

* PyPI package publication (post-v1.0).

* Configuration management via `vigil.toml`.

* Advanced timezone handling per remote host.

* Exporting alerts to Sigma format.

## 11. Risk Management

| Risk | Impact | Mitigation Strategy | 
| ----- | ----- | ----- | 
| **High False Positive Rates** | Noise, user loss of trust | Robust positive/negative unit tests, benchmark checks against realistic datasets. | 
| **OS Differences (Windows/Linux)** | Broken CI / cross-platform bugs | Dual-OS CI matrix from day one, strict use of `pathlib` and UTF-8 encoding. | 
| **Missing Year/Timezone in Syslog** | Event timestamp errors | Explicit `--year` argument, fallback to UTC, edge-case testing for year boundaries. | 
| **Feature Creep** | Unfinished project | Strict adherence to project boundaries (Section 1) and defined "Done" criteria. | 

## 12. Document Status

* **Version:** 0.1

* **Current Stage:** v0.1.0 completed ➔ transitioning to v0.2.0