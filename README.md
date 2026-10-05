# Kyptic

> **decode. detect. defend.**

Kyptic is an enterprise-grade Application & API Security Platform that unifies white-box code analysis, black-box web & API DAST, browser-based SPA security scanning, grey-box context correlation, targeted vulnerability verification, cross-validation confidence scoring, dynamic risk graph visualization, regulatory compliance mapping, and an AI security copilot.

---

## Key Capabilities

### Database Architecture & Hosting Readiness (Phase 1 Implemented)
- **PostgreSQL Relational Primary DB**: Production-grade relational database architecture backed by SQLAlchemy and PostgreSQL.
- **Alembic Schema Versioning**: Automated schema migration management replacing legacy ad-hoc table alterations.
- **Docker Compose Local Setup**: One-command reproducible local PostgreSQL container environment (`docker-compose up -d`).
- **Data Preservation Migration Utility**: Safe migration utility (`python -m app.migrations.migrate_sqlite_to_postgres`) preserving existing baseline project, scan, finding, and endpoint records with integrity verification.
- **Storage Abstraction**: Cross-platform file path resolution (`StorageService`) supporting both local filesystem and cloud S3-compatible object storage.
- **Credential Protection**: Secret-safe URL masking preventing database password leakage in application logs.

### White-Box Security (SAST & SCA)
- **Static Code Analysis (SAST)**: Identifies code-level injection flaws (SQLi, Command Injection, XSS), cryptographic weaknesses, insecure session handling, and misconfigurations via Semgrep integration.
- **Hardcoded Secret Detection**: Scans source repositories for exposed API tokens, JWTs, private keys, passwords, and database connection URIs via `detect-secrets`.
- **Software Composition Analysis (SCA)**: Inspects project manifests (`package.json`, `requirements.txt`, `pom.xml`) to detect vulnerable third-party dependencies.
- **Finding Normalization**: Standardizes raw scanner outputs into unified finding models mapped to **CWE**, **OWASP**, and **CVSS v3.1** metrics.

### Web DAST (Dynamic Security Testing)
- **HTTP Crawling & Discovery**: Safely discovers application routes, exposed files (`.env`, `.git`), and security headers (`HSTS`, `CSP`, `X-Frame-Options`).
- **SSRF Defenses**: Enforces pre-request IP resolution, loopback (`127.0.0.1`), private RFC-1918 IP blocking, cloud metadata (`169.254.169.254`) blocking, and same-origin redirect constraints.
- **Resource Limits**: Controls timeout bounds (default 5.0s), body size caps, and concurrency bounds.

### API Security
- **OpenAPI Ingestion**: Supports OpenAPI 2.0 (Swagger) and OpenAPI 3.x specifications in both JSON and YAML formats.
- **Endpoint Inventory**: Parses API paths, HTTP methods, authentication policies, request schemas, and parameters.
- **Vulnerability Checks**: BOLA / IDOR, Broken Authentication, Mass Assignment, and Rate Limiting assessment.

### Browser-Based DAST
- **Headless Chromium Automation**: Utilizes Playwright to launch isolated headless browser contexts for dynamic Single Page Application (SPA) crawling.
- **DOM XSS & Client-Side Probing**: Simulates user interactions and form submissions to detect client-side vulnerabilities.

### Grey-Box Context Engine
- Correlates static source code findings with dynamic API endpoint routes using a 4-tier resolution strategy (Exact Path Match, Route Annotations, Controller Heuristics, Unmapped Fallback).

### Targeted Verification
- Executes active, vulnerability-specific verification probes to eliminate false positives without executing destructive payloads.

### Cross-Validation & Confidence Engine
- Multi-source evidence correlation engine calculating authoritative `confidence_score` (0-100%), `confidence_level`, and `verification_status`.

### Dynamic Security Risk Map
- Production-grade hierarchical DAG graph visualization mapping application architecture topology:
  $$\text{PROJECT} \longrightarrow \text{API} \longrightarrow \text{ENDPOINT} \longrightarrow \text{FINDING} \longrightarrow \text{VULNERABILITY / FILE}$$

### Regulatory Compliance Mapping
- Maps Kyptic security findings to control requirements across PCI DSS v4.0, SOC 2 Type II, ISO/IEC 27001:2022, OWASP API Security Top 10, OWASP Web Security Top 10, and CWE Top 25.

---

## Architecture

```mermaid
graph TD
    Client["React 19 Frontend UI"] -->|REST API| Router["FastAPI Router / Main Entry"]

    subgraph "Backend Core Services"
        Router --> Orchestrator["Scan Orchestrator Engine"]
        Router --> RiskMap["Dynamic Risk Map Engine"]
        Router --> Compliance["Compliance Mapping Engine"]
        Router --> Verifier["Targeted Verification Engine"]

        Orchestrator --> WhiteBox["White-Box SAST / SCA / Secrets"]
        Orchestrator --> WebDAST["HTTP Web DAST Engine"]
        Orchestrator --> APIDAST["OpenAPI Security Scanner"]
        Orchestrator --> BrowserDAST["Playwright Browser DAST Engine"]
        Orchestrator --> GreyBox["Grey-Box Context Engine"]
        Orchestrator --> CrossVal["Cross-Validation Engine"]

        CrossVal --> DB[(PostgreSQL / SQLAlchemy DB)]
        RiskMap --> DB
        Compliance --> DB
        Verifier --> DB
    end
```

---

## Installation & Setup

### Prerequisites
- **Operating System**: Windows 10/11, Linux, or macOS
- **Python**: Python 3.10+
- **Node.js**: Node.js 18+ & npm
- **PostgreSQL**: PostgreSQL 14+ (or Docker Compose)
- **Git**: Latest release
- **Playwright / Chromium**: Required for Browser-Based DAST

---

### Step 1: Clone Repository

```bash
git clone https://github.com/sakship701/kyptic-api-security.git
cd kyptic-api-security
```

---

### Step 2: Database Setup (PostgreSQL)

Option A: Run PostgreSQL via Docker Compose:
```bash
docker-compose up -d
```

Option B: Use an existing PostgreSQL instance or local SQLite fallback for development.

Configure `.env`:
```bash
cp .env.example .env
```
Set `DATABASE_URL=postgresql+psycopg2://kyptic:kyptic_dev_pass@localhost:5432/kyptic_db`

---

### Step 3: Backend Setup & Migrations

Create virtual environment and install dependencies:
```powershell
python -m venv backend/.venv
.\backend\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
```

Run Alembic migrations:
```powershell
cd backend
alembic upgrade head
```

Run SQLite to PostgreSQL data migration utility (preserves baseline real data):
```powershell
python app/migrations/migrate_sqlite_to_postgres.py
```

---

### Step 4: Frontend Setup

Install Node dependencies:
```powershell
npm install
```

---

## Running Kyptic

### Start Backend Server

```powershell
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

- **Backend API**: `http://localhost:8000`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`

### Start Frontend Dev Server

```powershell
npm run dev
```

- **Frontend UI Application**: `http://localhost:5173`

---

## Running Tests

Run backend Phase 1 PostgreSQL architecture test suite:
```powershell
cd backend
python -m pytest app/test_phase1_postgres_architecture.py -v
```

Run full database & posture test suite:
```powershell
python -m pytest app/test_phase1_postgres_architecture.py app/test_dashboard_real_data.py app/test_database_isolation.py -v
```
