# Kyptic API Security Platform

Kyptic is an automated API security platform designed to help development and security teams detect, analyze, and manage API security risks in real time.

---

## Milestone 1 Overview

Milestone 1 introduces deterministic API security analysis and endpoint discovery to the Kyptic platform:

* **OpenAPI Specification Ingestion**: Support for OpenAPI 2.0 (Swagger), OpenAPI 3.0.x, and OpenAPI 3.1.x in both **JSON** and **YAML** formats.
* **API Endpoint Inventory**: Automatic extraction of path, HTTP method, summary, operation ID, parameters, request body schemas, response schemas, and security requirements.
* **Deterministic API Security Analysis**: Static specification auditing for Broken Authentication indicators, Excessive Data Exposure, and Poor Input Validation.
* **Deterministic Risk Scoring**: Explainable, formula-based risk scoring (0-100) and severity classification (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
* **Normalized Finding Lifecycle Integration**: Fully integrated with existing Kyptic scan management, finding deduplication via SHA-256 fingerprints, triage status tracking (`OPEN`, `RESOLVED`, `FALSE_POSITIVE`), and report generation.
* **API Security Decision Dashboard**: Dedicated interactive frontend dashboard displaying KPI metrics, filterable endpoint inventory, risk badges, and endpoint detail inspection.

---

## Architecture

```
                                  ┌──────────────────────────┐
                                  │   OpenAPI Spec Ingest    │
                                  │   (JSON / YAML Upload)   │
                                  └────────────┬─────────────┘
                                               │
                                               ▼
                                  ┌──────────────────────────┐
                                  │  OpenApiSpecParser       │
                                  │  - Local $ref resolution │
                                  │  - Schema normalization  │
                                  └────────────┬─────────────┘
                                               │
                                               ▼
                                  ┌──────────────────────────┐
                                  │   ApiSecurityScanner     │
                                  │  - Auth gap checks       │
                                  │  - Sensitive data audit  │
                                  │  - Input constraint audit│
                                  └────────────┬─────────────┘
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       ▼                                               ▼
         ┌───────────────────────────┐                   ┌───────────────────────────┐
         │   ApiEndpoint Model       │                   │   Finding Model           │
         │   (Path, Auth, Risk)      │                   │   (SHA-256 Fingerprint)   │
         └─────────────┬─────────────┘                   └─────────────┬─────────────┘
                       │                                               │
                       └───────────────────────┬───────────────────────┘
                                               ▼
                                  ┌──────────────────────────┐
                                  │  API Security Dashboard  │
                                  │  (React + Vite UI Kit)   │
                                  └──────────────────────────┘
```

---

## Detection Strategy & Rules (Milestone 1)

### 1. Broken / Missing Authentication Indicators
* **Explicitly Unauthenticated Operations**: Flags operations with an empty security requirement array (`security: []`) when security schemes exist globally or on other endpoints.
* **Missing Security Declarations**: Flags operations lacking both operation-level and global security declarations. Path semantics matching sensitive routes (`/admin`, `/users`, `/accounts`, `/payments`, `/password`, `/reset`, `/tokens`, `/credentials`) elevate severity to `HIGH`.
* **Weak Authentication Schemes**: Flags usage of HTTP Basic Authentication (`type: basic`).

> **Note**: Milestone 1 findings explicitly distinguish *“Missing or potentially weak authentication control”* from runtime-confirmed breaches.

### 2. Excessive Data Exposure Indicators
* Inspects response schemas for all 2xx success status codes.
* Scans properties recursively for sensitive credential/secret fields (`password`, `secret`, `token`, `access_token`, `refresh_token`, `api_key`, `private_key`) -> `HIGH` severity.
* Scans for PII and financial identifiers (`ssn`, `social_security`, `credit_card`, `card_number`, `cvv`) -> `MEDIUM` severity.

### 3. Poor Input Validation Indicators
* Audits request parameters and request body schemas.
* Flags string parameters lacking explicit `maxLength`, `pattern`, or `enum` constraints -> `LOW` severity.
* Flags numeric parameters lacking `minimum`/`maximum` bounds.
* Flags generic unconstrained object request bodies.

---

## Deterministic Risk Scoring Formula

Each API endpoint is assigned an explainable risk score between **0 and 100**:

$$\text{Risk Score} = \min\Big(100,\, S_{\text{auth}} + S_{\text{data}} + S_{\text{input}}\Big)$$

* **Authentication Factors ($S_{\text{auth}}$)**:
  * Unauthenticated Sensitive Route: **+40 points**
  * Unauthenticated Standard Route: **+25 points**
  * Weak Basic Authentication: **+15 points**
* **Data Exposure Factors ($S_{\text{data}}$)**:
  * Contains Credential / Secret response fields: **+35 points**
  * Contains PII / Financial response fields: **+20 points**
* **Input Validation Factors ($S_{\text{input}}$)**:
  * Unconstrained parameters / request schemas: **+10 points**

### Risk Level Mapping
* **CRITICAL**: $\ge 75$
* **HIGH**: $50 - 74$
* **MEDIUM**: $25 - 49$
* **LOW**: $1 - 24$
* **INFO**: $0$

---

## Example Workflow

1. **Start Backend & Frontend**:
   ```bash
   # Terminal 1 - Backend
   cd backend
   uvicorn app.main:app --reload --port 8000

   # Terminal 2 - Frontend
   npm run dev
   ```

2. **Ingest OpenAPI Specification**:
   * Navigate to **API Security** in the sidebar navigation.
   * Click **Ingest OpenAPI Spec** and select a JSON or YAML file (e.g. `openapi.json`).
   * The system parses all paths, schemas, and security definitions into the `ApiEndpoint` inventory.

3. **Execute API Security Analysis**:
   * Click **Run API Analysis**.
   * Kyptic runs the `ApiSecurityScanner`, populates normalized `Finding` entries, calculates deterministic risk scores, and updates the dashboard.

4. **Review & Triage**:
   * Inspect the Endpoint Inventory table sorted by risk score.
   * Click any endpoint to open the **Endpoint Detail View** showing risk factors, exposed fields, and actionable remediations.

---

## API Endpoints Added

* `POST /api/projects/{project_id}/ingest/openapi` - Uploads and parses JSON/YAML spec.
* `POST /api/projects/{project_id}/api-security/analyze` - Triggers deterministic security auditing and finding creation.
* `GET /api/projects/{project_id}/api-security/endpoints` - Lists endpoint inventory with risk scores and security flags.
* `GET /api/projects/{project_id}/api-security/endpoints/{endpoint_id}` - Returns detailed endpoint security breakdown.
* `GET /api/projects/{project_id}/api-security/summary` - Returns aggregated metrics for KPI cards.

---

## Limitations & Milestone Scope

* **Milestone 1 Scope**: Static, specification-based analysis. Does not send dynamic active attack traffic (active rate-limit probing, payload fuzzing, or runtime traffic interception are reserved for Milestone 2).
* **Remote Ref Resolution**: Local `$ref` pointers (e.g. `#/components/schemas/User`) are safely resolved. External/remote `$ref` URLs (`http://`, `https://`) are explicitly disabled for SSRF protection.
