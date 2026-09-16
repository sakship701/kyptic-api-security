# Kyptic Dynamic Security Risk Map — Technical Architecture

## Overview

The Kyptic Dynamic Security Risk Map visualizes application security architecture, data flow routes, vulnerability findings, and risk levels as a dynamic graph.

It consumes authoritative Kyptic data (`Project`, `ApiEndpoint`, `Finding`, `Scan`) and dynamically projects hierarchical layers (`PROJECT` -> `API` -> `ENDPOINT` -> `FINDING` -> `VULNERABILITY` / `FILE`).

---

## Graph Model Architecture

```
PROJECT (Layer 1)
   │
   └──► API SERVICE (Layer 2)
           │
           └──► ENDPOINT (Layer 3)
                   │
                   └──► FINDING (Layer 4)
                           ├──► VULNERABILITY (Layer 5: CWE / OWASP)
                           └──► SOURCE FILE (Layer 5: Source Code Asset)
```

---

## Data Model & Node Schema

Each node in the risk graph contains:
- `id`: Stable deterministic identifier (`proj-{id}`, `api-{id}`, `ep-{id}`, `finding-{id}`, `vuln-{cwe}`, `file-{path}`).
- `type`: `PROJECT`, `API`, `ENDPOINT`, `FINDING`, `VULNERABILITY`, `FILE`.
- `label`: Human-readable display label.
- `status`: `safe`, `warning`, `critical`, `info`.
- `score`: Node-level risk score computed from findings.
- `x`, `y`: Layer-based deterministic layout positions for reproducible UI rendering.
- `severity`, `confidence_score`, `confidence_level`, `verification_status`: Authoritative Cross-Validation attributes.

---

## Layout Algorithm

The Risk Map uses a layered hierarchical positioning algorithm:
- Layer 1 (`x=100`): Root Project Node.
- Layer 2 (`x=350`): API / Service Gateway Node.
- Layer 3 (`x=650`): Discovered API Endpoint Nodes.
- Layer 4 (`x=950`): Finding Nodes.
- Layer 5 (`x=1250`): Vulnerability Taxonomy & Source Code File Nodes.

---

## Risk Score Aggregation

Risk scoring reuses Kyptic's authoritative deduction model:
- Base Score: `100`
- Critical Finding: `-15` pts
- High Finding: `-8` pts
- Medium Finding: `-3` pts
- Low Finding: `-1` pt
- `Score = max(0, min(100, 100 - total_deduction))`

Phase 2 Cross-Validation `confidence_score` and `verification_status` are preserved **read-only**.

---

## API Endpoint

`GET /api/v1/projects/{project_id}/risk-map` (and `/api/projects/{project_id}/risk-map`)

**Query Parameters**:
- `severity`: Filter findings by severity (`critical`, `high`, `medium`, `low`).
- `verification_status`: Filter by status (`CONFIRMED`, `UNVERIFIED`).
- `vulnerability_type`: Filter by category or CWE.
- `min_risk_score`: Filter by minimum risk score threshold.
