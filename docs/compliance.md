# Kyptic Regulatory & Control Compliance Mapping — Technical Architecture

## Overview

Kyptic Regulatory Compliance evaluates application security findings against security controls defined by industry frameworks.

It produces an **evidence-based security assessment aid** detailing control coverage, affected controls, and remediation guidance references.

---

## Supported Regulatory Frameworks

1. **PCI DSS v4.0**: Payment Card Industry Data Security Standard (Requirements 6.2, 6.4.1, 8.2.1).
2. **SOC 2 Type II**: Trust Services Criteria (CC6.1 Access Control, CC6.6 Boundary Defense, CC7.1 Vulnerability Monitoring).
3. **ISO/IEC 27001:2022**: Information Security Management System Controls (A.8.8 Technical Vulnerabilities, A.8.24 Cryptography, A.8.28 Secure Coding).
4. **OWASP API Security Top 10 (2023)**: API-specific vulnerability categories (API1 BOLA, API2 Auth, API3 Property Authorization, etc.).
5. **OWASP Web Security Top 10 (2021)**: Web vulnerability categories (A01 Access Control, A02 Crypto, A03 Injection, etc.).
6. **CWE Taxonomy**: Common Weakness Enumeration mappings.

---

## Control Status Classification

- `AFFECTED`: Open vulnerability findings match the control's CWE/OWASP vectors.
- `NOT_AFFECTED`: Assessment was performed and no open findings violated this security control.
- `INSUFFICIENT_EVIDENCE`: Scans provided incomplete data or manual operational evidence is required.
- `NO_DIRECT_MAPPING`: Vulnerability vector does not map to this control.

---

## Assessment Framing & Statutory Disclaimer

Kyptic reports **security control coverage** based on empirical assessment evidence.

**Statutory Disclaimer**:
> *"Compliance coverage represents an automated evidence-based security assessment aid and does NOT constitute legal compliance certification."*

Absent findings do NOT automatically constitute legal compliance.

---

## API Endpoint

`GET /api/v1/projects/{project_id}/compliance?framework={framework_key}`

**Supported Framework Keys**:
- `PCI_DSS`
- `SOC_2`
- `ISO_27001`
- `OWASP_API_TOP_10`
- `OWASP_TOP_10`
- `CWE`
