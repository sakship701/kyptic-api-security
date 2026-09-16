# Kyptic AI Security Copilot — Architecture & Operational Documentation

## Overview

Kyptic AI Security Copilot provides evidence-grounded AI security explanations, remediation guidance, and patch suggestions.

It operates strictly as an **intelligence and explanation layer**. Scanner evidence, findings, confidence scores (`confidence_score`), and verification statuses (`verification_status`) remain **100% authoritative and immutable**.

---

## Architecture

```
                  ┌─────────────────────────────────────┐
                  │       React Frontend Copilot UI     │
                  └──────────────────┬──────────────────┘
                                     │ POST /api/copilot/chat
                                     ▼
                  ┌─────────────────────────────────────┐
                  │        FastAPI Copilot Router       │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │           Copilot Service           │
                  └──────┬───────────────────────┬──────┘
                         │                       │
                         ▼                       ▼
          ┌────────────────────────────┐  ┌─────────────┐
          │  Finding Context Builder   │  │SecurityGuard│
          │ (Redacts & Builds Context) │  │  (Sanitize) │
          └──────────────┬─────────────┘  └──────┬──────┘
                         └───────────┬───────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │    BaseLLMProvider Interface  │
                     └───────────────┬───────────────┘
                                     │
           ┌─────────────────────────┼─────────────────────────┐
           │ (Active)                │ (Active)                │ (Fallback)
           ▼                         ▼                         ▼
┌────────────────────┐   ┌───────────────────────┐   ┌─────────────────────┐
│  Ollama Provider   │   │  OpenAI-Compatible    │   │  Fallback Engine    │
│(qwen2.5-coder:1.5b)│   │  Provider (Local/Cloud)│   │ (Zero LLM Required) │
└────────────────────┘   └───────────────────────┘   └─────────────────────┘
```

---

## Provider Configuration

Copilot is configured via standard environment variables:

| Parameter | Default Value | Description |
| :--- | :--- | :--- |
| `COPILOT_PROVIDER` | `ollama` | Selected LLM provider (`ollama` or `openai`). |
| `COPILOT_OLLAMA_URL` | `http://localhost:11434` | Base URL for Ollama local server. |
| `COPILOT_OLLAMA_MODEL` | `qwen2.5-coder:1.5b` | Model name loaded in Ollama. |
| `COPILOT_OPENAI_URL` | `https://api.openai.com/v1` | Base URL for OpenAI-compatible endpoint. |
| `COPILOT_OPENAI_API_KEY` | `""` | Optional API key for OpenAI-compatible provider. |
| `COPILOT_OPENAI_MODEL` | `gpt-3.5-turbo` | Model name for OpenAI provider. |
| `COPILOT_TIMEOUT_SECONDS` | `8.0` | Maximum request timeout before activating fallback. |
| `COPILOT_MAX_CONTEXT_CHARS` | `4000` | Context character limit sent to provider. |
| `COPILOT_ENABLE_STREAMING` | `true` | Enables Server-Sent Events (SSE) streaming mode. |

---

## Laptop-Friendly Local Setup (Ollama)

To run local LLM intelligence on standard laptop hardware (no discrete GPU required):

1. **Install Ollama**:
   - macOS / Linux: `curl -fsSL https://ollama.com/install.sh | sh`
   - Windows: Download installer from [ollama.com](https://ollama.com)

2. **Pull Lightweight Model**:
   ```bash
   ollama pull qwen2.5-coder:1.5b
   ```
   *(Alternative lightweight models: `llama3.2:1b`, `llama3.2:3b`)*

3. **Verify Connectivity**:
   ```bash
   curl http://localhost:11434/api/tags
   ```

---

## Deterministic Fallback Engine

If Ollama or the configured OpenAI endpoint is unavailable, missing a model, or times out:

1. **No Application Failure**: Scans, Cross-Validation, Targeted Verification, and reports continue operating without interruption.
2. **Deterministic Security Guidance**: The `FallbackEngine` automatically generates static remediation guidance using Kyptic's internal CWE and OWASP knowledge base.
3. **Transparent Indicator**: Responses are flagged with `"is_fallback": true`.

---

## API Endpoints

### 1. `POST /api/copilot/chat`

Submits a prompt with optional finding context.

**Request**:
```json
{
  "finding_id": 42,
  "message": "Explain how to remediate this SQL injection.",
  "stream": false
}
```

**Response (`stream=false`)**:
```json
{
  "message": "To remediate this SQL injection, use parameterized queries...",
  "code_block": {
    "file": "controllers/auth.py",
    "code": "cursor.execute('SELECT * FROM users WHERE user = ?', (username,))",
    "lang": "python"
  },
  "is_fallback": false,
  "provider": "ollama",
  "model": "qwen2.5-coder:1.5b",
  "finding_id": 42
}
```

**Streaming Mode (`stream=true`)**:
Returns `text/event-stream` with chunk events:
```
event: token
data: {"delta": "To "}

event: token
data: {"delta": "remediate "}

event: done
data: {"status": "completed"}
```

---

### 2. `GET /api/copilot/status`

Returns provider connectivity and system health.

**Response**:
```json
{
  "configured_provider": "ollama",
  "configured_model": "qwen2.5-coder:1.5b",
  "provider_available": true,
  "fallback_available": true,
  "latency_ms": 28.5
}
```

---

## Security Controls

1. **Secret Redaction**:
   `SecurityGuard.redact_secrets()` strips AWS credentials, JWTs, bearer tokens, API keys, passwords, private keys, and database connection strings before prompt construction.
2. **Prompt Injection Containment**:
   All untrusted content (source code, evidence, user queries) is enclosed inside explicit XML tags (`<source_code_context>`, `<scanner_evidence>`). Tag-closing breakout sequences are escaped to prevent prompt injection hijacking.
3. **Data Minimization**:
   Only relevant finding context is sent to the provider. Unnecessary database records or full-project codebases are never dumped into prompts.

---

## Future RAG Integration (Phase 9)

Phase 7 defines the extensible interface `ContextBuilder.build_finding_context()`. In Phase 9, RAG retrieval (e.g. ChromaDB / Qdrant) can inject retrieved organization knowledge into the `<retrieved_knowledge>` XML block prior to LLM generation:

```
Finding Context + Retrieved Org Knowledge  ──► Context Builder ──► LLM Provider
```
