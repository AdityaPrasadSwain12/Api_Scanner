# Enterprise API Security Scanner

A production-oriented API security assessment module for **authorized targets only**. It accepts a base URL, OpenAPI 3.0/3.1 or Swagger 2.0 JSON/YAML, a specification URL, or a Postman Collection. It normalizes the inventory once, runs independent scanner engines, correlates their evidence, reports measurable coverage, and exposes a versioned FastAPI API plus a compact dashboard.

This scanner cannot prove that an API is secure or detect every vulnerability. A completed scan must be interpreted together with its coverage, skipped checks, confidence, and evidence.

## What is implemented

- Explicit authorization confirmation, global/per-scan host allowlists, DNS/IP SSRF checks, redirect validation, response/spec size caps, rate/concurrency/request/duration limits, redaction, encrypted credentials, API-key authentication, and audit logs.
- OpenAPI 3.0/3.1, Swagger 2.0, Postman 2.x, remote specification ingestion, common-doc discovery, user-seeded controlled discovery, and limited response-link discovery.
- Canonical endpoint and finding models used by static analysis, the custom API engine, ZAP, Nuclei, Wfuzz, and WuppieFuzz.
- Custom checks for missing authentication, BOLA/IDOR, broken function-level authorization, SQL and NoSQL injection, path traversal/local-file read, reflected XSS, open redirect, command injection canaries, SSRF callbacks, excessive data exposure, CORS, HTTP transport, and security headers. Request mutation covers documented path, query, header, cookie, JSON, and form inputs. BOLA requires identity-aware object evidence and response comparison—not merely HTTP 200.
- Independent engine failures and skip reasons, `PARTIAL` completion, normalized endpoint correlation, source preservation, confidence promotion with corroboration, documented risk scoring, and an endpoint-by-vulnerability coverage matrix. Coverage separates offline contract checks, endpoint reachability, and applicable runtime checks. If no documented endpoint returns an HTTP response, the scan fails before findings or authoritative reports are generated.
- PostgreSQL migrations, Celery/Valkey worker, structured logs, correlation IDs, health/readiness/Prometheus endpoints, normalized pentest JSON, exhaustive technical JSON/HTML, enterprise PDF reports, and a dashboard.
- A deliberately vulnerable local API and deterministic unit/API/parser/auth/authorization/correlation/report tests.

The architecture and tradeoffs are detailed in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); deployment hardening is in [SECURITY.md](SECURITY.md), and the parent-platform contract is in [docs/PLATFORM_INTEGRATION.md](docs/PLATFORM_INTEGRATION.md).

## Quick start (Docker)

PowerShell:

```powershell
.\scripts\init-env.ps1
docker compose --profile test-target build
docker compose --profile test-target up -d
docker compose ps
```

Linux/macOS:

```sh
chmod +x scripts/init-env.sh
./scripts/init-env.sh
docker compose --profile test-target build
docker compose --profile test-target up -d
docker compose ps
```

Open `http://localhost:8000`. The local development dashboard opens directly and does not ask for a scanner key. Production refuses this keyless mode and must be protected by the parent platform gateway. Swagger UI is at `http://localhost:8000/docs`.

The dashboard workflow is intentionally small:

1. Enter the hosted target API URL.
2. Upload an OpenAPI 3.0/3.1 or Swagger 2.0 JSON/YAML file, provide its URL, or paste it.
3. Confirm that the target is authorized and select **Verify and start scan**. The worker then verifies real endpoint reachability from the scanner network.
4. Follow live progress, review vulnerability findings, and download the PDF or JSON report.

The scanner validates the document before queueing it and rejects document server URLs outside the authorized target scope.

## Report outputs

- **Pentest JSON** (`format=json`) is a compact handoff. Repeated instances of the same issue are grouped under `affected_locations`; internal correlation identifiers, duplicate evidence, repeated descriptions, and scanner-only timestamps are omitted.
- **Technical JSON** (`format=technical_json`) preserves every correlated finding, source engine, classification, timestamp, and all redacted evidence for engineering investigation and audit.
- **Enterprise PDF** (`format=pdf`) groups repeated endpoint observations into unique issues while retaining every affected location. It contains an executive summary, assessment-completeness state, separate runtime/offline coverage, severity distribution, detailed remediation and evidence excerpts, and an engine/limitations appendix.
- **Technical HTML** (`format=html`) remains available through the API for browser-based review.

All report formats redact configured credentials. Findings are automated leads and still require manual pentester validation.

Stop without deleting persistent data:

```sh
docker compose --profile test-target down
```

To deliberately remove local containers **and scanner data volumes**:

```sh
docker compose --profile test-target down --volumes
```

## Create scans

The commands below demonstrate the protected service-to-service API. In local `DASHBOARD_AUTH_MODE=disabled`, the `X-API-Key` header is optional; production integrations use gateway authentication or the configured internal service key.

URL-only scan (coverage will explicitly be incomplete unless a spec is discovered):

```sh
curl -X POST http://localhost:8000/api/v1/scans \
  -H "X-API-Key: $SCANNER_API_KEY" -H "Content-Type: application/json" \
  --data '{"target_url":"http://vulnerable-api:8001","authorized":true,"profile":"QUICK","policy":{"user_paths":["/public","/search"]}}'
```

Inline OpenAPI scan:

```sh
curl -X POST http://localhost:8000/api/v1/scans/from-file \
  -H "X-API-Key: $SCANNER_API_KEY" \
  -F "target_url=http://vulnerable-api:8001" -F "authorized=true" -F "profile=STANDARD" \
  -F "specification=@vulnerable_test_api/openapi.yaml;type=application/yaml"
```

Authenticated multi-identity authorization scan:

```sh
curl -X POST http://localhost:8000/api/v1/scans \
  -H "X-API-Key: $SCANNER_API_KEY" -H "Content-Type: application/json" \
  --data @examples/multi-identity-scan.json
```

Deep scan: change `profile` to `DEEP` in the same JSON and set bounded values under `policy`. `AGGRESSIVE` additionally requires an explicit `enabled_engines` list and never disables rate/scope/DoS safety limits.

Poll and retrieve results:

```sh
curl -H "X-API-Key: $SCANNER_API_KEY" http://localhost:8000/api/v1/scans/SCAN_ID/status
curl -H "X-API-Key: $SCANNER_API_KEY" http://localhost:8000/api/v1/scans/SCAN_ID/endpoints
curl -H "X-API-Key: $SCANNER_API_KEY" http://localhost:8000/api/v1/scans/SCAN_ID/findings
curl -H "X-API-Key: $SCANNER_API_KEY" -o report.pdf "http://localhost:8000/api/v1/scans/SCAN_ID/report?format=pdf"
curl -X POST -H "X-API-Key: $SCANNER_API_KEY" http://localhost:8000/api/v1/scans/SCAN_ID/cancel
```

## Local development and tests

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
$env:ENVIRONMENT="test"
$env:DATABASE_URL="sqlite:///./dev.sqlite3"
$env:SECRET_ENCRYPTION_KEY="NQ4M5lY8yl5wE9bG6vRCcQ5Rk4j1g5HVFFOS5iQlJ0k="
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\ruff check .
```

Docker configuration and container integration test:

```sh
pytest -m integration tests/test_docker.py
docker compose --profile test-target up -d --build
python scripts/e2e.py
```

Run only the vulnerable fixture outside Docker:

```sh
uvicorn vulnerable_test_api.main:app --host 127.0.0.1 --port 8001
```

Never expose the vulnerable fixture to an untrusted network.

## Parent-platform integration

- `vulnerable-api:8001` is only the Docker-network test fixture. Real users submit their owned/authorized HTTPS API URL through the parent platform.
- Use `/api/v1`; pass the parent project identifier as `external_project_id`, the engagement/ownership record as `authorization_reference`, and an actor identifier as `X-Actor`.
- Send/propagate `X-Correlation-ID`; it is returned in the response and written to audit/structured logs.
- Keep the scanner API private. The platform backend holds `SCANNER_API_KEY`; never send it to an end-user browser.
- Use `TARGET_SCOPE_MODE=platform_managed` for dynamic customer domains or retain the default `deployment_allowlist` for a fixed estate.
- Treat `202` as accepted and poll the returned `status_url`, or add a platform-owned webhook adapter around terminal state transitions.
- Keep scanner credentials in a cloud secret manager and inject them as environment variables. Credentials never appear in read APIs.
- Store report volumes in durable encrypted storage or replace `ReportGenerator` with an object-store adapter. Database and engine abstractions are intentionally independent from HTTP routes.
- Scale API replicas freely. Scale workers by giving each worker its own stateful ZAP sidecar; do not share a single ZAP daemon across concurrent workers.

See [docs/PLATFORM_INTEGRATION.md](docs/PLATFORM_INTEGRATION.md) for the complete user/gateway flow, [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for Kubernetes/cloud controls, and [docs/API.md](docs/API.md) for route details.
