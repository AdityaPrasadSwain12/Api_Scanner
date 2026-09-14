# API guide

Interactive OpenAPI documentation is served at `/docs`; the machine-readable schema is `/openapi.json`. In `api_key` and `gateway` modes, all `/api/v1` routes require the internal `X-API-Key`. `DASHBOARD_AUTH_MODE=disabled` removes this requirement only for local development and is rejected when `ENVIRONMENT=production`. `/health`, `/ready`, and the dashboard shell are public.

## Scan input

`POST /api/v1/scans` accepts JSON. Required fields are `target_url` and literal `authorized: true`. Optional inventory inputs are mutually exclusive: `specification` (JSON object or JSON/YAML string), `specification_url`, or `postman_collection`. Without one, controlled discovery runs. `POST /api/v1/scans/from-file` accepts a multipart OpenAPI/Swagger upload.

In `platform_managed` target-scope mode, `external_project_id` and `authorization_reference` are also required. The trusted parent backend supplies these values after its tenant authorization and target-ownership workflow. In the default `deployment_allowlist` mode, the target and `policy.allowed_hosts` must be a subset of `ALLOWED_TARGETS`.

Authentication supports `NONE`, `BEARER`, `API_KEY` (`header` or `query`), and `BASIC`. Multiple identities include `name`, `role`, `is_admin`, `resource_ids`, and an `auth` object. Secret fields are encrypted separately and never returned.

## Routes

| Method | Route | Purpose |
|---|---|---|
| POST | `/api/v1/scans` | Queue a JSON-configured scan |
| POST | `/api/v1/scans/from-file` | Queue a multipart specification scan |
| GET | `/api/v1/scans` | Paginated scan history |
| GET | `/api/v1/scans/{id}` | Scan summary |
| GET | `/api/v1/scans/{id}/status` | Lightweight polling response |
| GET | `/api/v1/scans/{id}/endpoints` | Paginated normalized inventory |
| GET | `/api/v1/scans/{id}/findings` | Paginated correlated findings |
| GET | `/api/v1/scans/{id}/findings/{finding_id}` | Finding and redacted evidence |
| GET | `/api/v1/scans/{id}/coverage` | Coverage dimensions and skips |
| GET | `/api/v1/scans/{id}/reports` | Available report formats/checksums |
| GET | `/api/v1/scans/{id}/report?format=json|technical_json|html|pdf` | Download pentest JSON, exhaustive technical JSON/HTML, or enterprise PDF |
| POST | `/api/v1/scans/{id}/cancel` | Request cancellation |
| POST | `/api/v1/scans/{id}/pause` | Pause at the next safe checkpoint |
| POST | `/api/v1/scans/{id}/resume` | Resume a paused job |
| GET | `/api/v1/audit-logs` | Paginated security audit log |

Lifecycle: `QUEUED → INITIALIZING → DISCOVERING → SCANNING → CORRELATING → REPORTING → COMPLETED`. `PARTIAL`, `FAILED`, `CANCELLED`, and `TIMEOUT` are terminal; `PAUSED` is non-terminal.

The custom baseline always runs before optional external engines. If none of the documented endpoints returns an HTTP response from the worker network, the scan terminates as `FAILED`; the error identifies the reachability failure and no findings or report artifacts are published. `PARTIAL` means useful testing completed but one or more endpoints, engines, identities, callbacks, or applicable runtime checks were unavailable. Coverage exposes separate `runtime_check_summary`, `offline_check_summary`, and `assessment` objects.

Validation failures use HTTP 422. Missing resources use 404. Invalid lifecycle actions and unavailable reports use 409. Queue unavailability uses 503. Error bodies carry a stable `code` and a non-secret message.
