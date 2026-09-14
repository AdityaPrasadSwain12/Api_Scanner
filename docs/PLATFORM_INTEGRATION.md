# Parent-platform integration

## Responsibility boundary

The scanner is an internal assessment service, not the platform's identity provider. The parent platform authenticates the end user, applies tenant/project RBAC, confirms target ownership or written authorization, and retains the resulting authorization record. Only the parent backend knows `SCANNER_API_KEY` and can reach the scanner API.

```text
End user
  -> parent UI and authenticated platform API
  -> project/RBAC and target-authorization check
  -> private scanner POST /api/v1/scans
  -> scan_id stored against the platform project
  -> status/findings/reports returned through tenant-checked platform routes
```

Do not put the scanner service key in frontend JavaScript. Do not expose the scanner service, database, queue, or engine sidecars directly to the internet.

## Deployment modes

`TARGET_SCOPE_MODE=deployment_allowlist` is the default. Every requested target and additional host must match `ALLOWED_TARGETS`. Use it for local testing, a dedicated customer deployment, or a small fixed estate.

`TARGET_SCOPE_MODE=platform_managed` supports dynamically registered customer APIs. In this mode every scan requires:

- `external_project_id`: the immutable project/tenant reference from the parent platform;
- `authorization_reference`: the platform record proving ownership, contract scope, or engagement approval;
- `authorized: true`: the explicit assertion retained with the scan;
- the target URL and any additional authorized specification/API hosts.

The target host becomes part of the immutable per-scan allowlist. HTTP(S)-only validation, DNS/IP checks, redirect controls, request limits, and engine isolation still apply. Keep `ALLOW_PRIVATE_TARGETS=false` unless a dedicated private worker network is deliberately configured.

Production environment example:

```text
ENVIRONMENT=production
TARGET_SCOPE_MODE=platform_managed
DASHBOARD_AUTH_MODE=gateway
ALLOW_PRIVATE_TARGETS=false
SCANNER_API_KEY=<from-cloud-secret-manager>
SECRET_ENCRYPTION_KEY=<stable-fernet-key-from-secret-manager>
ENGINE_RUNNER_TOKEN=<from-cloud-secret-manager>
```

`DASHBOARD_AUTH_MODE=gateway` hides standalone API-key controls. The gateway must authenticate the user and inject `X-API-Key` only on the private upstream request. The scanner continues to validate that credential; gateway mode is not an authentication bypass.

## User workflow

1. User selects a platform project.
2. User registers `https://api.customer.example` and proves ownership or uploads written engagement scope.
3. Platform creates an immutable authorization record such as `engagement-456`.
4. User selects scan profile, specification input, target credentials, identities, and bounded policy.
5. Platform backend resolves short-lived test credentials from its vault and submits the scan.
6. Platform stores `scan_id`, polls the status endpoint, and shows coverage/findings.
7. Platform proxies report downloads after tenant/project authorization.

Example server-to-server request:

```http
POST /api/v1/scans HTTP/1.1
X-API-Key: <scanner workload credential>
X-Actor: user-123
X-Correlation-ID: platform-request-456
Content-Type: application/json

{
  "project_name": "Customer payments API",
  "external_project_id": "platform-project-123",
  "authorization_reference": "engagement-456",
  "target_url": "https://api.customer.example",
  "authorized": true,
  "profile": "STANDARD",
  "specification_url": "https://api.customer.example/openapi.json",
  "authentication": {
    "type": "BEARER",
    "token": "short-lived-test-token"
  },
  "policy": {
    "rate_limit": 5,
    "concurrency": 3,
    "max_requests": 1000,
    "max_duration": 900
  }
}
```

The scanner returns `202` and a `scan_id`. Poll `/api/v1/scans/{scan_id}/status`; obtain inventory, findings, coverage, and reports from the other versioned routes. Authentication inputs are encrypted in the scanner database and are never returned by read APIs.

## Gateway contract

The gateway or parent backend must:

- authenticate the human user and check project membership on every request;
- prevent users from supplying or overriding `X-API-Key`, `X-Actor`, and trusted project fields;
- inject the scanner service key and canonical actor/correlation identifiers;
- verify that `external_project_id` and `authorization_reference` belong to the current tenant;
- filter scan history and scan IDs through the platform's tenant model;
- rate-limit scan creation separately from target request-rate limits;
- use TLS and keep scanner endpoints on private networking;
- use short-lived target credentials and rotate/revoke them after the assessment.

For stronger workload authentication, a JWT/OIDC or mTLS dependency can replace `require_api_key` without changing scan schemas, storage, workers, or engine contracts.
