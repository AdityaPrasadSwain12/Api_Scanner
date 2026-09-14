# Architecture

## Boundary and flow

```text
Parent platform / dashboard
          │ HTTPS + API key + correlation ID
          ▼
FastAPI ───── PostgreSQL (inventory, state, evidence, audit)
   │
   └── Celery queue ── Valkey
              │
              ▼
        single-concurrency worker
          │       │       │       │
          ▼       ▼       ▼       ▼
       ZAP API  Nuclei  Wfuzz  WuppieFuzz
                 fixed-command sidecars
          │
          ▼
 authorized target only (scanner egress network)
```

The API process validates and persists a request, then returns `202`. The worker performs target validation again, ingests/discovers inventory, and runs the custom authenticated baseline before other engines. If no documented endpoint returns an HTTP response, the scan terminates as `FAILED` with an actionable network error and does not generate findings or authoritative reports. Otherwise it executes the remaining engines, correlates findings, computes coverage, and generates reports. An engine or applicable-check gap produces `PARTIAL`; complete reachability and runtime-check execution produces `COMPLETED`.

## Integration contracts

- `/api/v1` is the stable parent-platform boundary. Database models are private implementation details.
- `EndpointDefinition` is the version-independent API inventory. External document versions do not create separate testing paths.
- `ScannerEngine` defines `validate`, `prepare`, `execute`, `collect_results`, `normalize`, and `cleanup` hooks.
- `FindingDraft` is the common engine output. Raw engine material is preserved after recursive redaction.
- `external_project_id`, `X-Actor`, and `X-Correlation-ID` support composition into a larger platform without importing its tenant model.
- Target scope has two explicit modes: a fixed deployment allowlist and a platform-managed mode requiring trusted project and authorization references for each dynamic customer target.

## Engine isolation

ZAP exposes its supported daemon API. It is stateful, so the included worker has concurrency one and resets the ZAP session for each scan. In horizontally scaled deployments, pair each worker with one ZAP sidecar.

Nuclei, Wfuzz, and WuppieFuzz are CLI tools. Each has a private HTTP sidecar that accepts only a fixed typed request and invokes a fixed binary with an argument array (`shell=False`). The sidecars reject missing runner tokens, revalidate all target hosts, disable redirects where supported, impose OS resource limits, cap captured output, and accept no user template or payload paths. Nuclei templates are pinned and built into its image; the runner selects a fixed API-focused subset whose declared request counts fit the operational budget instead of sweeping generic web-technology directories. Because WuppieFuzz does not expose native request-rate or count flags, its generated specification points at a per-job loopback reverse proxy in the runner; that proxy applies the request budget, rate limit, response cap, and scope validation before forwarding each request.

The sidecar arrangement avoids mounting the Docker socket and keeps tool processes out of the API/worker image. Compose resource controls are a local baseline; production should also apply network policies, seccomp/AppArmor, read-only root filesystems, pod/container limits, and per-tenant queues.

## Scope and SSRF controls

The deployment allowlist is the maximum scope. Each scan has a subset stored on its target row. URL parsing rejects non-HTTP schemes and userinfo. DNS answers are evaluated with `ipaddress.is_global`; private testing must be explicitly enabled. Every application request and every redirect is revalidated, redirect host changes are rejected, response sizes are capped, and tool redirects are disabled when the tool supports it.

DNS validation immediately before dispatch narrows but cannot mathematically eliminate DNS-rebinding races in a generic HTTP stack. Production egress controls are therefore mandatory: resolve approved targets through controlled DNS and restrict the scanner subnet/pod to the approved destination IP/CIDR and required DNS service. Host allowlists alone are not a substitute for network policy.

## Profiles

| Profile | Default engines | Request default | Intended use |
|---|---|---:|---|
| QUICK | custom, Nuclei, ZAP passive | 250 | Rapid high-value signal |
| SAFE | custom, ZAP passive | 500 | Non-destructive checks |
| STANDARD | all applicable | 2,000 | Normal assessment |
| DEEP | all applicable | 10,000 (deployment-capped) | Broader fuzzing |
| AGGRESSIVE | explicitly selected | 20,000 (deployment-capped) | Explicit opt-in only |

User policy can tighten limits. It cannot exceed deployment caps. WuppieFuzz is skipped with a recorded reason when no specification is available.

## Correlation and risk

The stable fingerprint is SHA-256 over normalized endpoint, method, parameter, and category. External tool URLs are reduced to canonical API paths before correlation. Matching drafts become one finding; all evidence and source engines remain attached. Two independent sources promote confidence to high. Category aliases normalize common SQL/NoSQL injection, command injection, traversal, redirect, CORS, authentication bypass, SSRF, and XSS labels before correlation.

The custom engine generates valid baseline requests and bounded mutations from path, query, header, cookie, JSON, and form inputs in the normalized contract. High-signal analyzers use database-error deltas, boolean true/false response comparison, known local-file markers, unencoded HTML reflection, external `Location` control, NoSQL operator/control pairs, and non-destructive command-output canaries. A response difference by itself is not reported as a vulnerability.

Coverage is stored as an endpoint-by-security-check matrix with `TESTED`, `DETECTED`, `SKIPPED`, `ERROR`, and `NOT_APPLICABLE` states, tested parameters, techniques, request counts, and skip reasons. Applicability is calculated even when a baseline fails, so unrelated vulnerability classes do not inflate the denominator. Endpoint reachability, runtime check coverage, and offline contract/URL-scheme coverage are reported separately. The assessment state is `COMPLETE`, `PARTIAL`, or `INCOMPLETE`; an offline check can never make an unreachable target appear partially tested. SSRF uses a deployment-owned out-of-band HTTP callback collector. Compose configures the private local collector; cloud deployments expose only its opaque `/c/*` callback route and keep the authenticated `/events/*` polling route private. If the collector is not configured, SSRF is explicitly reported as skipped.

Risk is deliberately transparent and is not presented as CVSS:

```text
risk (0..10) = severity base × confidence multiplier

INFO 0.0, LOW 3.0, MEDIUM 5.5, HIGH 8.0, CRITICAL 10.0
LOW confidence 0.55, MEDIUM 0.80, HIGH 1.00
```

Engine-supplied CVSS metadata can be preserved as evidence, but this service does not label its own score as CVSS.

## Intentional simplicity

Celery is used instead of a custom scheduler. SQLAlchemy repositories avoid binding routes to PostgreSQL-specific queries. Reports use a local-path adapter suitable for Compose; an object-store implementation can replace it without changing scan APIs. OAuth/OIDC can be added as a new authentication strategy without changing the endpoint model. Webhooks, tenant RBAC, and SSO belong at the future parent-platform boundary and are not guessed here.
