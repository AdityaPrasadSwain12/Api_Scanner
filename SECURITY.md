# Scanner security policy and operating controls

Only operate this software against systems you own or are explicitly authorized to assess. Keep written scope, time window, allowed hosts/IP ranges, authentication roles, rate limits, and emergency contacts with the engagement record.

## Safe defaults and limitations

- Every scan requires `authorized: true`. Deployment and scan host allowlists, HTTP(S)-only URL validation, DNS/IP classification, redirect checks, maximum sizes, deadlines, request budgets, concurrency, and rate caps are enforced. WuppieFuzz traffic passes through a loopback proxy because the upstream CLI has no native request-rate or count option.
- Private/link-local targets are denied unless `ALLOW_PRIVATE_TARGETS=true`; enable it only in a controlled scanner network. Cloud metadata, localhost, and internal control planes must remain blocked with egress firewall rules.
- SAFE/QUICK omit active ZAP and broad fuzzing. No profile performs intentional denial of service. AGGRESSIVE still has hard deployment caps and requires explicit engines.
- Command-line runners use argument arrays, fixed binaries/templates/payloads, unprivileged users, read-only filesystems, and resource limits. No Docker socket or privileged container is used.
- Credentials use Fernet authenticated encryption at rest. Evidence, exceptions, logs, engine results, API responses, and reports pass through recursive redaction. Encryption is not a substitute for a secret manager, TLS, database encryption, or access control.
- The bootstrap API key is service-level authentication, not tenant RBAC. Put the module behind the parent platform's authenticated, authorized gateway in production. In `platform_managed` scope mode the backend must validate the project and authorization record before supplying their immutable references to the scanner.
- Pause/cancel takes effect at safe checkpoints. Some third-party engine calls cannot be interrupted instantly; hard worker/tool deadlines remain in force.

## Reporting vulnerabilities in this project

Do not open a public issue containing an exploitable scanner vulnerability or real customer data. Send a private report to the project security owner configured by the deploying organization. Include affected version, reproduction steps, impact, and suggested mitigation. Rotate potentially exposed credentials immediately.

## Pre-production checklist

- Replace every development secret and reject startup if a production value is absent.
- Set the narrowest `ALLOWED_TARGETS`; default-deny network egress separately.
- Terminate TLS at a trusted gateway and use TLS to PostgreSQL/Valkey.
- Validate backup, restore, cancellation, timeout, and partial-result behavior.
- Review Nuclei template changes before updating the pinned template tag.
- Run dependency, image, IaC, secret, and source scanners; preserve their artifacts.
- Obtain legal review for distribution obligations, especially GPL-2.0-only Wfuzz.
