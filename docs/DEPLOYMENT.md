# Cloud deployment guide

The Compose topology is a development/reference deployment. For a production platform:

1. Build and sign immutable images in CI. Pin base images by digest after vulnerability scanning. Generate an image-level SBOM with Syft or the cloud registry scanner; the checked-in SBOM covers declared application/tool components, not transitive OS packages.
2. Run migrations as a one-shot job before the API/worker rollout. Use managed PostgreSQL with TLS, encrypted storage, PITR, least-privilege credentials, and connection pooling. Use managed Valkey/Redis-protocol service with TLS and authentication.
3. Put the API behind the parent platform gateway. End users must never receive the scanner service key. Set `DASHBOARD_AUTH_MODE=gateway`, use `TARGET_SCOPE_MODE=platform_managed` for dynamic verified customer domains, and propagate `external_project_id`, `authorization_reference`, actor, and correlation ID. Replace the bootstrap API key with gateway-issued workload identity or tenant-aware JWT validation when the parent identity contract is available.
4. Store `SECRET_ENCRYPTION_KEY`, runner tokens, ZAP key, database credentials, and API credentials in the cloud secret manager. Rotate by adding a versioned multi-key decrypt strategy before replacing the active encryption key.
5. Give scanner workers a dedicated subnet/security group or Kubernetes namespace. Default-deny egress, then allow approved target IP/CIDRs and controlled DNS only. Enforce the same scope in a gateway/proxy. Isolate tenants with dedicated queues/workers for high assurance.
6. Pair each worker replica with its own ZAP sidecar because ZAP sessions are stateful. Give that pair a small shared ephemeral volume so the worker can hand a redacted OpenAPI document to ZAP's supported import API; mount it read-only in ZAP. Nuclei/Wfuzz/WuppieFuzz runners can scale independently if requests are authenticated and network-private.
7. Publish the OAST collector callback path (`/c/*`) on a dedicated HTTPS hostname reachable by assessed APIs. Keep `/events/*` private to workers, protect it with `OAST_API_KEY`, retain only opaque callback tokens, and override `OAST_CALLBACK_BASE_URL` with the public address. Without a reachable callback service, SSRF checks are truthfully marked skipped.
8. Replace the local report volume with encrypted object storage, short-lived signed downloads, retention policies, malware/DLP controls, and tenant-scoped object keys.
9. Apply non-root UID, read-only root filesystem, dropped Linux capabilities, RuntimeDefault seccomp, no privilege escalation, memory/CPU/PID/ephemeral-storage limits, and automatic kill deadlines. Do not mount the container runtime socket.
10. Export structured logs and Prometheus metrics without request bodies. Alert on queue depth, terminal failures, timeouts, scope violations, runner authentication failures, and unexpected egress blocks.
11. Back up database/audit data according to policy, document retention and deletion, and run the e2e fixture only in an isolated CI environment.

Readiness intentionally fails if PostgreSQL or the queue is unavailable. Health only proves that the HTTP process is alive. Rolling deployment should gate traffic on readiness.
