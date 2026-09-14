import asyncio
import json
import secrets
import time
from urllib.parse import quote, urljoin

import httpx

from app.analysis.authorization import authorization_confidence
from app.core.logging import redact, redact_known
from app.domain import EngineResult, EvidenceDraft, FindingDraft, ScanContext
from app.engines.base import ScannerEngine
from app.security.auth import apply_auth
from app.security.scope import ScopedHttpClient, ScopeGuard, safe_evidence_response
from app.security_tests.input_validation import (
    COMMAND_HINT,
    PATH_HINT,
    URL_HINT,
    MutationPoint,
    PreparedRequest,
    build_prepared_request,
    command_execution_evidence,
    eligible_points,
    nosql_injection_evidence,
    open_redirect_evidence,
    path_traversal_evidence,
    point_matches,
    reflected_xss_evidence,
    sql_boolean_evidence,
    sql_error_evidence,
)


def _sample_value(parameter: dict, resource_id: str | None = None) -> str:
    if resource_id and parameter.get("location") == "path":
        return resource_id
    if parameter.get("example") is not None:
        return str(parameter["example"])
    schema = parameter.get("schema") or {}
    if "example" in schema:
        return str(schema["example"])
    if "default" in schema:
        return str(schema["default"])
    if schema.get("type") == "integer":
        return str(schema.get("minimum", 1))
    return "test"


def endpoint_url(endpoint: dict, resource_id: str | None = None) -> str:
    path = endpoint["path"]
    for parameter in endpoint.get("parameters", []):
        if parameter.get("location") == "path":
            value = _sample_value(parameter, resource_id)
            path = path.replace("{" + parameter["name"] + "}", quote(value, safe=""))
    return urljoin(endpoint["base_url"].rstrip("/") + "/", path.lstrip("/"))


class RequestBudget:
    def __init__(self, maximum: int, rate: float):
        self.maximum = maximum
        self.rate = rate
        self.count = 0
        self.last_request = 0.0
        self.lock = asyncio.Lock()

    async def take(self) -> None:
        async with self.lock:
            if self.count >= self.maximum:
                raise RuntimeError("scan request budget exhausted")
            delay = max(0.0, (1 / self.rate) - (time.monotonic() - self.last_request))
            if delay:
                await asyncio.sleep(delay)
            self.count += 1
            self.last_request = time.monotonic()


class CustomApiEngine(ScannerEngine):
    name = "custom"

    def __init__(
        self,
        *,
        allow_private: bool,
        max_response_size: int,
        oast_callback_base_url: str | None = None,
        oast_poll_base_url: str | None = None,
        oast_api_key: str = "",
    ):
        self.allow_private = allow_private
        self.max_response_size = max_response_size
        self.oast_callback_base_url = oast_callback_base_url
        self.oast_poll_base_url = oast_poll_base_url
        self.oast_api_key = oast_api_key

    async def validate(self, context: ScanContext) -> tuple[bool, str | None]:
        return (bool(context.endpoints), None if context.endpoints else "no endpoints available")

    async def execute(self, context: ScanContext) -> EngineResult:
        started = time.monotonic()
        self._known_secrets = context.auth
        guard = ScopeGuard(context.allowed_hosts, allow_private=self.allow_private)
        client = ScopedHttpClient(
            guard,
            timeout=context.limits.request_timeout,
            max_response_size=self.max_response_size,
        )
        budget = RequestBudget(context.limits.max_requests, context.limits.rate_limit)
        findings: list[FindingDraft] = []
        semaphore = asyncio.Semaphore(context.limits.concurrency)

        async def bounded(endpoint: dict) -> tuple[list[FindingDraft], list[dict]]:
            async with semaphore:
                return await self._test_endpoint(client, budget, context, endpoint)

        batches = await asyncio.gather(
            *(bounded(item.model_dump(by_alias=True)) for item in context.endpoints),
            return_exceptions=True,
        )
        errors: list[str] = []
        checks: list[dict] = []
        for batch in batches:
            if isinstance(batch, Exception):
                errors.append(str(batch))
            else:
                endpoint_findings, endpoint_checks = batch
                findings.extend(endpoint_findings)
                checks.extend(endpoint_checks)
        auth_findings, auth_checks = await self._authorization_tests(
            client, budget, context
        )
        findings.extend(auth_findings)
        checks.extend(auth_checks)
        baseline_checks = [value for value in checks if value.get("check") == "baseline"]
        baseline_successes = sum(value.get("status") == "TESTED" for value in baseline_checks)
        target_unreachable = bool(baseline_checks) and baseline_successes == 0
        status = (
            "FAILED"
            if target_unreachable or (errors and not findings)
            else "COMPLETED"
        )
        baseline_reasons = list(
            dict.fromkeys(
                str(value.get("reason"))
                for value in baseline_checks
                if value.get("reason")
            )
        )
        reason = None
        if target_unreachable:
            reason = "target endpoint baselines failed: " + "; ".join(baseline_reasons[:3])
        elif errors and not findings:
            reason = "; ".join(errors[:3])
        return EngineResult(
            engine=self.name,
            status=status,
            findings=findings,
            request_count=budget.count,
            duration_seconds=time.monotonic() - started,
            raw={"endpoint_errors": errors, "checks": checks},
            reason=reason,
        )

    async def _send(
        self,
        client: ScopedHttpClient,
        budget: RequestBudget,
        method: str,
        url: str,
        auth: dict | None,
        **kwargs: object,
    ) -> httpx.Response:
        await budget.take()
        applied = apply_auth(url, auth)
        headers = {**applied.headers, **dict(kwargs.pop("headers", {}))}
        return await client.request(method, applied.url, headers=headers, **kwargs)

    async def _send_prepared(
        self,
        client: ScopedHttpClient,
        budget: RequestBudget,
        method: str,
        prepared: PreparedRequest,
        auth: dict | None,
    ) -> httpx.Response:
        return await self._send(
            client,
            budget,
            method,
            prepared.url,
            auth,
            follow_redirects=False,
            **prepared.kwargs(),
        )

    async def _test_endpoint(
        self,
        client: ScopedHttpClient,
        budget: RequestBudget,
        context: ScanContext,
        endpoint: dict,
    ) -> tuple[list[FindingDraft], list[dict]]:
        findings: list[FindingDraft] = []
        checks: list[dict] = []
        prepared = build_prepared_request(endpoint)
        url = prepared.url
        method = endpoint["method"]
        insecure_transport = url.lower().startswith("http://")
        if insecure_transport:
            findings.append(
                self._finding(
                    "Cleartext HTTP API endpoint",
                    "insecure-transport",
                    "HIGH",
                    "HIGH",
                    endpoint,
                    "Credentials and API data can be observed or modified in transit.",
                    "Require HTTPS and redirect HTTP only at a trusted edge.",
                    cwe="CWE-319",
                )
            )
        checks.append(
            self._check(
                endpoint,
                "insecure-transport",
                "DETECTED" if insecure_transport else "TESTED",
                techniques=["URL scheme inspection"],
            )
        )
        baseline: httpx.Response | None = None
        try:
            baseline = await self._send_prepared(
                client, budget, method, prepared, context.auth
            )
            checks.append(self._check(endpoint, "baseline", "TESTED", requests=1))
        except (httpx.HTTPError, ValueError, RuntimeError) as exc:
            failure_reason = self._request_failure("baseline request failed", exc)
            checks.append(
                self._check(
                    endpoint,
                    "baseline",
                    "ERROR",
                    reason=failure_reason,
                )
            )
            retrieval_operation = method in {"GET", "HEAD", "OPTIONS"}
            passive_applicability = {
                "security-headers": retrieval_operation,
                "excessive-data-exposure": retrieval_operation,
                "cors-misconfiguration": retrieval_operation,
                "missing-authentication": bool(endpoint.get("auth_required")),
            }
            for name in self._passive_check_names():
                applicable = passive_applicability[name]
                checks.append(
                    self._check(
                        endpoint,
                        name,
                        "SKIPPED" if applicable else "NOT_APPLICABLE",
                        reason=(
                            failure_reason
                            if applicable
                            else self._passive_not_applicable_reason(name)
                        ),
                    )
                )
            candidates = self._active_candidates(endpoint)
            for name in self._active_check_names():
                points = candidates[name]
                checks.append(
                    self._check(
                        endpoint,
                        name,
                        "SKIPPED" if points else "NOT_APPLICABLE",
                        points=points,
                        reason=(
                            failure_reason
                            if points
                            else self._active_not_applicable_reason(name)
                        ),
                        techniques=self._active_techniques(name),
                    )
                )
            return findings, checks
        if method in {"GET", "HEAD", "OPTIONS"}:
            missing = [
                header
                for header in ("x-content-type-options", "content-security-policy")
                if header not in baseline.headers
            ]
            if missing:
                findings.append(
                    self._finding(
                        "Missing HTTP security headers",
                        "security-headers",
                        "LOW",
                        "HIGH",
                        endpoint,
                        "Missing defense-in-depth headers can increase the effect of browser-facing flaws.",
                        "Set appropriate response security headers at the API gateway or application.",
                        detail={"missing": missing},
                    )
                )
            checks.append(
                self._check(
                    endpoint,
                    "security-headers",
                    "DETECTED" if missing else "TESTED",
                    techniques=["response-header inspection"],
                )
            )
            try:
                body = baseline.json()
            except (json.JSONDecodeError, ValueError):
                body = None
            sensitive_names = {"password", "passwd", "secret", "ssn", "access_token", "api_key"}

            def sensitive_paths(value: object, prefix: str = "") -> list[str]:
                if isinstance(value, dict):
                    paths = []
                    for key, child in value.items():
                        current = f"{prefix}.{key}".strip(".")
                        if str(key).lower() in sensitive_names:
                            paths.append(current)
                        paths.extend(sensitive_paths(child, current))
                    return paths
                if isinstance(value, list):
                    return [
                        path
                        for index, child in enumerate(value[:20])
                        for path in sensitive_paths(child, f"{prefix}[{index}]")
                    ]
                return []

            exposed = sensitive_paths(body)
            if exposed:
                findings.append(
                    self._finding(
                        "Potential excessive data exposure",
                        "excessive-data-exposure",
                        "MEDIUM",
                        "MEDIUM",
                        endpoint,
                        "Sensitive fields in a general API response may disclose personal or credential data.",
                        "Return an allowlisted response DTO containing only fields required by the caller.",
                        owasp="API3:2023 Broken Object Property Level Authorization",
                        cwe="CWE-200",
                        response=baseline,
                        detail={"sensitive_field_paths": exposed[:20]},
                    )
                )
            checks.append(
                self._check(
                    endpoint,
                    "excessive-data-exposure",
                    "DETECTED" if exposed else "TESTED",
                    techniques=["sensitive response-field inspection"],
                )
            )
            try:
                cors_prepared = build_prepared_request(endpoint)
                cors_prepared.headers["Origin"] = "https://untrusted.invalid"
                cors = await self._send_prepared(
                    client, budget, method, cors_prepared, context.auth
                )
                cors_vulnerable = (
                    cors.headers.get("access-control-allow-origin") == "*"
                    and cors.headers.get("access-control-allow-credentials", "").lower()
                    == "true"
                )
                if cors_vulnerable:
                    findings.append(
                        self._finding(
                            "Credentialed wildcard CORS policy",
                            "cors-misconfiguration",
                            "HIGH",
                            "HIGH",
                            endpoint,
                            "A browser may expose authenticated responses to an untrusted origin.",
                            "Use an explicit origin allowlist and never combine wildcard origin with credentials.",
                            cwe="CWE-942",
                            response=cors,
                        )
                    )
                checks.append(
                    self._check(
                        endpoint,
                        "cors-misconfiguration",
                        "DETECTED" if cors_vulnerable else "TESTED",
                        requests=1,
                        techniques=["untrusted Origin response comparison"],
                    )
                )
            except (httpx.HTTPError, ValueError, RuntimeError) as exc:
                checks.append(
                    self._check(
                        endpoint,
                        "cors-misconfiguration",
                        "ERROR",
                        reason=f"CORS probe failed: {type(exc).__name__}",
                    )
                )
        else:
            for name in (
                "security-headers",
                "excessive-data-exposure",
                "cors-misconfiguration",
            ):
                checks.append(
                    self._check(
                        endpoint,
                        name,
                        "NOT_APPLICABLE",
                        reason="check is limited to retrieval operations",
                    )
                )
        if endpoint.get("auth_required"):
            try:
                unauthenticated = await self._send_prepared(
                    client, budget, method, prepared, None
                )
                missing_auth = False
                if unauthenticated.status_code < 300:
                    similarity = 1.0
                    if baseline is not None:
                        from app.analysis.authorization import response_similarity

                        similarity = response_similarity(baseline.text, unauthenticated.text)
                    if similarity >= 0.7:
                        missing_auth = True
                        findings.append(
                            self._finding(
                                "Operation accessible without declared authentication",
                                "missing-authentication",
                                "HIGH",
                                "HIGH" if similarity > 0.9 else "MEDIUM",
                                endpoint,
                                "Unauthenticated callers may access functionality documented as protected.",
                                "Enforce authentication server-side for this operation.",
                                cwe="CWE-306",
                                owasp="API2:2023 Broken Authentication",
                                response=unauthenticated,
                                detail={"authenticated_similarity": round(similarity, 3)},
                            )
                        )
                checks.append(
                    self._check(
                        endpoint,
                        "missing-authentication",
                        "DETECTED" if missing_auth else "TESTED",
                        requests=1,
                        techniques=["authenticated/unauthenticated response comparison"],
                    )
                )
            except (httpx.HTTPError, ValueError, RuntimeError) as exc:
                checks.append(
                    self._check(
                        endpoint,
                        "missing-authentication",
                        "ERROR",
                        reason=f"unauthenticated probe failed: {type(exc).__name__}",
                    )
                )
        else:
            checks.append(
                self._check(
                    endpoint,
                    "missing-authentication",
                    "NOT_APPLICABLE",
                    reason="operation is not documented as requiring authentication",
                )
            )
        try:
            active_findings, active_checks = await self._input_validation_tests(
                client, budget, context, endpoint, baseline
            )
            findings.extend(active_findings)
            checks.extend(active_checks)
        except (httpx.HTTPError, ValueError, RuntimeError) as exc:
            for name in self._active_check_names():
                checks.append(
                    self._check(
                        endpoint,
                        name,
                        "ERROR",
                        reason=f"active testing stopped: {type(exc).__name__}",
                    )
                )
        return findings, checks

    @staticmethod
    def _active_check_names() -> tuple[str, ...]:
        return (
            "sql-injection",
            "nosql-injection",
            "path-traversal",
            "reflected-xss",
            "open-redirect",
            "command-injection",
            "ssrf",
        )

    @staticmethod
    def _passive_check_names() -> tuple[str, ...]:
        return (
            "security-headers",
            "excessive-data-exposure",
            "cors-misconfiguration",
            "missing-authentication",
        )

    @staticmethod
    def _bola_applicable(endpoint: dict) -> bool:
        return (
            endpoint.get("method") == "GET"
            and bool(endpoint.get("auth_required"))
            and any(
                parameter.get("location") == "path"
                for parameter in endpoint.get("parameters", [])
            )
        )

    @staticmethod
    def _request_failure(prefix: str, exc: Exception) -> str:
        detail = " ".join(str(exc).split())[:240]
        suffix = f": {detail}" if detail else ""
        return f"{prefix}: {type(exc).__name__}{suffix}"

    @staticmethod
    def _passive_not_applicable_reason(name: str) -> str:
        if name == "missing-authentication":
            return "operation is not documented as requiring authentication"
        return "check is limited to retrieval operations"

    @staticmethod
    def _active_not_applicable_reason(name: str) -> str:
        return {
            "sql-injection": "no scalar input was documented",
            "nosql-injection": "no query or body scalar input was documented",
            "path-traversal": "no file or path-like input was documented",
            "reflected-xss": "no scalar input was documented",
            "open-redirect": "no redirect or URL-like input was documented",
            "command-injection": "no command-like input was documented",
            "ssrf": "no URL-like input was documented",
        }[name]

    @staticmethod
    def _active_techniques(name: str) -> list[str]:
        return {
            "sql-injection": ["database-error differential", "boolean true/false differential"],
            "nosql-injection": ["operator/control differential", "database-error differential"],
            "path-traversal": ["Unix/Windows local-file marker", "encoded traversal variants"],
            "reflected-xss": ["unencoded active HTML reflection"],
            "open-redirect": ["absolute/protocol-relative Location header control"],
            "command-injection": ["POSIX/Windows non-destructive output canary"],
            "ssrf": ["out-of-band HTTP callback"],
        }[name]

    @staticmethod
    def _active_candidates(endpoint: dict) -> dict[str, list[MutationPoint]]:
        scalar_points = [
            point
            for point in eligible_points(endpoint)
            if point.schema_type not in {"boolean", "object", "array"}
        ]
        return {
            "sql-injection": scalar_points,
            "nosql-injection": [
                point for point in scalar_points if point.location in {"query", "body"}
            ],
            "path-traversal": [
                point for point in scalar_points if point_matches(point, PATH_HINT, endpoint)
            ],
            "reflected-xss": scalar_points,
            "open-redirect": [
                point for point in scalar_points if point_matches(point, URL_HINT, endpoint)
            ],
            "command-injection": [
                point for point in scalar_points if point_matches(point, COMMAND_HINT, endpoint)
            ],
            "ssrf": [
                point for point in scalar_points if point_matches(point, URL_HINT, endpoint)
            ],
        }

    @staticmethod
    def _check(
        endpoint: dict,
        name: str,
        status: str,
        *,
        points: list[MutationPoint] | None = None,
        requests: int = 0,
        reason: str | None = None,
        techniques: list[str] | None = None,
    ) -> dict:
        return {
            "endpoint_id": endpoint.get("endpoint_id"),
            "endpoint": endpoint.get("path"),
            "method": endpoint.get("method"),
            "check": name,
            "status": status,
            "eligible_parameters": [point.label for point in (points or [])],
            "request_count": requests,
            "reason": reason,
            "techniques": techniques or [],
        }

    @staticmethod
    def _point_request(point: MutationPoint, prepared: PreparedRequest, payload: object) -> dict:
        return {
            "method": "MUTATED_OPERATION",
            "url": prepared.url,
            "parameter": point.name,
            "location": point.location,
            "payload": payload,
            "headers": "[REDACTED]",
        }

    async def _mutate(
        self,
        client: ScopedHttpClient,
        budget: RequestBudget,
        context: ScanContext,
        endpoint: dict,
        point: MutationPoint,
        payload: object,
    ) -> tuple[PreparedRequest, httpx.Response]:
        prepared = build_prepared_request(endpoint, {point.key: payload})
        response = await self._send_prepared(
            client, budget, endpoint["method"], prepared, context.auth
        )
        return prepared, response

    async def _oast_hit(self, token: str) -> bool | None:
        if not self.oast_poll_base_url or not self.oast_api_key:
            return None
        url = f"{self.oast_poll_base_url.rstrip('/')}/events/{token}"
        try:
            async with httpx.AsyncClient(timeout=3, follow_redirects=False) as client:
                for attempt in range(3):
                    response = await client.get(
                        url, headers={"X-OAST-Key": self.oast_api_key}
                    )
                    response.raise_for_status()
                    if bool(response.json().get("hit")):
                        return True
                    if attempt < 2:
                        await asyncio.sleep(0.2)
        except (httpx.HTTPError, ValueError):
            return None
        return False

    async def _register_oast(self, token: str) -> bool:
        if not self.oast_poll_base_url or not self.oast_api_key:
            return False
        url = f"{self.oast_poll_base_url.rstrip('/')}/events/{token}/register"
        try:
            async with httpx.AsyncClient(timeout=3, follow_redirects=False) as client:
                response = await client.post(
                    url, headers={"X-OAST-Key": self.oast_api_key}
                )
                response.raise_for_status()
                return bool(response.json().get("registered"))
        except (httpx.HTTPError, ValueError):
            return False

    @staticmethod
    def _limited_points(points: list[MutationPoint], profile: str) -> list[MutationPoint]:
        maximum = {"STANDARD": 10, "DEEP": 25, "AGGRESSIVE": 50}.get(profile, 0)
        return points[:maximum]

    async def _input_validation_tests(
        self,
        client: ScopedHttpClient,
        budget: RequestBudget,
        context: ScanContext,
        endpoint: dict,
        baseline: httpx.Response,
    ) -> tuple[list[FindingDraft], list[dict]]:
        findings: list[FindingDraft] = []
        checks: list[dict] = []
        candidates = self._active_candidates(endpoint)
        scalar_points = candidates["sql-injection"]
        points = self._limited_points(scalar_points, context.profile)
        active = context.profile in {"STANDARD", "DEEP", "AGGRESSIVE"}

        if not active:
            for check_name in self._active_check_names():
                eligible = candidates[check_name]
                checks.append(
                    self._check(
                        endpoint,
                        check_name,
                        "SKIPPED" if eligible else "NOT_APPLICABLE",
                        points=eligible,
                        reason=(
                            f"{context.profile} profile does not execute active input mutation"
                            if eligible
                            else self._active_not_applicable_reason(check_name)
                        ),
                        techniques=self._active_techniques(check_name),
                    )
                )
            return findings, checks

        sql_requests = 0
        sql_detected = False
        for point in points:
            evidence = None
            finding_response = baseline
            finding_request: dict = {}
            confidence = "HIGH"
            for error_payload in ("'", '"', "')"):
                prepared, mutated = await self._mutate(
                    client, budget, context, endpoint, point, error_payload
                )
                sql_requests += 1
                evidence = sql_error_evidence(baseline, mutated)
                finding_response = mutated
                finding_request = self._point_request(point, prepared, error_payload)
                if evidence:
                    break
            if evidence is None:
                if point.schema_type in {"integer", "number"}:
                    true_payload, false_payload = "1 OR 1=1", "1 AND 1=2"
                else:
                    # Keep the SQL comment syntactically useful without trailing
                    # whitespace, which is illegal in an HTTP header field value.
                    true_payload = "' OR '1'='1' -- -"
                    false_payload = "' AND '1'='2' -- -"
                true_prepared, true_response = await self._mutate(
                    client, budget, context, endpoint, point, true_payload
                )
                _, false_response = await self._mutate(
                    client, budget, context, endpoint, point, false_payload
                )
                sql_requests += 2
                evidence = sql_boolean_evidence(
                    true_response, false_response, true_payload, false_payload
                )
                finding_response = true_response
                finding_request = self._point_request(point, true_prepared, true_payload)
                confidence = "MEDIUM"
            if evidence:
                sql_detected = True
                findings.append(
                    self._finding(
                        "SQL injection",
                        "sql-injection",
                        "HIGH",
                        confidence,
                        endpoint,
                        "Untrusted API input can influence a database query, which may expose or modify stored data.",
                        "Use parameterized queries or prepared statements, constrain input types, and avoid returning database errors.",
                        parameter=point.name,
                        cwe="CWE-89",
                        owasp="API8:2023 Security Misconfiguration",
                        response=finding_response,
                        detail={**evidence, "input_location": point.location},
                        evidence_request=finding_request,
                    )
                )
        checks.append(
            self._check(
                endpoint,
                "sql-injection",
                "DETECTED" if sql_detected else ("TESTED" if points else "NOT_APPLICABLE"),
                points=points,
                requests=sql_requests,
                reason=None if points else "no scalar input was documented",
                techniques=["database-error differential", "boolean true/false differential"],
            )
        )

        nosql_requests = 0
        nosql_detected = False
        for point in points:
            if point.location not in {"query", "body"}:
                continue
            if point.location == "body":
                operator_payload: object = {"$ne": None}
                control_payload: object = {"$scanner_control": None}
                operator_prepared, operator_response = await self._mutate(
                    client, budget, context, endpoint, point, operator_payload
                )
                _, control_response = await self._mutate(
                    client, budget, context, endpoint, point, control_payload
                )
            else:
                operator_prepared = build_prepared_request(endpoint)
                operator_prepared.params = [
                    item for item in operator_prepared.params if item[0] != point.name
                ]
                operator_prepared.params.append((f"{point.name}[$ne]", "API_SCANNER_NOSQL"))
                control_prepared = build_prepared_request(endpoint)
                control_prepared.params = [
                    item for item in control_prepared.params if item[0] != point.name
                ]
                control_prepared.params.append(
                    (f"{point.name}[$scanner_control]", "API_SCANNER_NOSQL")
                )
                operator_response = await self._send_prepared(
                    client, budget, endpoint["method"], operator_prepared, context.auth
                )
                control_response = await self._send_prepared(
                    client, budget, endpoint["method"], control_prepared, context.auth
                )
            nosql_requests += 2
            evidence = nosql_injection_evidence(baseline, operator_response, control_response)
            if evidence:
                nosql_detected = True
                findings.append(
                    self._finding(
                        "NoSQL injection",
                        "nosql-injection",
                        "HIGH",
                        "MEDIUM",
                        endpoint,
                        "The API appears to interpret an attacker-controlled NoSQL operator.",
                        "Reject object operators in user input, enforce strict schemas, and build database filters from allowlisted fields.",
                        parameter=point.name,
                        cwe="CWE-943",
                        owasp="API8:2023 Security Misconfiguration",
                        response=operator_response,
                        detail={**evidence, "input_location": point.location},
                        evidence_request=self._point_request(
                            point, operator_prepared, "controlled $ne operator"
                        ),
                    )
                )
        nosql_points = [point for point in points if point.location in {"query", "body"}]
        checks.append(
            self._check(
                endpoint,
                "nosql-injection",
                "DETECTED"
                if nosql_detected
                else ("TESTED" if nosql_points else "NOT_APPLICABLE"),
                points=nosql_points,
                requests=nosql_requests,
                reason=None if nosql_points else "no query or body scalar input was documented",
                techniques=["operator/control differential", "database-error differential"],
            )
        )

        traversal_points = [
            point for point in points if point_matches(point, PATH_HINT, endpoint)
        ]
        traversal_requests = 0
        traversal_detected = False
        traversal_payloads = (
            "../../../../../../etc/passwd",
            "..\\..\\..\\..\\Windows\\win.ini",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        )
        if context.profile in {"DEEP", "AGGRESSIVE"}:
            traversal_payloads += (
                "..%252f..%252f..%252fetc%252fpasswd",
                "....//....//....//etc/passwd",
            )
        for point in traversal_points:
            for payload in traversal_payloads:
                prepared, response = await self._mutate(
                    client, budget, context, endpoint, point, payload
                )
                traversal_requests += 1
                evidence = path_traversal_evidence(baseline, response)
                if not evidence:
                    continue
                traversal_detected = True
                findings.append(
                    self._finding(
                        "Path traversal / local file read",
                        "path-traversal",
                        "HIGH",
                        "HIGH",
                        endpoint,
                        "An attacker may read files outside the intended application directory.",
                        "Resolve files against a fixed directory, use opaque identifiers, and reject paths that escape the canonical base directory.",
                        parameter=point.name,
                        cwe="CWE-22",
                        owasp="API10:2023 Unsafe Consumption of APIs",
                        response=response,
                        detail={**evidence, "input_location": point.location},
                        evidence_request=self._point_request(point, prepared, payload),
                    )
                )
                break
        checks.append(
            self._check(
                endpoint,
                "path-traversal",
                "DETECTED"
                if traversal_detected
                else ("TESTED" if traversal_points else "NOT_APPLICABLE"),
                points=traversal_points,
                requests=traversal_requests,
                reason=None if traversal_points else "no file or path-like input was documented",
                techniques=["Unix/Windows local-file marker", "encoded traversal variants"],
            )
        )

        xss_requests = 0
        xss_detected = False
        xss_payloads = (
            '"><svg onload=alert(`API_SCANNER_XSS`)> ',
            "</script><script>alert('API_SCANNER_XSS')</script>",
            "'><img src=x onerror=alert('API_SCANNER_XSS')>",
        )
        for point in points:
            for xss_payload in xss_payloads:
                prepared, response = await self._mutate(
                    client, budget, context, endpoint, point, xss_payload
                )
                xss_requests += 1
                evidence = reflected_xss_evidence(xss_payload, response)
                if evidence:
                    xss_detected = True
                    findings.append(
                        self._finding(
                            "Reflected cross-site scripting",
                            "xss",
                            "HIGH",
                            "HIGH",
                            endpoint,
                            "Untrusted API input is returned as active HTML and may execute in a browser context.",
                            "Contextually encode output, return JSON for APIs, validate input, and deploy a restrictive Content Security Policy.",
                            parameter=point.name,
                            cwe="CWE-79",
                            owasp="API8:2023 Security Misconfiguration",
                            response=response,
                            detail={**evidence, "input_location": point.location},
                            evidence_request=self._point_request(point, prepared, xss_payload),
                        )
                    )
                    break
        checks.append(
            self._check(
                endpoint,
                "reflected-xss",
                "DETECTED" if xss_detected else ("TESTED" if points else "NOT_APPLICABLE"),
                points=points,
                requests=xss_requests,
                reason=None if points else "no scalar input was documented",
                techniques=["unencoded active HTML reflection"],
            )
        )

        redirect_points = [point for point in points if point_matches(point, URL_HINT, endpoint)]
        redirect_requests = 0
        redirect_detected = False
        callback_urls = (
            "https://redirect-canary.invalid/api-scanner",
            "//redirect-canary.invalid/api-scanner",
        )
        for point in redirect_points:
            for callback_url in callback_urls:
                prepared, response = await self._mutate(
                    client, budget, context, endpoint, point, callback_url
                )
                redirect_requests += 1
                evidence = open_redirect_evidence(callback_url, response)
                if evidence:
                    redirect_detected = True
                    findings.append(
                        self._finding(
                            "Open redirect",
                            "open-redirect",
                            "MEDIUM",
                            "HIGH",
                            endpoint,
                            "An attacker can create trusted-looking links that redirect users to an external site.",
                            "Allowlist relative destinations or map fixed identifiers to approved destinations.",
                            parameter=point.name,
                            cwe="CWE-601",
                            response=response,
                            detail={**evidence, "input_location": point.location},
                            evidence_request=self._point_request(point, prepared, callback_url),
                        )
                    )
                    break
        checks.append(
            self._check(
                endpoint,
                "open-redirect",
                "DETECTED"
                if redirect_detected
                else ("TESTED" if redirect_points else "NOT_APPLICABLE"),
                points=redirect_points,
                requests=redirect_requests,
                reason=None if redirect_points else "no redirect or URL-like input was documented",
                techniques=["absolute/protocol-relative Location header control"],
            )
        )

        command_points = [
            point for point in points if point_matches(point, COMMAND_HINT, endpoint)
        ]
        command_requests = 0
        command_detected = False
        command_payloads = (
            (";printf API_SCANNER_CMD_7F3A", "API_SCANNER_CMD_7F3A"),
            ("& echo API_SCANNER_CMD_9C2D", "API_SCANNER_CMD_9C2D"),
        )
        for point in command_points:
            for payload, marker in command_payloads:
                prepared, response = await self._mutate(
                    client, budget, context, endpoint, point, payload
                )
                command_requests += 1
                evidence = command_execution_evidence(payload, marker, response)
                if not evidence:
                    continue
                command_detected = True
                findings.append(
                    self._finding(
                        "OS command injection",
                        "command-injection",
                        "CRITICAL",
                        "HIGH",
                        endpoint,
                        "Attacker-controlled input appears to execute as an operating-system command.",
                        "Do not invoke a shell with user input; use fixed argument arrays and strict allowlists.",
                        parameter=point.name,
                        cwe="CWE-78",
                        owasp="API8:2023 Security Misconfiguration",
                        response=response,
                        detail={**evidence, "input_location": point.location},
                        evidence_request=self._point_request(point, prepared, payload),
                    )
                )
                break
        checks.append(
            self._check(
                endpoint,
                "command-injection",
                "DETECTED"
                if command_detected
                else ("TESTED" if command_points else "NOT_APPLICABLE"),
                points=command_points,
                requests=command_requests,
                reason=None if command_points else "no command-like input was documented",
                techniques=["POSIX/Windows non-destructive output canary"],
            )
        )

        ssrf_points = [point for point in points if point_matches(point, URL_HINT, endpoint)]
        ssrf_requests = 0
        ssrf_detected = False
        collector_error = False
        if self.oast_callback_base_url and self.oast_poll_base_url and self.oast_api_key:
            for point in ssrf_points:
                token = secrets.token_urlsafe(24)
                callback_url = f"{self.oast_callback_base_url.rstrip('/')}/{token}"
                if not await self._register_oast(token):
                    collector_error = True
                    continue
                prepared, response = await self._mutate(
                    client, budget, context, endpoint, point, callback_url
                )
                ssrf_requests += 1
                hit = await self._oast_hit(token)
                if hit is None:
                    collector_error = True
                    continue
                if not hit:
                    continue
                ssrf_detected = True
                findings.append(
                    self._finding(
                        "Server-side request forgery",
                        "ssrf",
                        "HIGH",
                        "HIGH",
                        endpoint,
                        "The API server made an outbound request to a scanner-controlled callback URL.",
                        "Allowlist required outbound destinations, block private and metadata networks, and validate every redirect and resolved address.",
                        parameter=point.name,
                        cwe="CWE-918",
                        owasp="API7:2023 Server Side Request Forgery",
                        response=response,
                        detail={
                            "technique": "out-of-band HTTP callback",
                            "input_location": point.location,
                            "callback_observed": True,
                        },
                        evidence_request=self._point_request(point, prepared, callback_url),
                    )
                )
        if not ssrf_points:
            ssrf_status = "NOT_APPLICABLE"
            ssrf_reason = "no URL-like input was documented"
        elif not (self.oast_callback_base_url and self.oast_poll_base_url and self.oast_api_key):
            ssrf_status = "SKIPPED"
            ssrf_reason = "out-of-band callback service is not configured"
        elif collector_error:
            ssrf_status = "ERROR"
            ssrf_reason = "out-of-band callback collector could not be queried"
        else:
            ssrf_status = "DETECTED" if ssrf_detected else "TESTED"
            ssrf_reason = None
        checks.append(
            self._check(
                endpoint,
                "ssrf",
                ssrf_status,
                points=ssrf_points,
                requests=ssrf_requests,
                reason=ssrf_reason,
                techniques=["out-of-band HTTP callback"] if ssrf_requests else [],
            )
        )
        return findings, checks

    async def _authorization_tests(
        self, client: ScopedHttpClient, budget: RequestBudget, context: ScanContext
    ) -> tuple[list[FindingDraft], list[dict]]:
        findings: list[FindingDraft] = []
        checks: list[dict] = []
        identities = [item for item in context.identities if item.get("resource_ids")]
        for endpoint_model in context.endpoints:
            endpoint = endpoint_model.model_dump(by_alias=True)
            bola_candidate = self._bola_applicable(endpoint)
            if bola_candidate and len(identities) >= 2:
                owner, foreign = identities[0], identities[1]
                owner_id, foreign_id = owner["resource_ids"][0], foreign["resource_ids"][0]
                owner_url = endpoint_url(endpoint, owner_id)
                foreign_url = endpoint_url(endpoint, foreign_id)
                try:
                    owner_response = await self._send(
                        client, budget, "GET", owner_url, owner["auth"], follow_redirects=False
                    )
                    cross_response = await self._send(
                        client, budget, "GET", foreign_url, owner["auth"], follow_redirects=False
                    )
                    vulnerable, confidence, similarity = authorization_confidence(
                        owner_status=owner_response.status_code,
                        cross_status=cross_response.status_code,
                        owner_body=owner_response.text,
                        cross_body=cross_response.text,
                        foreign_identifier=foreign_id,
                    )
                    if vulnerable:
                        findings.append(
                            self._finding(
                                "Broken object-level authorization",
                                "bola",
                                "HIGH",
                                confidence,
                                endpoint,
                                "One identity retrieved a resource assigned to a different identity.",
                                "Authorize every object access against the authenticated subject and tenant.",
                                parameter=next(
                                    p["name"]
                                    for p in endpoint["parameters"]
                                    if p["location"] == "path"
                                ),
                                cwe="CWE-639",
                                owasp="API1:2023 Broken Object Level Authorization",
                                response=cross_response,
                                detail={
                                    "actor": owner["name"],
                                    "foreign_identity": foreign["name"],
                                    "foreign_resource_id": foreign_id,
                                    "response_similarity": round(similarity, 3),
                                },
                                finding_type="AUTHORIZATION",
                            )
                        )
                    checks.append(
                        self._check(
                            endpoint,
                            "bola",
                            "DETECTED" if vulnerable else "TESTED",
                            requests=2,
                            techniques=["owner/foreign object identity comparison"],
                        )
                    )
                except (httpx.HTTPError, ValueError, RuntimeError) as exc:
                    checks.append(
                        self._check(
                            endpoint,
                            "bola",
                            "ERROR",
                            reason=f"authorization comparison failed: {type(exc).__name__}",
                        )
                    )
            elif bola_candidate:
                checks.append(
                    self._check(
                        endpoint,
                        "bola",
                        "SKIPPED",
                        reason="two identities with distinct resource identifiers are required",
                    )
                )
            else:
                if not endpoint.get("auth_required"):
                    reason = "operation is not documented as requiring authorization"
                else:
                    reason = "a GET operation with an object path parameter is required"
                checks.append(
                    self._check(
                        endpoint,
                        "bola",
                        "NOT_APPLICABLE",
                        reason=reason,
                    )
                )

            bfla_candidate = (
                "admin" in [str(tag).lower() for tag in endpoint.get("tags", [])]
                or "/admin" in endpoint["path"].lower()
            )
            if bfla_candidate:
                admins = [item for item in context.identities if item.get("is_admin")]
                regulars = [item for item in context.identities if not item.get("is_admin")]
                if admins and regulars and endpoint["method"] in {"GET", "HEAD"}:
                    url = endpoint_url(endpoint)
                    try:
                        admin_response = await self._send(
                            client,
                            budget,
                            endpoint["method"],
                            url,
                            admins[0]["auth"],
                            follow_redirects=False,
                        )
                        regular_response = await self._send(
                            client,
                            budget,
                            endpoint["method"],
                            url,
                            regulars[0]["auth"],
                            follow_redirects=False,
                        )
                        from app.analysis.authorization import response_similarity

                        similarity = response_similarity(
                            admin_response.text, regular_response.text
                        )
                        vulnerable = (
                            admin_response.status_code < 300
                            and regular_response.status_code < 300
                            and similarity >= 0.8
                        )
                        if vulnerable:
                            findings.append(
                                self._finding(
                                    "Broken function-level authorization",
                                    "bfla",
                                    "HIGH",
                                    "HIGH" if similarity >= 0.95 else "MEDIUM",
                                    endpoint,
                                    "A non-administrator invoked an administrative operation with behavior matching an administrator.",
                                    "Enforce role or permission checks for every privileged function.",
                                    cwe="CWE-862",
                                    owasp="API5:2023 Broken Function Level Authorization",
                                    response=regular_response,
                                    detail={
                                        "actor": regulars[0]["name"],
                                        "admin_similarity": round(similarity, 3),
                                    },
                                    finding_type="AUTHORIZATION",
                                )
                            )
                        checks.append(
                            self._check(
                                endpoint,
                                "bfla",
                                "DETECTED" if vulnerable else "TESTED",
                                requests=2,
                                techniques=["administrator/regular-user behavior comparison"],
                            )
                        )
                    except (httpx.HTTPError, ValueError, RuntimeError) as exc:
                        checks.append(
                            self._check(
                                endpoint,
                                "bfla",
                                "ERROR",
                                reason=f"role comparison failed: {type(exc).__name__}",
                            )
                        )
                else:
                    checks.append(
                        self._check(
                            endpoint,
                            "bfla",
                            "SKIPPED",
                            reason="administrator and regular-user identities are required",
                        )
                    )
            else:
                checks.append(
                    self._check(
                        endpoint,
                        "bfla",
                        "NOT_APPLICABLE",
                        reason="operation is not identified as administrative",
                    )
                )
        return findings, checks

    def _finding(
        self,
        title: str,
        category: str,
        severity: str,
        confidence: str,
        endpoint: dict,
        impact: str,
        remediation: str,
        *,
        parameter: str | None = None,
        cwe: str | None = None,
        owasp: str | None = None,
        response: httpx.Response | None = None,
        detail: dict | None = None,
        finding_type: str = "RUNTIME",
        evidence_request: dict | None = None,
    ) -> FindingDraft:
        url = endpoint_url(endpoint)
        request_evidence = evidence_request or {
            "url": url,
            "headers": "[REDACTED]",
        }
        request_evidence = {**request_evidence, "method": endpoint["method"]}
        evidence = EvidenceDraft(
            engine=self.name,
            request=redact_known(request_evidence, self._known_secrets),
            response=(
                redact_known(safe_evidence_response(response), self._known_secrets)
                if response
                else None
            ),
            detail=json.dumps(redact(detail or {}), sort_keys=True),
        )
        return FindingDraft(
            finding_type=finding_type,
            title=title,
            description=f"{title} was observed during controlled runtime testing.",
            category=category,
            severity=severity,
            confidence=confidence,
            endpoint=endpoint["path"],
            method=endpoint["method"],
            parameter=parameter,
            owasp_api=owasp,
            cwe=cwe,
            source_engine=self.name,
            impact=impact,
            remediation=remediation,
            evidence=[evidence],
        )
