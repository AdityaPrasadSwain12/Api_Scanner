import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.logging import redact, redact_known, redact_known_values
from app.domain import EngineResult, EvidenceDraft, FindingDraft, ScanContext
from app.engines.base import ScannerEngine

SEVERITIES = {
    "info": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}


def _contains_external_reference(value: Any) -> bool:
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str) and not reference.startswith("#/"):
            return True
        return any(_contains_external_reference(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_external_reference(child) for child in value)
    return False


def _normalize_category(category: str, title: str) -> str:
    value = f"{category} {title}".lower()
    mappings = {
        "sql-injection": ("sql injection", "sqli", "sql-injection"),
        "nosql-injection": ("nosql injection", "nosql-injection"),
        "command-injection": ("command injection", "os command"),
        "path-traversal": ("path traversal", "directory traversal"),
        "cors-misconfiguration": ("cors", "cross-origin"),
        "missing-authentication": ("missing authentication", "authentication bypass"),
        "ssrf": ("server-side request forgery", "ssrf"),
        "xss": ("cross site scripting", "cross-site scripting", "xss"),
        "open-redirect": ("open redirect", "off-site redirect", "external redirect"),
    }
    for normalized, markers in mappings.items():
        if any(marker in value for marker in markers):
            return normalized
    return category.lower().replace("_", "-").replace(" ", "-")


def _normalize_endpoint(endpoint: str | None) -> str | None:
    if not endpoint:
        return endpoint
    parsed = urlsplit(endpoint)
    path = parsed.path if parsed.scheme and parsed.netloc else endpoint.split("?", 1)[0]
    proxy_match = re.search(r"/_wuppie_proxy/[^/]+(?P<path>/.*)$", path)
    return proxy_match.group("path") if proxy_match else path


def _generic_finding(
    *,
    engine: str,
    title: str,
    category: str,
    severity: str,
    endpoint: str | None,
    method: str | None,
    parameter: str | None = None,
    description: str = "A scanner engine reported a potential security weakness.",
    confidence: str = "MEDIUM",
    cwe: str | None = None,
    reference: list[str] | None = None,
    raw: dict[str, Any] | None = None,
) -> FindingDraft:
    safe_raw = redact(raw or {})
    return FindingDraft(
        finding_type="RUNTIME",
        title=title[:300],
        description=description,
        category=_normalize_category(category, title),
        severity=SEVERITIES.get(
            severity.lower(),
            severity.upper() if severity.upper() in SEVERITIES.values() else "MEDIUM",
        ),
        confidence=confidence,
        endpoint=_normalize_endpoint(endpoint),
        method=method,
        parameter=parameter,
        cwe=cwe,
        source_engine=engine,
        impact="Successful exploitation may affect API confidentiality, integrity, or availability.",
        remediation="Validate the engine evidence, address the underlying condition, and add a regression test.",
        references=reference or [],
        evidence=[EvidenceDraft(engine=engine, detail=json.dumps(safe_raw, default=str)[:16_000])],
        external_id=str((raw or {}).get("template-id") or (raw or {}).get("pluginId") or "")
        or None,
        raw=safe_raw,
    )


class RunnerEngine(ScannerEngine):
    runner_url: str | None

    def __init__(self, runner_url: str | None, runner_token: str):
        self.runner_url = runner_url
        self.runner_token = runner_token

    async def validate(self, context: ScanContext) -> tuple[bool, str | None]:
        if not self.runner_url:
            return False, f"{self.name} runner is not configured"
        if (
            context.auth
            and context.auth.get("type") == "API_KEY"
            and context.auth.get("location", "header") == "query"
        ):
            return False, f"{self.name} does not safely inject query-string API keys"
        return True, None

    async def execute(self, context: ScanContext) -> EngineResult:
        started = time.monotonic()
        self._auth = context.auth
        payload = {
            "target_url": context.target_url,
            "endpoints": [
                item.model_dump(mode="json", by_alias=True) for item in context.endpoints
            ],
            "specification": context.specification,
            "profile": context.profile,
            "rate_limit": context.limits.rate_limit,
            "concurrency": context.limits.concurrency,
            "request_timeout": context.limits.request_timeout,
            "max_requests": context.limits.max_requests,
            "max_duration": context.limits.max_duration,
            "allowed_hosts": context.allowed_hosts,
            "authentication": context.auth,
        }
        timeout = httpx.Timeout(context.limits.max_duration + 15, connect=10)
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                response = await client.post(
                    self.runner_url.rstrip("/") + "/run",
                    json=payload,
                    headers={"X-Runner-Token": self.runner_token},
                )
                response.raise_for_status()
                data = response.json()
        except httpx.TimeoutException:
            return EngineResult(
                engine=self.name,
                status="TIMEOUT",
                duration_seconds=time.monotonic() - started,
                reason="engine runner timed out",
            )
        except (httpx.HTTPError, ValueError) as exc:
            return EngineResult(
                engine=self.name,
                status="FAILED",
                duration_seconds=time.monotonic() - started,
                reason=f"engine runner failed: {type(exc).__name__}",
            )
        findings = self._normalize_events(data.get("events", []))
        return EngineResult(
            engine=self.name,
            status=data.get("status", "COMPLETED"),
            findings=findings,
            raw=redact(data),
            request_count=int(data.get("request_count", 0)),
            duration_seconds=time.monotonic() - started,
            reason=data.get("reason"),
        )

    def _normalize_events(self, events: list[dict[str, Any]]) -> list[FindingDraft]:
        raise NotImplementedError


class NucleiEngine(RunnerEngine):
    name = "nuclei"

    def _normalize_events(self, events: list[dict[str, Any]]) -> list[FindingDraft]:
        findings = []
        for event in events:
            info = event.get("info", {})
            classification = info.get("classification", {}) or {}
            cwe_values = classification.get("cwe-id", []) or []
            findings.append(
                _generic_finding(
                    engine=self.name,
                    title=str(info.get("name") or event.get("template-id") or "Nuclei finding"),
                    category=str(event.get("template-id") or "template-detection"),
                    severity=str(info.get("severity", "medium")),
                    endpoint=str(event.get("matched-at") or event.get("host") or ""),
                    method=str(event.get("type", "GET")).upper()
                    if event.get("type") in {"get", "post", "put", "delete", "patch"}
                    else None,
                    description=str(
                        info.get("description")
                        or "A controlled Nuclei template matched the target."
                    ),
                    confidence="HIGH" if event.get("matcher-name") else "MEDIUM",
                    cwe=str(cwe_values[0]) if cwe_values else None,
                    reference=[str(value) for value in info.get("reference", [])],
                    raw=redact_known(event, self._auth),
                )
            )
        return findings


class WfuzzEngine(RunnerEngine):
    name = "wfuzz"

    def _normalize_events(self, events: list[dict[str, Any]]) -> list[FindingDraft]:
        findings = []
        for event in events:
            status = int(event.get("code", event.get("status", 0)) or 0)
            if status in {401, 403, 404} or not status:
                continue
            words = int(event.get("words", 0) or 0)
            lines = int(event.get("lines", 0) or 0)
            findings.append(
                _generic_finding(
                    engine=self.name,
                    title="Interesting fuzzing response",
                    category="unexpected-path-response",
                    severity="LOW",
                    endpoint=str(event.get("url") or event.get("target") or ""),
                    method=str(event.get("method", "GET")),
                    description=f"A controlled fuzz payload returned HTTP {status} ({words} words, {lines} lines).",
                    confidence="LOW",
                    raw=redact_known(event, self._auth),
                )
            )
        return findings


class WuppieFuzzEngine(RunnerEngine):
    name = "wuppiefuzz"

    async def validate(self, context: ScanContext) -> tuple[bool, str | None]:
        valid, reason = await super().validate(context)
        if not valid:
            return valid, reason
        if not context.specification or not (
            "openapi" in context.specification or str(context.specification.get("swagger")) == "2.0"
        ):
            return False, "WuppieFuzz requires an OpenAPI or Swagger specification"
        return True, None

    def _normalize_events(self, events: list[dict[str, Any]]) -> list[FindingDraft]:
        findings = []
        for event in events:
            if event.get("kind") not in {"crash", "server_error", "bug", "finding"}:
                continue
            findings.append(
                _generic_finding(
                    engine=self.name,
                    title=str(event.get("title", "REST API fuzzing anomaly")),
                    category=str(event.get("category", "fuzzing-anomaly")),
                    severity=str(event.get("severity", "medium")),
                    endpoint=event.get("endpoint"),
                    method=event.get("method"),
                    description=str(
                        event.get("description", "WuppieFuzz observed anomalous API behavior.")
                    ),
                    confidence=str(event.get("confidence", "MEDIUM")),
                    raw=redact_known(event, self._auth),
                )
            )
        return findings


class ZapEngine(ScannerEngine):
    name = "zap"

    def __init__(self, zap_url: str | None, api_key: str, shared_directory: Path | None = None):
        self.zap_url = zap_url
        self.api_key = api_key
        self.shared_directory = shared_directory

    async def validate(self, context: ScanContext) -> tuple[bool, str | None]:
        if not self.zap_url:
            return False, "ZAP is not configured"
        if (
            context.auth
            and context.auth.get("type") == "API_KEY"
            and context.auth.get("location", "header") == "query"
        ):
            return False, "ZAP adapter does not safely inject query-string API keys"
        return True, None

    async def _api(
        self, client: httpx.AsyncClient, component: str, operation: str, **params: Any
    ) -> dict:
        params["apikey"] = self.api_key
        url = f"{self.zap_url.rstrip('/')}/JSON/{component}/{operation}/"
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()

    async def execute(self, context: ScanContext) -> EngineResult:
        started = time.monotonic()
        self._auth = context.auth
        alerts: list[dict[str, Any]] = []
        specification_path: Path | None = None
        specification_import = "not applicable"
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
                await self._api(
                    client, "core", "action/newSession", name=context.scan_id, overwrite="true"
                )
                context_name = f"scan-{context.scan_id}"
                created_context = await self._api(
                    client,
                    "context",
                    "action/newContext",
                    contextName=context_name,
                )
                context_id = str(created_context.get("contextId", ""))
                await self._api(
                    client,
                    "context",
                    "action/includeInContext",
                    contextName=context_name,
                    regex=re.escape(context.target_url.rstrip("/")) + r"(?:/.*)?",
                )
                existing_rules = await self._api(client, "replacer", "view/rules")
                for rule in existing_rules.get("rules", []):
                    description = str(rule.get("description", ""))
                    if description.startswith("scanner-auth-"):
                        await self._api(
                            client,
                            "replacer",
                            "action/removeRule",
                            description=description,
                        )
                if context.auth and context.auth.get("type") not in {None, "NONE"}:
                    from app.security.auth import apply_auth

                    applied = apply_auth(context.target_url, context.auth)
                    for index, (header, value) in enumerate(applied.headers.items()):
                        await self._api(
                            client,
                            "replacer",
                            "action/addRule",
                            description=f"scanner-auth-{index}",
                            enabled="true",
                            matchType="REQ_HEADER",
                            matchRegex="false",
                            matchString=header,
                            replacement=value,
                        )
                if (
                    context.specification
                    and self.shared_directory
                    and (
                        "openapi" in context.specification
                        or str(context.specification.get("swagger")) == "2.0"
                    )
                    and not _contains_external_reference(context.specification)
                ):
                    self.shared_directory.mkdir(parents=True, exist_ok=True)
                    specification_path = self.shared_directory / f"{context.scan_id}.json"
                    specification_path.write_text(
                        json.dumps(redact_known_values(context.specification, context.auth)),
                        encoding="utf-8",
                    )
                    specification_path.chmod(0o644)
                    await self._api(
                        client,
                        "openapi",
                        "action/importFile",
                        file=str(specification_path),
                        target=context.target_url,
                        contextId=context_id,
                    )
                    specification_import = "imported"
                elif context.specification and _contains_external_reference(context.specification):
                    specification_import = "skipped: external references are not fetched"
                elif context.specification and not self.shared_directory:
                    specification_import = "skipped: shared import directory is not configured"
                # The worker queue is configured with concurrency 1 for this stateful ZAP sidecar.
                await self._api(
                    client,
                    "core",
                    "action/accessUrl",
                    url=context.target_url,
                    followRedirects="false",
                )
                if context.profile not in {"QUICK", "SAFE"}:
                    scan = await self._api(
                        client,
                        "ascan",
                        "action/scan",
                        url=context.target_url,
                        recurse="true",
                        inscopeonly="true",
                    )
                    scan_id = str(scan.get("scan", ""))
                    deadline = time.monotonic() + context.limits.max_duration
                    while scan_id and time.monotonic() < deadline:
                        status = await self._api(client, "ascan", "view/status", scanId=scan_id)
                        if int(status.get("status", 0)) >= 100:
                            break
                        await asyncio.sleep(2)
                    else:
                        if scan_id:
                            await self._api(client, "ascan", "action/stop", scanId=scan_id)
                            return EngineResult(
                                engine=self.name,
                                status="TIMEOUT",
                                duration_seconds=time.monotonic() - started,
                                reason="ZAP active scan exceeded scan duration",
                            )
                result = await self._api(
                    client, "core", "view/alerts", baseurl=context.target_url, start=0, count=5000
                )
                alerts = result.get("alerts", [])
        except (httpx.HTTPError, OSError, ValueError, KeyError) as exc:
            return EngineResult(
                engine=self.name,
                status="FAILED",
                duration_seconds=time.monotonic() - started,
                reason=f"ZAP execution failed: {type(exc).__name__}",
            )
        finally:
            if specification_path:
                specification_path.unlink(missing_ok=True)
        findings = [self._normalize_alert(alert) for alert in alerts]
        return EngineResult(
            engine=self.name,
            status="COMPLETED",
            findings=findings,
            raw=redact_known(
                {"alerts": alerts, "specification_import": specification_import}, context.auth
            ),
            duration_seconds=time.monotonic() - started,
            reason=(specification_import if specification_import.startswith("skipped:") else None),
        )

    def _normalize_alert(self, alert: dict[str, Any]) -> FindingDraft:
        risk = str(alert.get("risk", "medium")).lower().split()[0]
        confidence_value = str(alert.get("confidence", "medium")).upper().split()[0]
        confidence = confidence_value if confidence_value in {"LOW", "MEDIUM", "HIGH"} else "MEDIUM"
        cwe_id = str(alert.get("cweid", "0"))
        endpoint = str(alert.get("url", ""))
        method_match = re.search(
            r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", str(alert.get("attack", ""))
        )
        return _generic_finding(
            engine=self.name,
            title=str(alert.get("alert") or alert.get("name") or "ZAP alert"),
            category=str(alert.get("pluginId") or alert.get("alertRef") or "zap-alert"),
            severity=risk,
            endpoint=_normalize_endpoint(endpoint),
            method=(
                str(alert.get("method", "")).upper()
                if str(alert.get("method", "")).upper()
                in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
                else (method_match.group(1) if method_match else None)
            ),
            parameter=alert.get("param") or None,
            description=str(alert.get("description") or "ZAP reported a security alert."),
            confidence=confidence,
            cwe=f"CWE-{cwe_id}" if cwe_id != "0" else None,
            reference=[line for line in str(alert.get("reference", "")).splitlines() if line],
            raw=redact_known(alert, self._auth),
        )
