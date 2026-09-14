import asyncio
import hashlib
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.analysis.specification import analyze_specification
from app.core.config import Settings
from app.core.logging import logger, redact
from app.core.secrets import SecretStore
from app.correlation import correlate_findings
from app.coverage import calculate_coverage
from app.domain import EngineResult, ScanContext, ScanLimits
from app.engines import CustomApiEngine, NucleiEngine, WfuzzEngine, WuppieFuzzEngine, ZapEngine
from app.ingestion.discovery import discover_inventory, fetch_specification
from app.ingestion.openapi import parse_api_document, parse_postman_collection
from app.models.database import (
    ApiSpecification,
    AuthenticationProfile,
    Endpoint,
    Finding,
    FindingEvidence,
    FindingSource,
    Identity,
    Report,
    Scan,
    ScanEngine,
    ScanStatus,
    Target,
    utcnow,
)
from app.reporting import ReportGenerator
from app.risk import calculate_risk
from app.security.scope import ScopedHttpClient, ScopeGuard

PROFILE_DEFAULTS = {
    "QUICK": {"engines": ["custom", "nuclei", "zap"], "requests": 250, "duration": 300},
    "SAFE": {"engines": ["custom", "zap"], "requests": 500, "duration": 600},
    "STANDARD": {
        "engines": ["custom", "zap", "nuclei", "wfuzz", "wuppiefuzz"],
        "requests": 2000,
        "duration": 1800,
    },
    "DEEP": {
        "engines": ["custom", "zap", "nuclei", "wfuzz", "wuppiefuzz"],
        "requests": 10_000,
        "duration": 3600,
    },
    "AGGRESSIVE": {"engines": ["custom"], "requests": 20_000, "duration": 7200},
}


class ScanCancelled(Exception):
    pass


class ScanTimedOut(Exception):
    pass


class TargetUnreachable(Exception):
    pass


class Orchestrator:
    def __init__(self, db: Session, settings: Settings):
        self.db = db
        self.settings = settings
        self.secret_store = SecretStore(
            settings.secret_encryption_key, allow_ephemeral=settings.environment != "production"
        )

    def run_sync(self, scan_id: str) -> None:
        asyncio.run(self.run(scan_id))

    async def run(self, scan_id: str) -> None:
        scan = self.db.get(Scan, scan_id)
        if not scan:
            return
        if scan.cancel_requested or scan.status == ScanStatus.CANCELLED.value:
            return
        deadline = time.monotonic() + self._limits(scan).max_duration
        partial_failures: list[str] = []
        try:
            self._stage(scan, ScanStatus.INITIALIZING, 5, "validating target")
            target = self.db.get(Target, scan.target_id)
            if not target:
                raise ValueError("scan target no longer exists")
            guard = ScopeGuard(
                target.allowed_hosts, allow_private=self.settings.allow_private_targets
            )
            await guard.validate(target.base_url)
            await self._checkpoint(scan, deadline)

            self._stage(scan, ScanStatus.DISCOVERING, 15, "building API inventory")
            inventory, observations = await self._inventory(scan, target, guard)
            for endpoint in inventory.endpoints:
                await guard.validate(endpoint.base_url)
                self.db.add(
                    Endpoint(
                        scan_id=scan.id,
                        endpoint_id=endpoint.endpoint_id,
                        base_url=endpoint.base_url,
                        path=endpoint.path,
                        method=endpoint.method,
                        operation_id=endpoint.operation_id,
                        tags=endpoint.tags,
                        parameters=[
                            item.model_dump(mode="json", by_alias=True)
                            for item in endpoint.parameters
                        ],
                        request_body=redact(endpoint.request_body),
                        responses=redact(endpoint.responses),
                        content_types=endpoint.content_types,
                        auth_required=endpoint.auth_required,
                        source=endpoint.source,
                        confidence=endpoint.confidence,
                    )
                )
            if inventory.document:
                safe_document = redact(inventory.document)
                self.db.add(
                    ApiSpecification(
                        scan_id=scan.id,
                        version=inventory.version,
                        source=inventory.endpoints[0].source,
                        sha256=inventory.sha256,
                        document=safe_document,
                    )
                )
            self.db.commit()
            static_findings = (
                analyze_specification(inventory.document) if inventory.document else []
            )
            await self._checkpoint(scan, deadline)

            context = self._context(scan, target, inventory)
            engines = self._engines(scan)
            raw_findings = list(static_findings)
            self._stage(scan, ScanStatus.SCANNING, 30, "running scanner engines")
            for index, engine in enumerate(engines):
                await self._checkpoint(scan, deadline)
                logger.info("engine_started", scan_id=scan.id, engine_id=engine.name)
                try:
                    remaining = max(1, deadline - time.monotonic())
                    result = await asyncio.wait_for(engine.run(context), timeout=remaining)
                except TimeoutError:
                    result = EngineResult(
                        engine=engine.name, status="TIMEOUT", reason="scan deadline reached"
                    )
                except Exception as exc:
                    logger.exception("engine_failed", scan_id=scan.id, engine_id=engine.name)
                    result = EngineResult(
                        engine=engine.name,
                        status="FAILED",
                        reason=f"unhandled engine error: {type(exc).__name__}",
                    )
                self._persist_engine(scan.id, result)
                raw_findings.extend(result.findings)
                if result.status in {"FAILED", "TIMEOUT"}:
                    partial_failures.append(f"{engine.name}: {result.reason or result.status}")
                if engine.name == "custom":
                    endpoints = list(
                        self.db.scalars(select(Endpoint).where(Endpoint.scan_id == scan.id))
                    )
                    tested, baseline_reasons = self._apply_endpoint_baselines(endpoints, result.raw)
                    if endpoints and tested == 0:
                        engines_db = list(
                            self.db.scalars(
                                select(ScanEngine).where(ScanEngine.scan_id == scan.id)
                            )
                        )
                        identities = list(
                            self.db.scalars(
                                select(Identity).where(Identity.scan_id == scan.id)
                            )
                        )
                        coverage = calculate_coverage(endpoints, engines_db, len(identities))
                        scan.result_summary = {
                            "endpoint_count": len(endpoints),
                            "finding_count": 0,
                            "severity_distribution": {},
                            "maximum_risk_score": 0,
                            "target": target.base_url,
                            "coverage": coverage,
                            "partial_failures": partial_failures,
                            "discovery_observations": observations,
                        }
                        self.db.commit()
                        reason = "; ".join(baseline_reasons[:3]) or "no HTTP response"
                        raise TargetUnreachable(
                            "Target API could not be reached from the scanner worker: "
                            f"0 of {len(endpoints)} documented endpoints returned an HTTP "
                            f"response ({reason}). Ensure the API is running and that its host "
                            "and port are reachable from the scanner containers, then start a new scan."
                        )
                progress = 30 + int(40 * ((index + 1) / max(len(engines), 1)))
                self._stage(scan, ScanStatus.SCANNING, progress, f"finished {engine.name}")

            self._stage(scan, ScanStatus.CORRELATING, 75, "correlating and deduplicating findings")
            correlated = correlate_findings(raw_findings)
            for value in correlated:
                draft = value.finding
                finding = Finding(
                    scan_id=scan.id,
                    fingerprint=draft.fingerprint(),
                    finding_type=draft.finding_type,
                    title=draft.title,
                    description=draft.description,
                    category=draft.category,
                    owasp_api=draft.owasp_api,
                    cwe=draft.cwe,
                    severity=draft.severity,
                    confidence=draft.confidence,
                    risk_score=calculate_risk(draft.severity, draft.confidence),
                    endpoint=draft.endpoint,
                    method=draft.method,
                    parameter=draft.parameter,
                    source_engines=value.sources,
                    impact=draft.impact,
                    remediation=draft.remediation,
                    references=draft.references,
                )
                self.db.add(finding)
                self.db.flush()
                for evidence in draft.evidence:
                    self.db.add(
                        FindingEvidence(
                            finding_id=finding.id,
                            engine=evidence.engine,
                            request=redact(evidence.request),
                            response=redact(evidence.response),
                            detail=redact(evidence.detail),
                        )
                    )
                for source in value.sources:
                    self.db.add(
                        FindingSource(
                            finding_id=finding.id,
                            engine=source,
                            external_id=draft.external_id,
                            raw_result=redact(draft.raw),
                        )
                    )
            endpoints = list(self.db.scalars(select(Endpoint).where(Endpoint.scan_id == scan.id)))
            custom_result = next(
                (
                    value
                    for value in self.db.scalars(
                        select(ScanEngine).where(ScanEngine.scan_id == scan.id)
                    )
                    if value.name == "custom"
                ),
                None,
            )
            custom_checks = (
                custom_result.raw_result.get("checks", [])
                if custom_result and isinstance(custom_result.raw_result, dict)
                else []
            )
            self._apply_endpoint_baselines(endpoints, {"checks": custom_checks})
            await self._checkpoint(scan, deadline)

            self._stage(scan, ScanStatus.REPORTING, 90, "generating reports")
            engines_db = list(
                self.db.scalars(select(ScanEngine).where(ScanEngine.scan_id == scan.id))
            )
            identities = list(self.db.scalars(select(Identity).where(Identity.scan_id == scan.id)))
            coverage = calculate_coverage(endpoints, engines_db, len(identities))
            findings_db = list(
                self.db.scalars(
                    select(Finding)
                    .options(selectinload(Finding.evidence))
                    .where(Finding.scan_id == scan.id)
                )
            )
            scan.finished_at = utcnow()
            scan.status = (
                ScanStatus.PARTIAL.value
                if partial_failures
                or coverage.get("assessment", {}).get("status") != "COMPLETE"
                else ScanStatus.COMPLETED.value
            )
            report_generator = ReportGenerator(self.settings.report_directory)
            payload = report_generator.payload(scan, target, findings_db, coverage)
            for format_name, path, digest in report_generator.write_all(scan.id, payload):
                self.db.add(
                    Report(scan_id=scan.id, format=format_name, path=str(path), sha256=digest)
                )
            scan.progress = 100
            scan.stage = "complete"
            scan.result_summary = {
                **payload["summary"],
                "target": target.base_url,
                "coverage": coverage,
                "partial_failures": partial_failures,
                "discovery_observations": observations,
            }
            self.db.commit()
        except ScanCancelled:
            self._terminate(scan, ScanStatus.CANCELLED, "scan cancelled by user")
        except ScanTimedOut:
            self._terminate(scan, ScanStatus.TIMEOUT, "scan duration limit reached")
        except TargetUnreachable as exc:
            self._terminate(scan, ScanStatus.FAILED, str(exc))
        except Exception as exc:
            logger.exception("scan_failed", scan_id=scan.id)
            self._terminate(scan, ScanStatus.FAILED, f"{type(exc).__name__}: {exc}")

    async def _inventory(self, scan: Scan, target: Target, guard: ScopeGuard):
        config = scan.request_config
        client = ScopedHttpClient(
            guard,
            timeout=self.settings.request_timeout,
            max_response_size=self.settings.max_response_size,
        )
        ingestion = self.db.scalar(
            select(AuthenticationProfile).where(
                AuthenticationProfile.scan_id == scan.id,
                AuthenticationProfile.auth_type == "_INGESTION_PAYLOAD",
            )
        )
        secret_payload = self.secret_store.decrypt(ingestion.encrypted_config) if ingestion else {}
        if secret_payload.get("specification") is not None:
            inventory = parse_api_document(
                secret_payload["specification"], target.base_url, self.settings.max_spec_size
            )
            observations = [{"source": "inline_specification", "outcome": "parsed"}]
        elif secret_payload.get("postman_collection") is not None:
            inventory = parse_postman_collection(
                secret_payload["postman_collection"], target.base_url, self.settings.max_spec_size
            )
            observations = [{"source": "postman_collection", "outcome": "parsed"}]
        elif config.get("specification_url"):
            inventory = await fetch_specification(
                client, config["specification_url"], self.settings.max_spec_size, target.base_url
            )
            observations = [{"source": "specification_url", "outcome": "parsed"}]
        else:
            discovered_spec, endpoints, observations = await discover_inventory(
                client,
                target.base_url,
                self.settings.max_spec_size,
                config.get("policy", {}).get("user_paths", []),
            )
            if discovered_spec:
                inventory = discovered_spec
            else:
                from app.ingestion.openapi import ParsedInventory

                inventory = ParsedInventory(
                    "discovery",
                    [target.base_url],
                    endpoints,
                    {},
                    hashlib.sha256(b"{}").hexdigest(),
                )
        if ingestion:
            self.db.delete(ingestion)
            self.db.commit()
        return inventory, observations

    def _context(self, scan: Scan, target: Target, inventory: Any) -> ScanContext:
        auth_row = self.db.scalar(
            select(AuthenticationProfile).where(
                AuthenticationProfile.scan_id == scan.id,
                AuthenticationProfile.auth_type != "_INGESTION_PAYLOAD",
            )
        )
        auth = self.secret_store.decrypt(auth_row.encrypted_config) if auth_row else None
        identities = []
        for identity in self.db.scalars(select(Identity).where(Identity.scan_id == scan.id)):
            identities.append(
                {
                    "name": identity.name,
                    "role": identity.role,
                    "is_admin": identity.is_admin,
                    "resource_ids": identity.resource_ids,
                    "auth": self.secret_store.decrypt(identity.encrypted_auth),
                }
            )
        return ScanContext(
            scan_id=scan.id,
            target_url=target.base_url,
            allowed_hosts=target.allowed_hosts,
            profile=scan.profile,
            limits=self._limits(scan),
            endpoints=inventory.endpoints,
            specification=inventory.document or None,
            auth=auth,
            identities=identities,
        )

    def _limits(self, scan: Scan) -> ScanLimits:
        policy = scan.request_config.get("policy", {})
        defaults = PROFILE_DEFAULTS[scan.profile]
        return ScanLimits(
            rate_limit=min(
                float(policy.get("rate_limit") or self.settings.default_rate_limit),
                self.settings.default_rate_limit,
            ),
            concurrency=min(
                int(policy.get("concurrency") or self.settings.max_concurrency),
                self.settings.max_concurrency,
            ),
            request_timeout=min(
                float(policy.get("request_timeout") or self.settings.request_timeout),
                self.settings.request_timeout,
            ),
            max_requests=min(
                int(policy.get("max_requests") or defaults["requests"]), self.settings.max_requests
            ),
            max_duration=min(
                int(policy.get("max_duration") or defaults["duration"]), self.settings.scan_timeout
            ),
        )

    def _engines(self, scan: Scan) -> list[Any]:
        requested = scan.request_config.get("policy", {}).get("enabled_engines")
        names = list(requested or PROFILE_DEFAULTS[scan.profile]["engines"])
        # The custom engine owns the authenticated baseline and per-check coverage model.
        # Run it first even when callers provide a different engine ordering.
        names = ["custom", *(name for name in names if name != "custom")]
        available = {
            "custom": CustomApiEngine(
                allow_private=self.settings.allow_private_targets,
                max_response_size=self.settings.max_response_size,
                oast_callback_base_url=self.settings.oast_callback_base_url,
                oast_poll_base_url=self.settings.oast_poll_base_url,
                oast_api_key=self.settings.oast_api_key,
            ),
            "zap": ZapEngine(
                self.settings.zap_url,
                self.settings.zap_api_key,
                self.settings.zap_shared_directory,
            ),
            "nuclei": NucleiEngine(
                self.settings.nuclei_runner_url, self.settings.engine_runner_token
            ),
            "wfuzz": WfuzzEngine(self.settings.wfuzz_runner_url, self.settings.engine_runner_token),
            "wuppiefuzz": WuppieFuzzEngine(
                self.settings.wuppiefuzz_runner_url, self.settings.engine_runner_token
            ),
        }
        return [available[name] for name in names]

    async def _checkpoint(self, scan: Scan, deadline: float) -> None:
        while True:
            self.db.refresh(scan)
            if scan.cancel_requested:
                raise ScanCancelled
            if time.monotonic() >= deadline:
                raise ScanTimedOut
            if not scan.pause_requested:
                if scan.status == ScanStatus.PAUSED.value:
                    scan.status = ScanStatus.SCANNING.value
                    self.db.commit()
                return
            scan.status = ScanStatus.PAUSED.value
            scan.stage = "paused at safe checkpoint"
            self.db.commit()
            await asyncio.sleep(2)

    def _persist_engine(self, scan_id: str, result: EngineResult) -> None:
        self.db.add(
            ScanEngine(
                scan_id=scan_id,
                name=result.engine,
                status=result.status,
                duration_seconds=result.duration_seconds,
                request_count=result.request_count,
                reason=result.reason,
                raw_result=redact(result.raw),
            )
        )
        self.db.commit()

    def _apply_endpoint_baselines(
        self, endpoints: list[Endpoint], raw_result: Any
    ) -> tuple[int, list[str]]:
        checks = raw_result.get("checks", []) if isinstance(raw_result, dict) else []
        baseline_by_endpoint = {
            str(value.get("endpoint_id")): value
            for value in checks
            if isinstance(value, dict) and value.get("check") == "baseline"
        }
        tested = 0
        reasons: list[str] = []
        for endpoint in endpoints:
            baseline_check = baseline_by_endpoint.get(endpoint.endpoint_id)
            if baseline_check and baseline_check.get("status") == "TESTED":
                endpoint.test_status = "TESTED"
                endpoint.skip_reason = None
                tested += 1
                continue
            endpoint.test_status = "SKIPPED"
            endpoint.skip_reason = str(
                (baseline_check or {}).get("reason")
                or "custom baseline request was not completed"
            )
            if endpoint.skip_reason not in reasons:
                reasons.append(endpoint.skip_reason)
        self.db.commit()
        return tested, reasons

    def _stage(self, scan: Scan, status: ScanStatus, progress: int, stage: str) -> None:
        scan.status = status.value
        scan.progress = progress
        scan.stage = stage
        if scan.started_at is None:
            scan.started_at = utcnow()
        self.db.commit()
        logger.info(
            "scan_stage", scan_id=scan.id, status=status.value, progress=progress, stage=stage
        )

    def _terminate(self, scan: Scan, status: ScanStatus, error: str) -> None:
        scan.status = status.value
        scan.stage = status.value.lower()
        scan.error = redact(error)
        scan.finished_at = utcnow()
        self.db.commit()
