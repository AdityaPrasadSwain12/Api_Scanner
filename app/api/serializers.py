from typing import Any

from app.core.logging import redact


def scan_dict(scan: Any) -> dict:
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "target_id": scan.target_id,
        "target_url": scan.target.base_url,
        "profile": scan.profile,
        "status": scan.status,
        "progress": scan.progress,
        "stage": scan.stage,
        "result_summary": scan.result_summary or {},
        "error": scan.error,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
    }


def endpoint_dict(endpoint: Any) -> dict:
    return {
        "endpoint_id": endpoint.endpoint_id,
        "path": endpoint.path,
        "method": endpoint.method,
        "base_url": endpoint.base_url,
        "operation_id": endpoint.operation_id,
        "tags": endpoint.tags,
        "parameters": endpoint.parameters,
        "request_body": endpoint.request_body,
        "responses": endpoint.responses,
        "content_types": endpoint.content_types,
        "authentication_required": endpoint.auth_required,
        "source": endpoint.source,
        "confidence": endpoint.confidence,
        "test_status": endpoint.test_status,
        "skip_reason": endpoint.skip_reason,
    }


def finding_dict(finding: Any, include_evidence: bool = True) -> dict:
    data = {
        "finding_id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "finding_type": finding.finding_type,
        "category": finding.category,
        "owasp_api": finding.owasp_api,
        "cwe": finding.cwe,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "risk_score": finding.risk_score,
        "endpoint": finding.endpoint,
        "method": finding.method,
        "parameter": finding.parameter,
        "source_engines": finding.source_engines,
        "impact": finding.impact,
        "remediation": finding.remediation,
        "references": finding.references,
        "status": finding.status,
        "first_seen_at": finding.first_seen_at,
        "last_seen_at": finding.last_seen_at,
    }
    if include_evidence:
        data["evidence"] = [
            redact(
                {
                    "engine": value.engine,
                    "request": value.request,
                    "response": value.response,
                    "detail": value.detail,
                }
            )
            for value in finding.evidence
        ]
    return data
