from collections import Counter
from typing import Any

OFFLINE_CHECKS = {"insecure-transport"}


def _check_summary(checks: dict[str, dict[str, Any]], names: set[str]) -> dict[str, Any]:
    eligible = sum(checks[name]["eligible_endpoints"] for name in names)
    attempted = sum(checks[name]["attempted_endpoints"] for name in names)
    return {
        "eligible_endpoint_checks": eligible,
        "attempted_endpoint_checks": attempted,
        "skipped_or_error_endpoint_checks": max(eligible - attempted, 0),
        "percent_attempted": round((attempted / eligible * 100) if eligible else 100.0, 1),
    }


def calculate_coverage(endpoints: list[Any], engines: list[Any], identity_count: int) -> dict:
    statuses = Counter(endpoint.test_status for endpoint in endpoints)
    defined = sum(1 for endpoint in endpoints if endpoint.source.startswith(("OPENAPI", "POSTMAN")))
    discovered = len(endpoints) - defined
    tested = statuses.get("TESTED", 0)
    skipped = statuses.get("SKIPPED", 0)
    engine_coverage = {
        engine.name: {
            "status": engine.status,
            "request_count": engine.request_count,
            "reason": engine.reason,
        }
        for engine in engines
    }
    total = len(endpoints)
    endpoint_check_matrix: list[dict[str, Any]] = []
    for engine in engines:
        raw = engine.raw_result
        if not isinstance(raw, dict) or not isinstance(raw.get("checks"), list):
            continue
        for value in raw["checks"]:
            if isinstance(value, dict) and value.get("check") != "baseline":
                endpoint_check_matrix.append(value)
    check_names = sorted(
        {str(value.get("check")) for value in endpoint_check_matrix if value.get("check")}
    )
    security_checks: dict[str, dict[str, Any]] = {}
    for name in check_names:
        values = [value for value in endpoint_check_matrix if value.get("check") == name]
        eligible = [value for value in values if value.get("status") != "NOT_APPLICABLE"]
        attempted = [
            value for value in eligible if value.get("status") in {"TESTED", "DETECTED"}
        ]
        security_checks[name] = {
            "execution_mode": "OFFLINE" if name in OFFLINE_CHECKS else "RUNTIME",
            "eligible_endpoints": len(eligible),
            "attempted_endpoints": len(attempted),
            "detected_endpoints": sum(
                value.get("status") == "DETECTED" for value in eligible
            ),
            "skipped_endpoints": sum(
                value.get("status") == "SKIPPED" for value in eligible
            ),
            "error_endpoints": sum(value.get("status") == "ERROR" for value in eligible),
            "request_count": sum(int(value.get("request_count", 0) or 0) for value in values),
            "percent_attempted": round(
                (len(attempted) / len(eligible) * 100) if eligible else 100.0, 1
            ),
            "skip_reasons": dict(
                Counter(
                    str(value.get("reason"))
                    for value in eligible
                    if value.get("status") in {"SKIPPED", "ERROR"} and value.get("reason")
                )
            ),
        }
    all_check_names = set(security_checks)
    offline_check_names = all_check_names & OFFLINE_CHECKS
    runtime_check_names = all_check_names - OFFLINE_CHECKS
    all_check_summary = _check_summary(security_checks, all_check_names)
    offline_check_summary = _check_summary(security_checks, offline_check_names)
    runtime_check_summary = _check_summary(security_checks, runtime_check_names)
    required_auth_endpoints = sum(endpoint.auth_required for endpoint in endpoints)
    auth_check = security_checks.get("missing-authentication", {})
    authorization_checks = [
        security_checks.get(name, {}) for name in ("bola", "bfla")
    ]
    authorization_eligible = sum(
        int(value.get("eligible_endpoints", 0)) for value in authorization_checks
    )
    authorization_attempted = sum(
        int(value.get("attempted_endpoints", 0)) for value in authorization_checks
    )
    endpoint_skip_reasons = Counter(
        endpoint.skip_reason for endpoint in endpoints if endpoint.skip_reason
    )
    blocking_reasons = Counter(endpoint_skip_reasons)
    for name in runtime_check_names:
        for reason, count in security_checks[name]["skip_reasons"].items():
            # A failed baseline fans out to dependent checks. Count that transport failure
            # once per endpoint, not once for every vulnerability class.
            if str(reason).startswith("baseline request failed"):
                continue
            blocking_reasons[str(reason)] += int(count)
    if not total or not tested:
        assessment_status = "INCOMPLETE"
    elif tested < total or runtime_check_summary["skipped_or_error_endpoint_checks"]:
        assessment_status = "PARTIAL"
    else:
        assessment_status = "COMPLETE"
    return {
        "assessment": {
            "status": assessment_status,
            "complete": assessment_status == "COMPLETE",
            "endpoint_reachability_complete": bool(total) and tested == total,
            "runtime_check_coverage_complete": (
                runtime_check_summary["skipped_or_error_endpoint_checks"] == 0
            ),
            "blocking_reasons": dict(blocking_reasons),
        },
        "endpoints": {
            "total": total,
            "defined": defined,
            "discovered": discovered,
            "tested": tested,
            "skipped": skipped,
            "not_tested": max(total - tested - skipped, 0),
            "percent_tested": round((tested / total * 100) if total else 0, 1),
            "skip_reasons": dict(endpoint_skip_reasons),
        },
        "authentication": {
            "required_endpoints": required_auth_endpoints,
            "tested_endpoints": int(auth_check.get("attempted_endpoints", 0)),
            "tested": required_auth_endpoints == 0
            or int(auth_check.get("attempted_endpoints", 0)) == required_auth_endpoints,
        },
        "authorization": {
            "identities_configured": identity_count,
            "eligible_endpoint_checks": authorization_eligible,
            "attempted_endpoint_checks": authorization_attempted,
            "tested": authorization_eligible == 0
            or authorization_attempted == authorization_eligible,
        },
        "fuzzing": {
            "tested": any(
                engine.name in {"wfuzz", "wuppiefuzz"} and engine.status == "COMPLETED"
                for engine in engines
            )
        },
        # Kept as the primary/backwards-compatible metric. It intentionally excludes
        # URL-scheme/specification checks that can run while the target is offline.
        "security_check_summary": runtime_check_summary,
        "runtime_check_summary": runtime_check_summary,
        "offline_check_summary": offline_check_summary,
        "all_security_check_summary": all_check_summary,
        "security_checks": security_checks,
        "endpoint_check_matrix": endpoint_check_matrix,
        "engines": engine_coverage,
        "specification": {"available": defined > 0, "operations_analyzed": defined},
        "interpretation": (
            "Runtime coverage excludes offline contract and URL-scheme inspection. "
            "A report is complete only when every documented endpoint is reachable and "
            "every applicable runtime check is attempted. "
            "A TESTED check with no finding means no evidence was detected by that check; "
            "it does not prove the endpoint is secure."
        ),
    }
