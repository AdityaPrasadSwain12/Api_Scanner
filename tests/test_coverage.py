from types import SimpleNamespace

from app.coverage import calculate_coverage


def test_coverage_separates_offline_checks_and_does_not_count_not_applicable_checks():
    endpoint = SimpleNamespace(
        endpoint_id="endpoint-1",
        source="OPENAPI_3.1.0",
        test_status="SKIPPED",
        skip_reason="baseline request failed: ConnectError: network unreachable",
        auth_required=False,
    )
    base = {
        "endpoint_id": "endpoint-1",
        "endpoint": "/search",
        "method": "GET",
        "eligible_parameters": [],
        "request_count": 0,
        "techniques": [],
    }
    engine = SimpleNamespace(
        name="custom",
        status="FAILED",
        request_count=1,
        reason="target endpoint baselines failed",
        raw_result={
            "checks": [
                {**base, "check": "baseline", "status": "ERROR"},
                {**base, "check": "insecure-transport", "status": "DETECTED"},
                {
                    **base,
                    "check": "sql-injection",
                    "status": "SKIPPED",
                    "reason": "baseline request failed: ConnectError: network unreachable",
                },
                {
                    **base,
                    "check": "reflected-xss",
                    "status": "SKIPPED",
                    "reason": "baseline request failed: ConnectError: network unreachable",
                },
                {
                    **base,
                    "check": "path-traversal",
                    "status": "NOT_APPLICABLE",
                    "reason": "no file or path-like input was documented",
                },
            ]
        },
    )

    coverage = calculate_coverage([endpoint], [engine], identity_count=0)

    assert coverage["assessment"]["status"] == "INCOMPLETE"
    assert coverage["assessment"]["blocking_reasons"] == {
        "baseline request failed: ConnectError: network unreachable": 1
    }
    assert coverage["runtime_check_summary"] == {
        "eligible_endpoint_checks": 2,
        "attempted_endpoint_checks": 0,
        "skipped_or_error_endpoint_checks": 2,
        "percent_attempted": 0.0,
    }
    assert coverage["offline_check_summary"] == {
        "eligible_endpoint_checks": 1,
        "attempted_endpoint_checks": 1,
        "skipped_or_error_endpoint_checks": 0,
        "percent_attempted": 100.0,
    }
    assert coverage["security_checks"]["path-traversal"]["eligible_endpoints"] == 0

