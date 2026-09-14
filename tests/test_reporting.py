import json
from datetime import UTC, datetime
from types import SimpleNamespace

from app.reporting import ReportGenerator


def test_generates_normalized_technical_html_and_pdf_reports_with_redaction(tmp_path):
    now = datetime.now(UTC)
    evidence = SimpleNamespace(
        engine="custom",
        request={"headers": {"Authorization": "Bearer top-secret"}},
        response={"status_code": 200},
        detail=json.dumps(
            {
                "pluginId": "scanner-internal-10036",
                "sourceMessageId": "scanner-correlation-value",
                "evidence": "reproducible proof",
                "url": "https://api.example.test/test",
                "method": "GET",
            }
        ),
    )
    finding = SimpleNamespace(
        id="finding-1",
        title="Example finding",
        finding_type="RUNTIME",
        description="Description",
        category="example",
        owasp_api=None,
        cwe=None,
        severity="HIGH",
        confidence="MEDIUM",
        risk_score=6.4,
        endpoint="/test",
        method="GET",
        parameter=None,
        source_engines=["custom"],
        impact="Impact",
        remediation="Fix",
        references=[],
        status="OPEN",
        evidence=[evidence],
        first_seen_at=now,
        last_seen_at=now,
    )
    repeated_finding = SimpleNamespace(
        **{
            **vars(finding),
            "id": "finding-2",
            "endpoint": "/test/2",
        }
    )
    scan = SimpleNamespace(
        id="scan-1", profile="SAFE", status="COMPLETED", started_at=now, finished_at=now
    )
    target = SimpleNamespace(base_url="https://api.example.test")
    generator = ReportGenerator(tmp_path)
    payload = generator.payload(
        scan,
        target,
        [finding, repeated_finding],
        {
            "endpoints": {
                "total": 2,
                "tested": 2,
                "skipped": 0,
                "not_tested": 0,
                "percent_tested": 100,
            },
            "engines": {"custom": {"status": "COMPLETED", "request_count": 2}},
            "interpretation": "An untested endpoint is not evidence of security.",
        },
    )
    files = generator.write_all("scan-1", payload)
    assert {item[0] for item in files} == {"JSON", "TECHNICAL_JSON", "HTML", "PDF"}

    json_path = next(path for kind, path, _ in files if kind == "JSON")
    pentest = json.loads(json_path.read_text())
    assert pentest["report_type"] == "pentest_handoff"
    assert pentest["summary"]["unique_issue_count"] == 1
    assert pentest["summary"]["affected_location_count"] == 2
    assert len(pentest["issues"]) == 1
    assert len(pentest["issues"][0]["affected_locations"]) == 2
    assert pentest["issues"][0]["issue_id"] == "PT-001"
    assert "finding_id" not in json_path.read_text()
    assert "first_seen_at" not in json_path.read_text()
    assert "source_engines" not in json_path.read_text()
    assert "scanner-internal-10036" not in json_path.read_text()
    assert "scanner-correlation-value" not in json_path.read_text()
    assert pentest["issues"][0]["affected_locations"][0]["evidence"][0]["proof"] == {
        "evidence": "reproducible proof",
        "url": "https://api.example.test/test",
        "method": "GET",
    }
    assert "top-secret" not in json_path.read_text()
    assert "[REDACTED]" in json_path.read_text()

    technical_path = next(path for kind, path, _ in files if kind == "TECHNICAL_JSON")
    technical = json.loads(technical_path.read_text())
    assert technical["report_metadata"]["report_type"] == "technical"
    assert len(technical["findings"]) == 2
    assert technical["findings"][0]["finding_id"]
    assert "scanner-internal-10036" in technical_path.read_text()
    assert "top-secret" not in technical_path.read_text()

    pdf_path = next(path for kind, path, _ in files if kind == "PDF")
    assert pdf_path.read_bytes().startswith(b"%PDF")
    assert pdf_path.stat().st_size > 5_000
