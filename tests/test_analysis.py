from app.analysis.authorization import authorization_confidence
from app.analysis.specification import analyze_specification
from app.correlation import correlate_findings
from app.domain import EvidenceDraft, FindingDraft
from app.engines.external import ZapEngine
from app.risk import calculate_risk


def finding(engine: str, confidence: str = "MEDIUM") -> FindingDraft:
    return FindingDraft(
        finding_type="RUNTIME",
        title="SQL Injection",
        description="test",
        category="sql-injection",
        severity="HIGH",
        confidence=confidence,
        endpoint="/users",
        method="GET",
        parameter="q",
        source_engine=engine,
        impact="impact",
        remediation="fix",
        evidence=[EvidenceDraft(engine=engine, detail="evidence")],
    )


def test_correlation_merges_sources_and_raises_confidence():
    results = correlate_findings([finding("zap", "LOW"), finding("nuclei", "MEDIUM")])
    assert len(results) == 1
    assert results[0].sources == ["nuclei", "zap"]
    assert results[0].finding.confidence == "HIGH"
    assert len(results[0].finding.evidence) == 2


def test_risk_separates_severity_from_confidence():
    assert calculate_risk("HIGH", "LOW") == 4.4
    assert calculate_risk("HIGH", "HIGH") == 8.0


def test_authorization_requires_more_than_http_200():
    vulnerable, confidence, similarity = authorization_confidence(
        owner_status=200,
        cross_status=200,
        owner_body='{"id":"100","name":"Alice"}',
        cross_body='{"id":"200","name":"Bob"}',
        foreign_identifier="200",
    )
    assert vulnerable is True
    assert similarity > 0.55
    not_vulnerable, _, _ = authorization_confidence(
        owner_status=200,
        cross_status=200,
        owner_body='{"id":"100","name":"Alice"}',
        cross_body='{"message":"generic accepted"}',
        foreign_identifier="200",
    )
    assert not_vulnerable is False


def test_specification_analysis_separates_static_findings():
    document = {
        "openapi": "3.1.0",
        "servers": [{"url": "http://api.example.test"}],
        "paths": {
            "/items": {
                "get": {
                    "security": [],
                    "deprecated": True,
                    "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
                    "responses": {},
                }
            }
        },
    }
    results = analyze_specification(document)
    categories = {item.category for item in results}
    assert {
        "missing-authentication-scheme",
        "insecure-transport",
        "deprecated-endpoint",
        "missing-authentication",
        "weak-schema-constraint",
    } <= categories
    assert all(item.finding_type == "SPECIFICATION" for item in results)


def test_zap_results_use_canonical_endpoint_and_runtime_method_for_correlation():
    engine = ZapEngine("http://zap:8080", "test-key")
    engine._auth = None
    finding = engine._normalize_alert(
        {
            "alert": "Off-site Redirect",
            "pluginId": "10028",
            "risk": "High",
            "confidence": "Medium",
            "url": "https://api.example.test/v1/redirect?to=https://example.invalid",
            "method": "GET",
            "param": "to",
            "cweid": "601",
        }
    )

    assert finding.endpoint == "/v1/redirect"
    assert finding.method == "GET"
    assert finding.category == "open-redirect"
