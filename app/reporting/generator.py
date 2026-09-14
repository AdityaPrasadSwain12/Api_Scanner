import hashlib
import html
import io
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.logging import redact

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
SEVERITY_COLORS = {
    "CRITICAL": "#7F1D1D",
    "HIGH": "#DC2626",
    "MEDIUM": "#D97706",
    "LOW": "#2563EB",
    "INFO": "#64748B",
}


def _compact(value: Any) -> Any:
    """Remove empty report fields without dropping meaningful false/zero values."""
    if isinstance(value, dict):
        result = {key: _compact(child) for key, child in value.items()}
        return {key: child for key, child in result.items() if child not in (None, "", [], {})}
    if isinstance(value, list):
        return [child for item in value if (child := _compact(item)) not in (None, "", [], {})]
    return value


def _best(value: str, candidate: str, order: dict[str, int]) -> str:
    return candidate if order.get(candidate, -1) > order.get(value, -1) else value


def _assessment_status(coverage: dict[str, Any]) -> str:
    explicit = coverage.get("assessment", {}).get("status")
    if explicit in {"COMPLETE", "PARTIAL", "INCOMPLETE"}:
        return explicit
    endpoints = coverage.get("endpoints", {})
    total = int(endpoints.get("total", 0) or 0)
    tested = int(endpoints.get("tested", 0) or 0)
    security = coverage.get("runtime_check_summary", coverage.get("security_check_summary", {}))
    blocked = int(security.get("skipped_or_error_endpoint_checks", 0) or 0)
    if not total or not tested:
        return "INCOMPLETE"
    if tested < total or blocked:
        return "PARTIAL"
    return "COMPLETE"


def _pentest_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Keep reproducible proof while dropping verbose engine transport metadata."""
    detail = evidence.get("detail")
    parsed_detail: Any = detail
    if isinstance(detail, str):
        try:
            parsed_detail = json.loads(detail)
        except (json.JSONDecodeError, TypeError):
            parsed_detail = detail[:1500]
    if isinstance(parsed_detail, dict):
        detail_keys = (
            "evidence",
            "attack",
            "param",
            "inputVector",
            "url",
            "method",
            "status_code",
            "reason",
        )
        parsed_detail = {
            key: parsed_detail[key]
            for key in detail_keys
            if parsed_detail.get(key) not in (None, "", [], {})
        }
    return _compact(
        {
            "request": evidence.get("request"),
            "response": evidence.get("response"),
            "proof": parsed_detail,
        }
    )


class ReportGenerator:
    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def payload(self, scan: Any, target: Any, findings: list[Any], coverage: dict) -> dict:
        """Build the exhaustive technical payload retained for audit and deep review."""
        safe_findings = []
        for finding in findings:
            safe_findings.append(
                {
                    "finding_id": finding.id,
                    "title": finding.title,
                    "finding_type": finding.finding_type,
                    "description": finding.description,
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
                    "evidence": [
                        {
                            "engine": value.engine,
                            "request": redact(value.request),
                            "response": redact(value.response),
                            "detail": redact(value.detail),
                        }
                        for value in finding.evidence
                    ],
                    "first_seen_at": finding.first_seen_at.isoformat(),
                    "last_seen_at": finding.last_seen_at.isoformat(),
                }
            )
        safe_findings.sort(
            key=lambda item: (
                -SEVERITY_ORDER.get(item["severity"], -1),
                -float(item["risk_score"]),
                item["title"],
                item["endpoint"] or "",
            )
        )
        duration = None
        if scan.started_at and scan.finished_at:
            started_at = scan.started_at
            finished_at = scan.finished_at
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=UTC)
            if finished_at.tzinfo is None:
                finished_at = finished_at.replace(tzinfo=UTC)
            duration = (finished_at - started_at).total_seconds()
        return {
            "report_metadata": {
                "format_version": "2.0",
                "report_type": "technical",
                "generated_at": datetime.now(UTC).isoformat(),
                "disclaimer": "Automated testing does not guarantee complete vulnerability detection.",
            },
            "scan": {
                "id": scan.id,
                "target": target.base_url,
                "profile": scan.profile,
                "status": scan.status,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                "duration_seconds": duration,
            },
            "summary": {
                "endpoint_count": coverage.get("endpoints", {}).get("total", 0),
                "finding_count": len(findings),
                "severity_distribution": dict(Counter(item.severity for item in findings)),
                "maximum_risk_score": max((item.risk_score for item in findings), default=0),
                "assessment_status": _assessment_status(coverage),
            },
            "coverage": coverage,
            "findings": safe_findings,
        }

    def pentest_payload(self, technical: dict) -> dict:
        """Create a compact, grouped handoff without correlation/deduplication internals."""
        groups: dict[tuple[Any, ...], dict[str, Any]] = {}
        location_maps: dict[tuple[Any, ...], dict[tuple[Any, ...], dict[str, Any]]] = {}
        evidence_markers: dict[int, set[str]] = {}

        for finding in technical["findings"]:
            group_key = (
                finding.get("category"),
                finding.get("title"),
                finding.get("description"),
                finding.get("impact"),
                finding.get("remediation"),
                finding.get("owasp_api"),
                finding.get("cwe"),
            )
            group = groups.get(group_key)
            if group is None:
                group = {
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "confidence": finding["confidence"],
                    "risk_score": finding["risk_score"],
                    "classification": _compact(
                        {
                            "category": finding.get("category"),
                            "owasp_api": finding.get("owasp_api"),
                            "cwe": finding.get("cwe"),
                        }
                    ),
                    "description": finding["description"],
                    "impact": finding["impact"],
                    "affected_locations": [],
                    "remediation": finding["remediation"],
                    "references": list(dict.fromkeys(finding.get("references") or [])),
                    "status": finding["status"],
                    "detected_by": list(dict.fromkeys(finding.get("source_engines") or [])),
                }
                groups[group_key] = group
                location_maps[group_key] = {}
            else:
                group["severity"] = _best(
                    group["severity"], finding["severity"], SEVERITY_ORDER
                )
                group["confidence"] = _best(
                    group["confidence"], finding["confidence"], CONFIDENCE_ORDER
                )
                group["risk_score"] = max(group["risk_score"], finding["risk_score"])
                group["detected_by"] = list(
                    dict.fromkeys([*group["detected_by"], *(finding.get("source_engines") or [])])
                )

            location_key = (
                finding.get("method"),
                finding.get("endpoint"),
                finding.get("parameter"),
            )
            location = location_maps[group_key].get(location_key)
            if location is None:
                location = _compact(
                    {
                        "method": finding.get("method"),
                        "path": finding.get("endpoint"),
                        "parameter": finding.get("parameter"),
                        "evidence": [],
                    }
                )
                location.setdefault("evidence", [])
                location_maps[group_key][location_key] = location
                group["affected_locations"].append(location)
                evidence_markers[id(location)] = set()

            # Evidence from multiple engines is often byte-for-byte identical. Retain up to
            # three unique, redacted examples per location; the technical JSON retains all.
            for evidence in finding.get("evidence") or []:
                concise = _pentest_evidence(evidence)
                marker = json.dumps(concise, sort_keys=True, default=str)
                markers = evidence_markers[id(location)]
                if not concise or marker in markers:
                    continue
                markers.add(marker)
                if len(location["evidence"]) < 3:
                    location["evidence"].append(concise)

        issues = sorted(
            groups.values(),
            key=lambda item: (
                -SEVERITY_ORDER.get(item["severity"], -1),
                -float(item["risk_score"]),
                item["title"],
            ),
        )
        for index, issue in enumerate(issues, start=1):
            issue["issue_id"] = f"PT-{index:03d}"
            issue["detected_by"].sort()
            issue["affected_locations"].sort(
                key=lambda item: (item.get("path", ""), item.get("method", ""))
            )
            # Put the human tracking identifier first in serialized JSON.
            issue.update({key: issue.pop(key) for key in list(issue) if key != "issue_id"})

        endpoint_coverage = technical.get("coverage", {}).get("endpoints", {})
        security_summary = technical.get("coverage", {}).get("security_check_summary", {})
        security_checks = technical.get("coverage", {}).get("security_checks", {})
        severity_distribution = Counter(issue["severity"] for issue in issues)
        affected_locations = sum(len(issue["affected_locations"]) for issue in issues)
        return {
            "schema_version": "2.0",
            "report_type": "pentest_handoff",
            "generated_at": technical["report_metadata"]["generated_at"],
            "scan": {
                "scan_id": technical["scan"]["id"],
                "target": technical["scan"]["target"],
                "status": technical["scan"]["status"],
                "profile": technical["scan"]["profile"],
                "started_at": technical["scan"].get("started_at"),
                "finished_at": technical["scan"].get("finished_at"),
                "duration_seconds": technical["scan"].get("duration_seconds"),
            },
            "summary": {
                "assessment_status": _assessment_status(technical.get("coverage", {})),
                "unique_issue_count": len(issues),
                "affected_location_count": affected_locations,
                "severity_distribution": {
                    severity: severity_distribution.get(severity, 0)
                    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                },
                "maximum_risk_score": max(
                    (issue["risk_score"] for issue in issues), default=0
                ),
                "endpoint_coverage": {
                    key: endpoint_coverage.get(key, 0)
                    for key in ("total", "tested", "skipped", "not_tested", "percent_tested")
                },
                "security_check_coverage": {
                    key: security_summary.get(key, 0)
                    for key in (
                        "eligible_endpoint_checks",
                        "attempted_endpoint_checks",
                        "skipped_or_error_endpoint_checks",
                        "percent_attempted",
                    )
                },
            },
            "test_coverage": {
                name: {
                    key: value.get(key, 0)
                    for key in (
                        "eligible_endpoints",
                        "attempted_endpoints",
                        "detected_endpoints",
                        "skipped_endpoints",
                        "error_endpoints",
                        "percent_attempted",
                    )
                }
                for name, value in security_checks.items()
            },
            "issues": issues,
            "limitations": [
                technical["report_metadata"]["disclaimer"],
                technical.get("coverage", {}).get(
                    "interpretation",
                    "Untested endpoints must not be interpreted as secure.",
                ),
                "Full scanner evidence and engine metadata are available in the technical JSON report.",
            ],
        }

    def write_all(self, scan_id: str, payload: dict) -> list[tuple[str, Path, str]]:
        scan_dir = self.directory / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        technical = redact(payload)
        pentest = redact(self.pentest_payload(technical))
        rendered = {
            "JSON": ("report.json", json.dumps(pentest, indent=2, default=str).encode()),
            "TECHNICAL_JSON": (
                "report.technical.json",
                json.dumps(technical, indent=2, default=str).encode(),
            ),
            "HTML": ("report.html", self._html(technical).encode()),
            "PDF": ("report.pdf", self._pdf(technical)),
        }
        output = []
        for format_name, (filename, content) in rendered.items():
            path = scan_dir / filename
            path.write_bytes(content)
            output.append((format_name, path, hashlib.sha256(content).hexdigest()))
        return output

    def _html(self, payload: dict) -> str:
        summary = payload["summary"]
        finding_rows = "".join(
            f"<tr><td>{html.escape(item['severity'])}</td><td>{html.escape(item['confidence'])}</td>"
            f"<td>{html.escape(item['title'])}</td><td><code>{html.escape(str(item['method'] or ''))} "
            f"{html.escape(str(item['endpoint'] or ''))}</code></td><td>{item['risk_score']}</td></tr>"
            for item in payload["findings"]
        )
        detail = "".join(
            f"<section><h2>{index}. {html.escape(item['title'])}</h2><p><b>{item['severity']} / "
            f"{item['confidence']}</b> &middot; Risk {item['risk_score']}</p>"
            f"<p><code>{html.escape(str(item['method'] or ''))} {html.escape(str(item['endpoint'] or ''))}</code></p>"
            f"<p>{html.escape(item['description'])}</p><h3>Impact</h3><p>{html.escape(item['impact'])}</p>"
            f"<h3>Evidence</h3><pre>{html.escape(json.dumps(item['evidence'], indent=2, default=str))}</pre>"
            f"<h3>Remediation</h3><p>{html.escape(item['remediation'])}</p></section>"
            for index, item in enumerate(payload["findings"], start=1)
        )
        return f"""<!doctype html><html><head><meta charset='utf-8'><title>Technical API Security Report</title>
<style>body{{font:14px system-ui;margin:40px;color:#17202a}}header{{border-bottom:4px solid #0f766e}}
table{{border-collapse:collapse;width:100%}}th,td{{padding:9px;border:1px solid #dfe6e9;text-align:left}}
th{{background:#e2e8f0}}code,pre{{font-size:12px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f8fafc;padding:12px}}
section{{page-break-inside:avoid;border-top:1px solid #ddd}}.note{{background:#fff3bf;padding:12px}}</style></head>
<body><header><p>SENTINEL API SECURITY</p><h1>Technical Assessment Report</h1>
<p>{html.escape(payload["scan"]["target"])}</p></header><p class='note'>{payload["report_metadata"]["disclaimer"]}</p>
<h2>Executive summary</h2><p>{summary["endpoint_count"]} endpoints; {summary["finding_count"]} findings; maximum risk {summary["maximum_risk_score"]}.</p>
<h2>Coverage</h2><pre>{html.escape(json.dumps(payload["coverage"], indent=2, default=str))}</pre>
<h2>Findings overview</h2><table><thead><tr><th>Severity</th><th>Confidence</th><th>Finding</th><th>Endpoint</th><th>Risk</th></tr></thead><tbody>{finding_rows}</tbody></table>
<h2>Detailed findings</h2>{detail}</body></html>"""

    def _pdf(self, payload: dict) -> bytes:
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=16 * mm,
            leftMargin=16 * mm,
            topMargin=18 * mm,
            bottomMargin=17 * mm,
            title="Sentinel API Security Assessment",
            author="Sentinel API Scanner",
            subject=f"API security findings for {payload['scan']['target']}",
        )
        styles = self._pdf_styles()
        story: list[Any] = []

        story.extend(
            [
                Spacer(1, 19 * mm),
                Paragraph("SENTINEL", styles["CoverBrand"]),
                Paragraph("API SECURITY", styles["CoverEyebrow"]),
                Spacer(1, 22 * mm),
                Paragraph("API Security<br/>Assessment Report", styles["CoverTitle"]),
                Spacer(1, 8 * mm),
                Paragraph(html.escape(payload["scan"]["target"]), styles["CoverTarget"]),
                Spacer(1, 22 * mm),
                self._pdf_metadata_table(payload, styles),
                Spacer(1, 18 * mm),
                Paragraph("CONFIDENTIAL - AUTHORIZED SECURITY TESTING", styles["Classification"]),
                Spacer(1, 4 * mm),
                Paragraph(
                    html.escape(payload["report_metadata"]["disclaimer"]), styles["SmallMuted"]
                ),
                PageBreak(),
            ]
        )

        pentest = self.pentest_payload(payload)
        issues = pentest["issues"]
        overall_risk = self._overall_risk(issues)
        assessment_status = _assessment_status(payload.get("coverage", {}))
        assessment_callout: list[Any] = []
        if assessment_status != "COMPLETE":
            blockers = payload.get("coverage", {}).get("assessment", {}).get(
                "blocking_reasons", {}
            )
            blocker_text = "; ".join(
                f"{reason} ({count})" for reason, count in list(blockers.items())[:4]
            ) or "One or more required runtime checks were not completed."
            assessment_callout = [
                Paragraph(
                    "<b>ASSESSMENT NOT COMPLETE.</b> Do not interpret missing findings as a "
                    f"clean result. Blocking conditions: {html.escape(blocker_text)}",
                    styles["WarningCallout"],
                ),
                Spacer(1, 6 * mm),
            ]
        story.extend(
            [
                Paragraph("Executive Summary", styles["SectionTitle"]),
                Paragraph(
                    "This report presents the results of an automated security assessment of "
                    f"<b>{html.escape(payload['scan']['target'])}</b>. Findings require manual "
                    "validation before remediation or exploitation decisions are made.",
                    styles["Body"],
                ),
                Spacer(1, 5 * mm),
                *assessment_callout,
                self._pdf_summary_table(
                    payload, overall_risk, styles, unique_issue_count=len(issues)
                ),
                Spacer(1, 6 * mm),
                Paragraph("Severity Distribution", styles["Subsection"]),
                self._pdf_severity_table(
                    pentest["summary"]["severity_distribution"], styles
                ),
                Spacer(1, 8 * mm),
                Paragraph("Scope and Coverage", styles["SectionTitle"]),
                self._pdf_scope_table(payload, styles),
                Spacer(1, 5 * mm),
                Paragraph(
                    html.escape(
                        payload.get("coverage", {}).get(
                            "interpretation",
                            "Untested endpoints must not be interpreted as secure.",
                        )
                    ),
                    styles["Callout"],
                ),
                Spacer(1, 8 * mm),
                Paragraph("Findings Overview", styles["SectionTitle"]),
                self._pdf_findings_overview(issues, styles),
                PageBreak(),
                Paragraph("Detailed Findings", styles["SectionTitle"]),
                Paragraph(
                    "Repeated endpoint observations are grouped into unique issues below. Every "
                    "affected location is retained. Full per-engine observations and evidence are "
                    "available in the accompanying technical JSON report.",
                    styles["Body"],
                ),
                Spacer(1, 5 * mm),
            ]
        )

        if not issues:
            story.append(
                Paragraph(
                    "No findings were reported. This result must be interpreted together with "
                    "the recorded coverage and scanner limitations.",
                    styles["Callout"],
                )
            )
        for index, finding in enumerate(issues, start=1):
            story.extend(self._pdf_finding(index, finding, styles))

        story.extend(
            [
                PageBreak(),
                Paragraph("Appendix A - Engine and Coverage Detail", styles["SectionTitle"]),
                self._pdf_engine_table(payload.get("coverage", {}).get("engines", {}), styles),
                Spacer(1, 5 * mm),
                Paragraph("Security Check Coverage", styles["Subsection"]),
                self._pdf_security_check_table(
                    payload.get("coverage", {}).get("security_checks", {}), styles
                ),
                Spacer(1, 7 * mm),
                Paragraph("Assessment Limitations", styles["SectionTitle"]),
                Paragraph(
                    "Automated scanners may produce false positives and false negatives. Business "
                    "logic, authorization boundaries, authenticated workflows, and environment-specific "
                    "controls require manual pentester validation. No finding should be treated as "
                    "confirmed solely because it appears in this report.",
                    styles["Body"],
                ),
            ]
        )
        document.build(story, onFirstPage=self._pdf_page, onLaterPages=self._pdf_page)
        return buffer.getvalue()

    def _pdf_styles(self) -> dict[str, ParagraphStyle]:
        base = getSampleStyleSheet()
        return {
            "CoverBrand": ParagraphStyle(
                "CoverBrand",
                parent=base["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=17,
                leading=20,
                textColor=colors.HexColor("#0F766E"),
                spaceAfter=2,
            ),
            "CoverEyebrow": ParagraphStyle(
                "CoverEyebrow",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=10,
                tracking=2,
                textColor=colors.HexColor("#475569"),
            ),
            "CoverTitle": ParagraphStyle(
                "CoverTitle",
                parent=base["Title"],
                fontName="Helvetica-Bold",
                fontSize=30,
                leading=35,
                textColor=colors.HexColor("#0F172A"),
            ),
            "CoverTarget": ParagraphStyle(
                "CoverTarget",
                parent=base["Heading2"],
                fontName="Helvetica",
                fontSize=13,
                leading=18,
                textColor=colors.HexColor("#334155"),
            ),
            "Classification": ParagraphStyle(
                "Classification",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=10,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#991B1B"),
            ),
            "SectionTitle": ParagraphStyle(
                "SectionTitle",
                parent=base["Heading1"],
                fontName="Helvetica-Bold",
                fontSize=17,
                leading=21,
                textColor=colors.HexColor("#0F172A"),
                spaceBefore=4,
                spaceAfter=9,
                keepWithNext=True,
            ),
            "Subsection": ParagraphStyle(
                "Subsection",
                parent=base["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=11,
                leading=14,
                textColor=colors.HexColor("#0F172A"),
                spaceBefore=4,
                spaceAfter=5,
                keepWithNext=True,
            ),
            "FindingTitle": ParagraphStyle(
                "FindingTitle",
                parent=base["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=12,
                leading=15,
                textColor=colors.white,
            ),
            "Body": ParagraphStyle(
                "Body",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=9,
                leading=13,
                textColor=colors.HexColor("#334155"),
                spaceAfter=4,
            ),
            "Small": ParagraphStyle(
                "Small",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10,
                textColor=colors.HexColor("#334155"),
            ),
            "SmallMuted": ParagraphStyle(
                "SmallMuted",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10,
                textColor=colors.HexColor("#64748B"),
            ),
            "TableHeader": ParagraphStyle(
                "TableHeader",
                parent=base["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=9,
                textColor=colors.white,
            ),
            "TableCell": ParagraphStyle(
                "TableCell",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10,
                textColor=colors.HexColor("#1E293B"),
            ),
            "Metric": ParagraphStyle(
                "Metric",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=17,
                leading=19,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#0F172A"),
            ),
            "MetricLabel": ParagraphStyle(
                "MetricLabel",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=7,
                leading=9,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#64748B"),
            ),
            "Callout": ParagraphStyle(
                "Callout",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=8,
                leading=11,
                leftIndent=7,
                rightIndent=7,
                borderColor=colors.HexColor("#0F766E"),
                borderWidth=0,
                borderPadding=7,
                backColor=colors.HexColor("#ECFDF5"),
                textColor=colors.HexColor("#134E4A"),
            ),
            "WarningCallout": ParagraphStyle(
                "WarningCallout",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=8.5,
                leading=12,
                leftIndent=7,
                rightIndent=7,
                borderPadding=8,
                backColor=colors.HexColor("#FEF2F2"),
                textColor=colors.HexColor("#991B1B"),
            ),
            "Code": ParagraphStyle(
                "Code",
                parent=base["Code"],
                fontName="Courier",
                fontSize=6.5,
                leading=8.5,
                backColor=colors.HexColor("#F8FAFC"),
                borderPadding=6,
                textColor=colors.HexColor("#334155"),
            ),
        }

    def _pdf_page(self, canvas: Any, document: Any) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
        canvas.setLineWidth(0.4)
        canvas.line(16 * mm, height - 12 * mm, width - 16 * mm, height - 12 * mm)
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(colors.HexColor("#0F766E"))
        canvas.drawString(16 * mm, height - 9 * mm, "SENTINEL API SECURITY")
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawRightString(width - 16 * mm, height - 9 * mm, "CONFIDENTIAL")
        canvas.line(16 * mm, 12 * mm, width - 16 * mm, 12 * mm)
        canvas.drawString(16 * mm, 8 * mm, "Automated assessment - manual validation required")
        canvas.drawRightString(width - 16 * mm, 8 * mm, f"Page {document.page}")
        canvas.restoreState()

    def _pdf_metadata_table(self, payload: dict, styles: dict[str, ParagraphStyle]) -> Table:
        scan = payload["scan"]
        generated = payload["report_metadata"]["generated_at"]
        data = [
            ["REPORT ID", html.escape(str(scan["id"]))],
            ["GENERATED", html.escape(str(generated))],
            ["SCAN STATUS", html.escape(str(scan["status"]))],
            ["ASSESSMENT PROFILE", html.escape(str(scan["profile"]))],
        ]
        table = Table(
            [[Paragraph(label, styles["TableHeader"]), Paragraph(value, styles["TableCell"])] for label, value in data],
            colWidths=[43 * mm, 112 * mm],
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0F766E")),
                    ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#F8FAFC")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )
        return table

    def _pdf_summary_table(
        self,
        payload: dict,
        overall_risk: str,
        styles: dict[str, ParagraphStyle],
        *,
        unique_issue_count: int | None = None,
    ) -> Table:
        summary = payload["summary"]
        coverage = payload.get("coverage", {})
        percent = coverage.get("runtime_check_summary", coverage.get("security_check_summary", {})).get(
            "percent_attempted",
            coverage.get("endpoints", {}).get("percent_tested", 0),
        )
        assessment_status = _assessment_status(coverage)
        assessment_value = f"{percent}%" if assessment_status == "COMPLETE" else assessment_status
        values = [
            (str(summary["endpoint_count"]), "ENDPOINTS"),
            (
                str(summary["finding_count"] if unique_issue_count is None else unique_issue_count),
                "UNIQUE ISSUES",
            ),
            (assessment_value, "ASSESSMENT"),
            (overall_risk, "MAX OBSERVED RISK"),
        ]
        table = Table(
            [
                [Paragraph(value, styles["Metric"]) for value, _ in values],
                [Paragraph(label, styles["MetricLabel"]) for _, label in values],
            ],
            colWidths=[39 * mm] * 4,
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E2E8F0")),
                    ("TOPPADDING", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 1), (-1, 1), 9),
                ]
            )
        )
        return table

    def _pdf_severity_table(
        self, distribution: dict, styles: dict[str, ParagraphStyle]
    ) -> Table:
        severities = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        cells = [
            [Paragraph(severity, styles["TableHeader"]) for severity in severities],
            [Paragraph(str(distribution.get(severity, 0)), styles["Metric"]) for severity in severities],
        ]
        table = Table(cells, colWidths=[31.2 * mm] * 5)
        style = [
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]
        for column, severity in enumerate(severities):
            style.append(
                ("BACKGROUND", (column, 0), (column, 0), colors.HexColor(SEVERITY_COLORS[severity]))
            )
            style.append(("BACKGROUND", (column, 1), (column, 1), colors.HexColor("#F8FAFC")))
        table.setStyle(TableStyle(style))
        return table

    def _pdf_scope_table(self, payload: dict, styles: dict[str, ParagraphStyle]) -> Table:
        scan = payload["scan"]
        coverage = payload.get("coverage", {})
        endpoints = coverage.get("endpoints", {})
        security = coverage.get("runtime_check_summary", coverage.get("security_check_summary", {}))
        offline = coverage.get("offline_check_summary", {})
        assessment = coverage.get("assessment", {})
        blockers = assessment.get("blocking_reasons", {})
        blocker_text = "; ".join(
            f"{reason} ({count})" for reason, count in list(blockers.items())[:4]
        ) or "None"
        values = [
            ("Target", scan["target"]),
            ("Started", scan.get("started_at") or "Not recorded"),
            ("Finished", scan.get("finished_at") or "Not recorded"),
            ("Duration", f"{scan.get('duration_seconds') or 0:.1f} seconds"),
            ("Assessment completeness", _assessment_status(coverage)),
            (
                "Endpoint reachability",
                f"{endpoints.get('tested', 0)} of {endpoints.get('total', 0)} "
                f"({endpoints.get('percent_tested', 0)}%)",
            ),
            ("Skipped / not tested", f"{endpoints.get('skipped', 0)} / {endpoints.get('not_tested', 0)}"),
            (
                "Runtime checks executed",
                f"{security.get('attempted_endpoint_checks', 0)} of "
                f"{security.get('eligible_endpoint_checks', 0)} "
                f"({security.get('percent_attempted', 0)}%)",
            ),
            (
                "Offline checks evaluated",
                f"{offline.get('attempted_endpoint_checks', 0)} of "
                f"{offline.get('eligible_endpoint_checks', 0)} "
                f"({offline.get('percent_attempted', 0)}%)",
            ),
            ("Blocking reasons", blocker_text),
        ]
        data = [
            [Paragraph("FIELD", styles["TableHeader"]), Paragraph("VALUE", styles["TableHeader"])]
        ]
        data.extend(
            [Paragraph(html.escape(label), styles["TableCell"]), Paragraph(html.escape(str(value)), styles["TableCell"])]
            for label, value in values
        )
        table = Table(data, colWidths=[43 * mm, 113 * mm], repeatRows=1)
        table.setStyle(self._standard_table_style())
        return table

    def _pdf_findings_overview(
        self, findings: list[dict], styles: dict[str, ParagraphStyle]
    ) -> Table:
        data = [
            [
                Paragraph("ID", styles["TableHeader"]),
                Paragraph("SEVERITY", styles["TableHeader"]),
                Paragraph("RISK", styles["TableHeader"]),
                Paragraph("FINDING", styles["TableHeader"]),
                Paragraph("AFFECTED ENDPOINT", styles["TableHeader"]),
            ]
        ]
        for index, finding in enumerate(findings, start=1):
            locations = finding.get("affected_locations") or []
            endpoint = (
                f"{len(locations)} affected location{'s' if len(locations) != 1 else ''}"
                if locations
                else f"{finding.get('method') or ''} {finding.get('endpoint') or 'General'}".strip()
            )
            data.append(
                [
                    Paragraph(f"F-{index:03d}", styles["TableCell"]),
                    Paragraph(html.escape(finding["severity"]), styles["TableCell"]),
                    Paragraph(str(finding["risk_score"]), styles["TableCell"]),
                    Paragraph(html.escape(finding["title"]), styles["TableCell"]),
                    Paragraph(html.escape(endpoint), styles["TableCell"]),
                ]
            )
        if not findings:
            data.append([Paragraph("No findings reported", styles["TableCell"]), "", "", "", ""])
        table = Table(
            data,
            colWidths=[15 * mm, 22 * mm, 13 * mm, 55 * mm, 51 * mm],
            repeatRows=1,
        )
        style = self._standard_table_style().getCommands()
        for row, finding in enumerate(findings, start=1):
            style.append(
                ("TEXTCOLOR", (1, row), (1, row), colors.HexColor(SEVERITY_COLORS.get(finding["severity"], "#334155")))
            )
            style.append(("FONTNAME", (1, row), (1, row), "Helvetica-Bold"))
        table.setStyle(TableStyle(style))
        return table

    def _pdf_finding(
        self, index: int, finding: dict, styles: dict[str, ParagraphStyle]
    ) -> list[Any]:
        severity = finding["severity"]
        color = colors.HexColor(SEVERITY_COLORS.get(severity, "#334155"))
        header = Table(
            [
                [
                    Paragraph(f"F-{index:03d}  {html.escape(finding['title'])}", styles["FindingTitle"]),
                    Paragraph(html.escape(severity), styles["FindingTitle"]),
                ]
            ],
            colWidths=[130 * mm, 26 * mm],
        )
        header.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), color),
                    ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )
        locations = finding.get("affected_locations") or []
        endpoint = (
            f"{len(locations)} affected location{'s' if len(locations) != 1 else ''}"
            if locations
            else f"{finding.get('method') or ''} {finding.get('endpoint') or 'General'}".strip()
        )
        classification_value = finding.get("classification") or {}
        if isinstance(classification_value, dict):
            classification = " | ".join(
                str(classification_value.get(key))
                for key in ("category", "owasp_api", "cwe")
                if classification_value.get(key)
            )
        else:
            classification = " | ".join(
                value
                for value in (
                    finding.get("category"),
                    finding.get("owasp_api"),
                    finding.get("cwe"),
                )
                if value
            )
        parameters = sorted(
            {
                str(location.get("parameter"))
                for location in locations
                if location.get("parameter")
            }
        )
        parameter = ", ".join(parameters) if parameters else finding.get("parameter")
        detected_by = finding.get("detected_by") or finding.get("source_engines") or []
        metadata = Table(
            [
                [
                    Paragraph("Risk score", styles["TableCell"]),
                    Paragraph(str(finding["risk_score"]), styles["TableCell"]),
                    Paragraph("Confidence", styles["TableCell"]),
                    Paragraph(html.escape(finding["confidence"]), styles["TableCell"]),
                ],
                [
                    Paragraph("Affected", styles["TableCell"]),
                    Paragraph(html.escape(endpoint), styles["TableCell"]),
                    Paragraph("Parameter", styles["TableCell"]),
                    Paragraph(html.escape(str(parameter or "Not specified")), styles["TableCell"]),
                ],
                [
                    Paragraph("Classification", styles["TableCell"]),
                    Paragraph(html.escape(classification or "Not mapped"), styles["TableCell"]),
                    Paragraph("Status", styles["TableCell"]),
                    Paragraph(html.escape(finding["status"]), styles["TableCell"]),
                ],
                [
                    Paragraph("Detected by", styles["TableCell"]),
                    Paragraph(html.escape(", ".join(detected_by) or "Not recorded"), styles["TableCell"]),
                    "",
                    "",
                ],
            ],
            colWidths=[24 * mm, 54 * mm, 24 * mm, 54 * mm],
        )
        metadata.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        grouped_evidence = [
            {
                "method": location.get("method"),
                "path": location.get("path"),
                "parameter": location.get("parameter"),
                "evidence": location.get("evidence") or [],
            }
            for location in locations
            if location.get("evidence")
        ]
        evidence = json.dumps(
            grouped_evidence or finding.get("evidence") or [], indent=2, default=str
        )
        if len(evidence) > 5000:
            evidence = evidence[:5000] + "\n... Evidence truncated in PDF; see technical JSON."
        references = finding.get("references") or []
        result: list[Any] = [header, metadata, Spacer(1, 3 * mm)]
        if locations:
            result.extend(
                [
                    Paragraph("Affected Locations", styles["Subsection"]),
                    self._pdf_locations_table(locations, styles),
                    Spacer(1, 3 * mm),
                ]
            )
        for title, content in (
            ("Description", finding["description"]),
            ("Impact", finding["impact"]),
        ):
            result.extend(
                [
                    Paragraph(title, styles["Subsection"]),
                    Paragraph(html.escape(str(content)), styles["Body"]),
                ]
            )
        result.extend(
            [
                Paragraph("Evidence", styles["Subsection"]),
                Paragraph(html.escape(evidence).replace("\n", "<br/>"), styles["Code"]),
                Paragraph("Recommended Remediation", styles["Subsection"]),
                Paragraph(html.escape(str(finding["remediation"])), styles["Body"]),
            ]
        )
        if references:
            result.extend(
                [
                    Paragraph("References", styles["Subsection"]),
                    Paragraph(
                        "<br/>".join(html.escape(str(reference)) for reference in references),
                        styles["Small"],
                    ),
                ]
            )
        result.extend([Spacer(1, 8 * mm)])
        return result

    def _pdf_locations_table(
        self, locations: list[dict], styles: dict[str, ParagraphStyle]
    ) -> Table:
        data = [
            [
                Paragraph("METHOD", styles["TableHeader"]),
                Paragraph("PATH", styles["TableHeader"]),
                Paragraph("PARAMETER", styles["TableHeader"]),
            ]
        ]
        for location in locations:
            data.append(
                [
                    Paragraph(html.escape(str(location.get("method") or "-")), styles["TableCell"]),
                    Paragraph(html.escape(str(location.get("path") or "General")), styles["TableCell"]),
                    Paragraph(
                        html.escape(str(location.get("parameter") or "-")),
                        styles["TableCell"],
                    ),
                ]
            )
        table = Table(data, colWidths=[24 * mm, 92 * mm, 40 * mm], repeatRows=1)
        table.setStyle(self._standard_table_style())
        return table

    def _pdf_engine_table(self, engines: dict, styles: dict[str, ParagraphStyle]) -> Table:
        data = [
            [
                Paragraph("ENGINE", styles["TableHeader"]),
                Paragraph("STATUS", styles["TableHeader"]),
                Paragraph("REQUESTS", styles["TableHeader"]),
                Paragraph("NOTES", styles["TableHeader"]),
            ]
        ]
        for name, detail in sorted(engines.items()):
            data.append(
                [
                    Paragraph(html.escape(name), styles["TableCell"]),
                    Paragraph(html.escape(str(detail.get("status", "unknown"))), styles["TableCell"]),
                    Paragraph(str(detail.get("request_count", 0)), styles["TableCell"]),
                    Paragraph(html.escape(str(detail.get("reason") or "")), styles["TableCell"]),
                ]
            )
        if len(data) == 1:
            data.append([Paragraph("No engine metadata recorded", styles["TableCell"]), "", "", ""])
        table = Table(data, colWidths=[35 * mm, 30 * mm, 22 * mm, 69 * mm], repeatRows=1)
        table.setStyle(self._standard_table_style())
        return table

    def _pdf_security_check_table(
        self, checks: dict, styles: dict[str, ParagraphStyle]
    ) -> Table:
        data = [
            [
                Paragraph("CHECK", styles["TableHeader"]),
                Paragraph("ELIGIBLE", styles["TableHeader"]),
                Paragraph("ATTEMPTED", styles["TableHeader"]),
                Paragraph("DETECTED", styles["TableHeader"]),
                Paragraph("SKIPPED / ERROR", styles["TableHeader"]),
            ]
        ]
        for name, detail in sorted(checks.items()):
            data.append(
                [
                    Paragraph(html.escape(name), styles["TableCell"]),
                    Paragraph(str(detail.get("eligible_endpoints", 0)), styles["TableCell"]),
                    Paragraph(str(detail.get("attempted_endpoints", 0)), styles["TableCell"]),
                    Paragraph(str(detail.get("detected_endpoints", 0)), styles["TableCell"]),
                    Paragraph(
                        f"{detail.get('skipped_endpoints', 0)} / "
                        f"{detail.get('error_endpoints', 0)}",
                        styles["TableCell"],
                    ),
                ]
            )
        if len(data) == 1:
            data.append(
                [Paragraph("No per-check metadata recorded", styles["TableCell"]), "", "", "", ""]
            )
        table = Table(
            data,
            colWidths=[54 * mm, 23 * mm, 25 * mm, 23 * mm, 31 * mm],
            repeatRows=1,
        )
        table.setStyle(self._standard_table_style())
        return table

    def _standard_table_style(self) -> TableStyle:
        return TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )

    def _overall_risk(self, findings: list[dict]) -> str:
        if not findings:
            return "NONE"
        return max(findings, key=lambda item: SEVERITY_ORDER.get(item["severity"], -1))["severity"]
