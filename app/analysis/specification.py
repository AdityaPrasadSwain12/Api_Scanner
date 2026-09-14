from typing import Any

from app.domain import EvidenceDraft, FindingDraft


def _finding(
    title: str,
    category: str,
    severity: str,
    description: str,
    remediation: str,
    *,
    endpoint: str | None = None,
    method: str | None = None,
    parameter: str | None = None,
    owasp: str | None = None,
    cwe: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> FindingDraft:
    return FindingDraft(
        finding_type="SPECIFICATION",
        title=title,
        description=description,
        category=category,
        severity=severity,
        confidence="HIGH",
        endpoint=endpoint,
        method=method,
        parameter=parameter,
        owasp_api=owasp,
        cwe=cwe,
        source_engine="specification",
        impact="The API contract permits or documents behavior that weakens its security posture.",
        remediation=remediation,
        evidence=[EvidenceDraft(engine="specification", detail=str(evidence or {}))],
    )


def analyze_specification(document: dict[str, Any]) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    version3 = "openapi" in document
    security_schemes = (
        document.get("components", {}).get("securitySchemes", {})
        if version3
        else document.get("securityDefinitions", {})
    )
    if not security_schemes:
        findings.append(
            _finding(
                "API specification defines no authentication scheme",
                "missing-authentication-scheme",
                "MEDIUM",
                "No reusable security scheme is declared in the API specification.",
                "Define the supported authentication mechanism and apply security requirements explicitly.",
                owasp="API2:2023 Broken Authentication",
                cwe="CWE-306",
            )
        )
    for server in document.get("servers", []):
        url = server.get("url", "") if isinstance(server, dict) else ""
        if str(url).lower().startswith("http://"):
            findings.append(
                _finding(
                    "Insecure HTTP server in API specification",
                    "insecure-transport",
                    "HIGH",
                    f"The specification declares an unencrypted server: {url}",
                    "Publish and enforce an HTTPS server URL.",
                    cwe="CWE-319",
                    evidence={"server": url},
                )
            )
    if str(document.get("swagger")) == "2.0" and "http" in document.get("schemes", []):
        findings.append(
            _finding(
                "Insecure HTTP scheme in Swagger specification",
                "insecure-transport",
                "HIGH",
                "The Swagger schemes list includes cleartext HTTP.",
                "Remove HTTP and require HTTPS.",
                cwe="CWE-319",
            )
        )

    root_security = document.get("security")
    for path, path_item in document.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in {
                "get",
                "put",
                "post",
                "delete",
                "options",
                "head",
                "patch",
                "trace",
            }:
                continue
            if not isinstance(operation, dict):
                continue
            if operation.get("deprecated") is True:
                findings.append(
                    _finding(
                        "Deprecated API operation remains exposed",
                        "deprecated-endpoint",
                        "LOW",
                        "The API contract marks this operation as deprecated.",
                        "Remove the operation after a controlled migration or document compensating controls.",
                        endpoint=path,
                        method=method.upper(),
                        owasp="API9:2023 Improper Inventory Management",
                    )
                )
            security = operation.get("security", root_security)
            if security == []:
                findings.append(
                    _finding(
                        "Operation explicitly disables authentication",
                        "missing-authentication",
                        "MEDIUM",
                        "This operation overrides global security with an empty security requirement.",
                        "Confirm public access is intended; otherwise apply an authentication requirement.",
                        endpoint=path,
                        method=method.upper(),
                        owasp="API2:2023 Broken Authentication",
                        cwe="CWE-306",
                    )
                )
            for parameter in [*path_item.get("parameters", []), *operation.get("parameters", [])]:
                if not isinstance(parameter, dict) or "$ref" in parameter:
                    continue
                schema = parameter.get("schema", parameter)
                if schema.get("type") == "string" and not any(
                    key in schema for key in ("maxLength", "enum", "pattern", "format")
                ):
                    findings.append(
                        _finding(
                            "String parameter has no input constraint",
                            "weak-schema-constraint",
                            "LOW",
                            "A string input has no maximum length, format, pattern, or enumeration.",
                            "Add a schema constraint appropriate to the business value.",
                            endpoint=path,
                            method=method.upper(),
                            parameter=str(parameter.get("name", "unknown")),
                            owasp="API4:2023 Unrestricted Resource Consumption",
                            cwe="CWE-20",
                        )
                    )
    return findings
