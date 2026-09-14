import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ParameterDefinition(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    location: Literal["path", "query", "header", "cookie"]
    required: bool = False
    schema_: dict[str, Any] = Field(default_factory=dict, alias="schema")
    example: Any = None


class EndpointDefinition(BaseModel):
    endpoint_id: str
    base_url: str
    path: str
    method: str
    operation_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    parameters: list[ParameterDefinition] = Field(default_factory=list)
    request_body: dict[str, Any] | None = None
    responses: dict[str, Any] = Field(default_factory=dict)
    content_types: list[str] = Field(default_factory=list)
    auth_required: bool = False
    source: str
    confidence: Literal["LOW", "MEDIUM", "HIGH"] = "HIGH"

    @classmethod
    def build_id(cls, base_url: str, path: str, method: str) -> str:
        canonical = f"{base_url.rstrip('/')}|{path}|{method.upper()}"
        return hashlib.sha256(canonical.encode()).hexdigest()[:32]


class EvidenceDraft(BaseModel):
    engine: str
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    detail: str | None = None


class FindingDraft(BaseModel):
    finding_type: Literal["SPECIFICATION", "RUNTIME", "DISCOVERY", "AUTHORIZATION"]
    title: str
    description: str
    category: str
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    endpoint: str | None = None
    method: str | None = None
    parameter: str | None = None
    owasp_api: str | None = None
    cwe: str | None = None
    source_engine: str
    impact: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    evidence: list[EvidenceDraft] = Field(default_factory=list)
    external_id: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    def fingerprint(self) -> str:
        values = [
            (self.endpoint or "").rstrip("/").lower(),
            (self.method or "").upper(),
            (self.parameter or "").lower(),
            self.category.lower(),
        ]
        return hashlib.sha256("|".join(values).encode()).hexdigest()


class EngineResult(BaseModel):
    engine: str
    status: Literal["COMPLETED", "FAILED", "SKIPPED", "TIMEOUT", "CANCELLED"]
    findings: list[FindingDraft] = Field(default_factory=list)
    raw: dict[str, Any] | list[Any] | None = None
    request_count: int = 0
    duration_seconds: float = 0
    reason: str | None = None


class ScanLimits(BaseModel):
    rate_limit: float
    concurrency: int
    request_timeout: float
    max_requests: int
    max_duration: int


class ScanContext(BaseModel):
    scan_id: str
    target_url: str
    allowed_hosts: list[str]
    profile: str
    limits: ScanLimits
    endpoints: list[EndpointDefinition]
    specification: dict[str, Any] | None = None
    auth: dict[str, Any] | None = None
    identities: list[dict[str, Any]] = Field(default_factory=list)


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
