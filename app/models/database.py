import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


class ScanStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    INITIALIZING = "INITIALIZING"
    DISCOVERING = "DISCOVERING"
    SCANNING = "SCANNING"
    CORRELATING = "CORRELATING"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    PAUSED = "PAUSED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Project(Base, TimestampMixin):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(200), index=True)


class Target(Base, TimestampMixin):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    base_url: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_hosts: Mapped[list] = mapped_column(JSON, default=list)
    confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ScanProfile(Base, TimestampMixin):
    __tablename__ = "scan_profiles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(30), unique=True)
    configuration: Mapped[dict] = mapped_column(JSON, default=dict)


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True)
    profile: Mapped[str] = mapped_column(String(30), default="STANDARD")
    status: Mapped[str] = mapped_column(String(30), default=ScanStatus.QUEUED.value, index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    stage: Mapped[str] = mapped_column(String(100), default="queued")
    request_config: Mapped[dict] = mapped_column(JSON, default=dict)
    result_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    pause_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    target: Mapped["Target"] = relationship()
    endpoints: Mapped[list["Endpoint"]] = relationship(cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(cascade="all, delete-orphan")


class ScanEngine(Base, TimestampMixin):
    __tablename__ = "scan_engines"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    name: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(30))
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str | None] = mapped_column(Text)
    raw_result: Mapped[dict | list | None] = mapped_column(JSON)


class ApiSpecification(Base, TimestampMixin):
    __tablename__ = "api_specifications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    version: Mapped[str] = mapped_column(String(30))
    source: Mapped[str] = mapped_column(String(30))
    sha256: Mapped[str] = mapped_column(String(64))
    document: Mapped[dict] = mapped_column(JSON)


class Endpoint(Base, TimestampMixin):
    __tablename__ = "endpoints"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    endpoint_id: Mapped[str] = mapped_column(String(64), index=True)
    base_url: Mapped[str] = mapped_column(Text)
    path: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(10))
    operation_id: Mapped[str | None] = mapped_column(String(300))
    tags: Mapped[list] = mapped_column(JSON, default=list)
    parameters: Mapped[list] = mapped_column(JSON, default=list)
    request_body: Mapped[dict | None] = mapped_column(JSON)
    responses: Mapped[dict] = mapped_column(JSON, default=dict)
    content_types: Mapped[list] = mapped_column(JSON, default=list)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(50))
    confidence: Mapped[str] = mapped_column(String(20), default="HIGH")
    test_status: Mapped[str] = mapped_column(String(30), default="PENDING")
    skip_reason: Mapped[str | None] = mapped_column(Text)


class AuthenticationProfile(Base, TimestampMixin):
    __tablename__ = "authentication_profiles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    auth_type: Mapped[str] = mapped_column(String(30))
    encrypted_config: Mapped[str] = mapped_column(Text)


class Identity(Base, TimestampMixin):
    __tablename__ = "identities"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(100), default="user")
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    resource_ids: Mapped[list] = mapped_column(JSON, default=list)
    encrypted_auth: Mapped[str] = mapped_column(Text)


class HttpRequestRecord(Base, TimestampMixin):
    __tablename__ = "requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    engine: Mapped[str] = mapped_column(String(50))
    method: Mapped[str] = mapped_column(String(10))
    url: Mapped[str] = mapped_column(Text)
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    body: Mapped[str | None] = mapped_column(Text)


class HttpResponseRecord(Base, TimestampMixin):
    __tablename__ = "responses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(ForeignKey("requests.id"), index=True)
    status_code: Mapped[int] = mapped_column(Integer)
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    body: Mapped[str | None] = mapped_column(Text)
    elapsed_ms: Mapped[float | None] = mapped_column(Float)


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    finding_type: Mapped[str] = mapped_column(String(30))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(100), index=True)
    owasp_api: Mapped[str | None] = mapped_column(String(100))
    cwe: Mapped[str | None] = mapped_column(String(30))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    confidence: Mapped[str] = mapped_column(String(20))
    risk_score: Mapped[float] = mapped_column(Float)
    endpoint: Mapped[str | None] = mapped_column(Text)
    method: Mapped[str | None] = mapped_column(String(10))
    parameter: Mapped[str | None] = mapped_column(String(200))
    source_engines: Mapped[list] = mapped_column(JSON, default=list)
    impact: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(30), default=FindingStatus.OPEN.value)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    evidence: Mapped[list["FindingEvidence"]] = relationship(cascade="all, delete-orphan")


class FindingEvidence(Base, TimestampMixin):
    __tablename__ = "finding_evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    engine: Mapped[str] = mapped_column(String(50))
    request: Mapped[dict | None] = mapped_column(JSON)
    response: Mapped[dict | None] = mapped_column(JSON)
    detail: Mapped[str | None] = mapped_column(Text)


class FindingSource(Base, TimestampMixin):
    __tablename__ = "finding_sources"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    engine: Mapped[str] = mapped_column(String(50))
    external_id: Mapped[str | None] = mapped_column(String(300))
    raw_result: Mapped[dict] = mapped_column(JSON, default=dict)


class FindingRelationship(Base, TimestampMixin):
    __tablename__ = "finding_relationships"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    target_finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    relationship: Mapped[str] = mapped_column(String(50))


class Report(Base, TimestampMixin):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    format: Mapped[str] = mapped_column(String(20))
    path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(100))
    resource_id: Mapped[str | None] = mapped_column(String(100))
    correlation_id: Mapped[str | None] = mapped_column(String(100), index=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
