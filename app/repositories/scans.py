from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.database import AuditLog, Endpoint, Finding, Scan, ScanEngine


class ScanRepository:
    def __init__(self, db: Session):
        self.db = db

    def get(self, scan_id: str, *, details: bool = False) -> Scan | None:
        statement = select(Scan).options(selectinload(Scan.target)).where(Scan.id == scan_id)
        if details:
            statement = statement.options(
                selectinload(Scan.findings).selectinload(Finding.evidence),
                selectinload(Scan.endpoints),
            )
        return self.db.scalar(statement)

    def list(self, limit: int, offset: int) -> tuple[list[Scan], int]:
        total = self.db.scalar(select(func.count()).select_from(Scan)) or 0
        scans = list(
            self.db.scalars(
                select(Scan)
                .options(selectinload(Scan.target))
                .order_by(Scan.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        return scans, total

    def engines(self, scan_id: str) -> list[ScanEngine]:
        return list(self.db.scalars(select(ScanEngine).where(ScanEngine.scan_id == scan_id)))

    def endpoints(self, scan_id: str, limit: int, offset: int) -> tuple[list[Endpoint], int]:
        base = Endpoint.scan_id == scan_id
        total = self.db.scalar(select(func.count()).select_from(Endpoint).where(base)) or 0
        values = list(
            self.db.scalars(
                select(Endpoint)
                .where(base)
                .order_by(Endpoint.path, Endpoint.method)
                .limit(limit)
                .offset(offset)
            )
        )
        return values, total

    def findings(self, scan_id: str, limit: int, offset: int) -> tuple[list[Finding], int]:
        base = Finding.scan_id == scan_id
        total = self.db.scalar(select(func.count()).select_from(Finding).where(base)) or 0
        values = list(
            self.db.scalars(
                select(Finding)
                .options(selectinload(Finding.evidence))
                .where(base)
                .order_by(Finding.risk_score.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        return values, total


def audit(
    db: Session,
    *,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    correlation_id: str | None,
    metadata: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            correlation_id=correlation_id,
            metadata_json=metadata or {},
        )
    )
