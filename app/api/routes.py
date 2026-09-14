from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.dependencies import actor_identity, correlation_id, require_api_key
from app.api.serializers import endpoint_dict, finding_dict, scan_dict
from app.core.config import Settings, get_settings
from app.db import get_db
from app.models.database import AuditLog, Finding, Report, Scan, ScanStatus
from app.repositories.scans import ScanRepository, audit
from app.schemas.scans import ScanAccepted, ScanCreate, ScanProfileName
from app.services.scan_service import create_scan
from app.workers.tasks import run_scan

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])


def _get_or_404(db: Session, scan_id: str, *, details: bool = False) -> Scan:
    scan = ScanRepository(db).get(scan_id, details=details)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail={"code": "SCAN_NOT_FOUND", "message": "scan does not exist"},
        )
    return scan


def _dispatch(scan: Scan, db: Session) -> None:
    try:
        run_scan.delay(scan.id)
    except Exception as exc:
        scan.status = ScanStatus.FAILED.value
        scan.error = f"queue dispatch failed: {type(exc).__name__}"
        db.commit()
        raise HTTPException(
            status_code=503,
            detail={
                "code": "QUEUE_UNAVAILABLE",
                "message": "scan was saved but the worker queue is unavailable",
                "scan_id": scan.id,
            },
        ) from exc


@router.post("/scans", response_model=ScanAccepted, status_code=202)
async def submit_scan(
    request: ScanCreate,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    actor: Annotated[str, Depends(actor_identity)],
    request_id: Annotated[str, Depends(correlation_id)],
) -> ScanAccepted:
    scan = await create_scan(db, request, settings, actor=actor, correlation_id=request_id)
    _dispatch(scan, db)
    return ScanAccepted(
        scan_id=scan.id,
        status=scan.status,
        status_url=f"/api/v1/scans/{scan.id}/status",
    )


@router.post("/scans/from-file", response_model=ScanAccepted, status_code=202)
async def submit_scan_file(
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    actor: Annotated[str, Depends(actor_identity)],
    request_id: Annotated[str, Depends(correlation_id)],
    target_url: Annotated[str, Form()],
    authorized: Annotated[bool, Form()],
    specification: Annotated[UploadFile, File()],
    profile: Annotated[ScanProfileName, Form()] = ScanProfileName.STANDARD,
    project_name: Annotated[str, Form(max_length=200)] = "Default",
    external_project_id: Annotated[str | None, Form(max_length=200)] = None,
    authorization_reference: Annotated[str | None, Form(max_length=500)] = None,
) -> ScanAccepted:
    if not authorized:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "AUTHORIZATION_REQUIRED",
                "message": "explicit target authorization is required",
            },
        )
    content = await specification.read(settings.max_spec_size + 1)
    if len(content) > settings.max_spec_size:
        raise HTTPException(
            status_code=413,
            detail={"code": "SPEC_TOO_LARGE", "message": "specification exceeds MAX_SPEC_SIZE"},
        )
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_SPEC", "message": "specification must be UTF-8 JSON or YAML"},
        ) from exc
    request = ScanCreate(
        target_url=target_url,
        authorized=True,
        profile=profile,
        specification=text,
        project_name=project_name,
        external_project_id=external_project_id,
        authorization_reference=authorization_reference,
    )
    scan = await create_scan(db, request, settings, actor=actor, correlation_id=request_id)
    _dispatch(scan, db)
    return ScanAccepted(
        scan_id=scan.id, status=scan.status, status_url=f"/api/v1/scans/{scan.id}/status"
    )


@router.get("/scans")
def scan_history(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    scans, total = ScanRepository(db).list(limit, offset)
    return {
        "items": [scan_dict(scan) for scan in scans],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, db: Annotated[Session, Depends(get_db)]) -> dict:
    return scan_dict(_get_or_404(db, scan_id))


@router.get("/scans/{scan_id}/status")
def get_status(scan_id: str, db: Annotated[Session, Depends(get_db)]) -> dict:
    scan = _get_or_404(db, scan_id)
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "progress": scan.progress,
        "stage": scan.stage,
        "error": scan.error,
        "terminal": scan.status in {"COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "TIMEOUT"},
    }


@router.get("/scans/{scan_id}/endpoints")
def get_endpoints(
    scan_id: str,
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    _get_or_404(db, scan_id)
    values, total = ScanRepository(db).endpoints(scan_id, limit, offset)
    return {
        "items": [endpoint_dict(value) for value in values],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/scans/{scan_id}/findings")
def get_findings(
    scan_id: str,
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    _get_or_404(db, scan_id)
    values, total = ScanRepository(db).findings(scan_id, limit, offset)
    return {
        "items": [finding_dict(value) for value in values],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/scans/{scan_id}/findings/{finding_id}")
def get_finding(scan_id: str, finding_id: str, db: Annotated[Session, Depends(get_db)]) -> dict:
    _get_or_404(db, scan_id)
    finding = db.scalar(
        select(Finding)
        .options(selectinload(Finding.evidence))
        .where(Finding.scan_id == scan_id, Finding.id == finding_id)
    )
    if not finding:
        raise HTTPException(
            status_code=404,
            detail={"code": "FINDING_NOT_FOUND", "message": "finding does not exist"},
        )
    return finding_dict(finding)


@router.get("/scans/{scan_id}/coverage")
def get_coverage(scan_id: str, db: Annotated[Session, Depends(get_db)]) -> dict:
    scan = _get_or_404(db, scan_id)
    coverage = (scan.result_summary or {}).get("coverage")
    if coverage is None:
        return {"available": False, "reason": "coverage is calculated during reporting"}
    return {"available": True, **coverage}


@router.get("/scans/{scan_id}/reports")
def list_reports(scan_id: str, db: Annotated[Session, Depends(get_db)]) -> dict:
    _get_or_404(db, scan_id)
    reports = list(db.scalars(select(Report).where(Report.scan_id == scan_id)))
    return {
        "items": [
            {
                "format": report.format,
                "sha256": report.sha256,
                "download_url": f"/api/v1/scans/{scan_id}/report?format={report.format.lower()}",
            }
            for report in reports
        ]
    }


@router.get("/scans/{scan_id}/report")
def download_report(
    scan_id: str,
    db: Annotated[Session, Depends(get_db)],
    format: Annotated[str, Query(pattern="^(json|technical_json|html|pdf)$")] = "json",
) -> FileResponse:
    _get_or_404(db, scan_id)
    report = db.scalar(
        select(Report).where(Report.scan_id == scan_id, Report.format == format.upper())
    )
    if not report:
        raise HTTPException(
            status_code=409,
            detail={"code": "REPORT_NOT_READY", "message": "the requested report is not available"},
        )
    media_types = {
        "json": "application/json",
        "technical_json": "application/json",
        "html": "text/html",
        "pdf": "application/pdf",
    }
    extensions = {
        "json": "json",
        "technical_json": "technical.json",
        "html": "html",
        "pdf": "pdf",
    }
    return FileResponse(
        report.path,
        media_type=media_types[format],
        filename=f"api-scan-{scan_id}.{extensions[format]}",
    )


def _control(
    db: Session,
    scan_id: str,
    action: str,
    actor: str,
    request_id: str,
) -> dict:
    scan = _get_or_404(db, scan_id)
    terminal = {"COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "TIMEOUT"}
    if scan.status in terminal:
        raise HTTPException(
            status_code=409,
            detail={"code": "TERMINAL_SCAN", "message": f"cannot {action} a terminal scan"},
        )
    if action == "cancel":
        scan.cancel_requested = True
        if scan.status == ScanStatus.QUEUED.value:
            scan.status = ScanStatus.CANCELLED.value
            scan.stage = "cancelled before execution"
            from app.models.database import utcnow

            scan.finished_at = utcnow()
    elif action == "pause":
        scan.pause_requested = True
    elif action == "resume":
        scan.pause_requested = False
    audit(
        db,
        actor=actor,
        action=f"scan.{action}",
        resource_type="scan",
        resource_id=scan.id,
        correlation_id=request_id,
    )
    db.commit()
    return {"scan_id": scan.id, "status": scan.status, f"{action}_requested": True}


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
    db: Annotated[Session, Depends(get_db)],
    actor: Annotated[str, Depends(actor_identity)],
    request_id: Annotated[str, Depends(correlation_id)],
) -> dict:
    return _control(db, scan_id, "cancel", actor, request_id)


@router.post("/scans/{scan_id}/pause")
def pause_scan(
    scan_id: str,
    db: Annotated[Session, Depends(get_db)],
    actor: Annotated[str, Depends(actor_identity)],
    request_id: Annotated[str, Depends(correlation_id)],
) -> dict:
    return _control(db, scan_id, "pause", actor, request_id)


@router.post("/scans/{scan_id}/resume")
def resume_scan(
    scan_id: str,
    db: Annotated[Session, Depends(get_db)],
    actor: Annotated[str, Depends(actor_identity)],
    request_id: Annotated[str, Depends(correlation_id)],
) -> dict:
    return _control(db, scan_id, "resume", actor, request_id)


@router.get("/audit-logs")
def audit_logs(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    values = list(
        db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset))
    )
    return {
        "items": [
            {
                "timestamp": value.timestamp,
                "actor": value.actor,
                "action": value.action,
                "resource_type": value.resource_type,
                "resource_id": value.resource_id,
                "correlation_id": value.correlation_id,
                "metadata": value.metadata_json,
            }
            for value in values
        ]
    }
