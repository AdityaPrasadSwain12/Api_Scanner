from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import redact
from app.core.secrets import SecretStore
from app.ingestion.discovery import fetch_specification
from app.ingestion.openapi import IngestionError, parse_api_document
from app.models.database import AuthenticationProfile, Identity, Project, Scan, Target, utcnow
from app.repositories.scans import audit
from app.schemas.scans import ScanCreate
from app.security.scope import ScopedHttpClient, ScopeGuard, ScopeViolation, _host_matches


def effective_allowed_hosts(request: ScanCreate, settings: Settings) -> list[str]:
    target_host = (urlsplit(str(request.target_url)).hostname or "").lower().rstrip(".")
    requested = [target_host, *[item.lower().rstrip(".") for item in request.policy.allowed_hosts]]
    requested = list(dict.fromkeys(requested))
    if settings.target_scope_mode == "platform_managed":
        missing = []
        if not request.external_project_id:
            missing.append("external_project_id")
        if not request.authorization_reference:
            missing.append("authorization_reference")
        if missing:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "PLATFORM_AUTHORIZATION_REQUIRED",
                    "message": (
                        "platform-managed targets require trusted project and authorization "
                        f"references: {', '.join(missing)}"
                    ),
                },
            )
    elif settings.allowed_targets:
        outside = [
            host
            for host in requested
            if not any(
                _host_matches(host.lstrip("*."), global_rule) or host == global_rule
                for global_rule in settings.allowed_targets
            )
        ]
        if outside:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "SCOPE_VIOLATION",
                    "message": f"hosts outside deployment allowlist: {outside}",
                },
            )
    return requested


async def create_scan(
    db: Session,
    request: ScanCreate,
    settings: Settings,
    *,
    actor: str,
    correlation_id: str,
) -> Scan:
    allowed_hosts = effective_allowed_hosts(request, settings)
    guard = ScopeGuard(allowed_hosts, allow_private=settings.allow_private_targets)
    try:
        await guard.validate(str(request.target_url))
        if request.specification_url:
            await guard.validate(str(request.specification_url))
    except ScopeViolation as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "SCOPE_VIOLATION", "message": str(exc)},
        ) from exc

    # Reject malformed documents and server URLs outside the authorized target scope before
    # a scan is queued. The worker repeats these checks to protect against DNS or document
    # changes between submission and execution.
    try:
        inventory = None
        if request.specification is not None:
            inventory = parse_api_document(
                request.specification, str(request.target_url), settings.max_spec_size
            )
        elif request.specification_url is not None:
            client = ScopedHttpClient(
                guard,
                timeout=settings.request_timeout,
                max_response_size=settings.max_response_size,
            )
            inventory = await fetch_specification(
                client,
                str(request.specification_url),
                settings.max_spec_size,
                str(request.target_url),
            )
        if inventory:
            for base_url in inventory.base_urls:
                await guard.validate(base_url)
    except IngestionError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_API_DOCUMENT", "message": str(exc)},
        ) from exc
    except ScopeViolation as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "SPEC_TARGET_MISMATCH",
                "message": f"the API document points outside the authorized target: {exc}",
            },
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "API_DOCUMENT_UNREACHABLE",
                "message": f"the API document could not be verified: {type(exc).__name__}",
            },
        ) from exc
    project = None
    if request.external_project_id:
        project = db.scalar(
            select(Project).where(Project.external_id == request.external_project_id)
        )
    if project is None:
        project = Project(name=request.project_name, external_id=request.external_project_id)
        db.add(project)
        db.flush()
    target = Target(
        project_id=project.id,
        base_url=str(request.target_url),
        allowed_hosts=allowed_hosts,
        confirmed_at=utcnow(),
    )
    db.add(target)
    db.flush()
    request_data = request.model_dump(
        mode="json", exclude={"authentication", "identities", "specification", "postman_collection"}
    )
    request_data["has_inline_specification"] = request.specification is not None
    request_data["has_postman_collection"] = request.postman_collection is not None
    # The source documents live in the specification row; credentials are encrypted separately.
    scan = Scan(
        project_id=project.id,
        target_id=target.id,
        profile=request.profile.value,
        request_config=redact(request_data),
    )
    db.add(scan)
    db.flush()
    secret_store = SecretStore(
        settings.secret_encryption_key, allow_ephemeral=settings.environment != "production"
    )
    if request.authentication:
        db.add(
            AuthenticationProfile(
                scan_id=scan.id,
                auth_type=request.authentication.type.value,
                encrypted_config=secret_store.encrypt(
                    request.authentication.model_dump(mode="json")
                ),
            )
        )
    for identity in request.identities:
        db.add(
            Identity(
                scan_id=scan.id,
                name=identity.name,
                role=identity.role,
                is_admin=identity.is_admin,
                resource_ids=identity.resource_ids,
                encrypted_auth=secret_store.encrypt(identity.auth.model_dump(mode="json")),
            )
        )
    # Temporarily retain ingestion input encrypted; it is consumed then removed by the worker.
    ingestion_payload = {
        "specification": request.specification,
        "postman_collection": request.postman_collection,
    }
    if request.specification is not None or request.postman_collection is not None:
        db.add(
            AuthenticationProfile(
                scan_id=scan.id,
                auth_type="_INGESTION_PAYLOAD",
                encrypted_config=secret_store.encrypt(ingestion_payload),
            )
        )
    audit(
        db,
        actor=actor,
        action="scan.created",
        resource_type="scan",
        resource_id=scan.id,
        correlation_id=correlation_id,
        metadata={
            "target_host": urlsplit(target.base_url).hostname,
            "profile": scan.profile,
            "external_project_id": request.external_project_id,
            "authorization_reference": request.authorization_reference,
        },
    )
    db.commit()
    return scan
