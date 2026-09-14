import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from redis import Redis
from sqlalchemy import text
from starlette.responses import Response

from app.api.routes import router
from app.core.config import get_settings
from app.core.logging import configure_logging, logger
from app.db import SessionLocal, create_schema

settings = get_settings()
REQUESTS = Counter("scanner_http_requests_total", "HTTP requests", ["method", "path", "status"])
LATENCY = Histogram(
    "scanner_http_request_duration_seconds", "HTTP request latency", ["method", "path"]
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging(settings.log_level)
    if settings.environment in {"development", "test"}:
        create_schema()
    yield


app = FastAPI(
    title="Enterprise API Security Scanner",
    version="0.1.0",
    description="Authorized, scope-controlled API security assessment module. Automated results require validation.",
    lifespan=lifespan,
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))[:100]
    request.state.correlation_id = correlation_id
    started = time.monotonic()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("request_failed", request_id=correlation_id, path=request.url.path)
        raise
    duration = time.monotonic() - started
    response.headers["X-Correlation-ID"] = correlation_id
    path = request.scope.get("route").path if request.scope.get("route") else request.url.path
    REQUESTS.labels(request.method, path, response.status_code).inc()
    LATENCY.labels(request.method, path).observe(duration)
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "request validation failed",
                "details": exc.errors(),
            }
        },
    )


@app.exception_handler(HTTPException)
async def http_error_handler(_: Request, exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict):
        error = exc.detail
    else:
        error = {"code": f"HTTP_{exc.status_code}", "message": str(exc.detail)}
    return JSONResponse(status_code=exc.status_code, content={"error": error}, headers=exc.headers)


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception(
        "unhandled_api_error",
        request_id=request.state.correlation_id,
        error_type=type(exc).__name__,
    )
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "INTERNAL_ERROR", "message": "an internal error occurred"}},
    )


@app.get("/health", tags=["observability"])
def health() -> dict:
    return {"status": "healthy", "version": app.version}


@app.get("/ready", tags=["observability"])
def ready() -> JSONResponse:
    checks: dict[str, str] = {}
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        checks["database"] = "ready"
    except Exception:
        checks["database"] = "unavailable"
    if settings.task_always_eager:
        checks["queue"] = "eager"
    else:
        try:
            Redis.from_url(settings.redis_url, socket_timeout=1).ping()
            checks["queue"] = "ready"
        except Exception:
            checks["queue"] = "unavailable"
    ok = all(value in {"ready", "eager"} for value in checks.values())
    return JSONResponse(
        status_code=200 if ok else 503,
        content={"status": "ready" if ok else "not_ready", "checks": checks},
    )


@app.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/ui-config", include_in_schema=False)
def ui_config() -> dict:
    """Expose non-secret browser integration settings."""
    return {
        "auth_mode": settings.dashboard_auth_mode,
        "target_scope_mode": settings.target_scope_mode,
        "authorization_reference_required": settings.target_scope_mode == "platform_managed",
    }


app.include_router(router)
static_directory = Path(__file__).parent / "static"
app.mount("/", StaticFiles(directory=static_directory, html=True), name="dashboard")
