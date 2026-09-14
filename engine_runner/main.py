import asyncio
import hmac
import json
import math
import os
import re
import resource
import secrets
import signal
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.security.scope import ScopedHttpClient, ScopeGuard, ScopeViolation

ENGINE = os.getenv("ENGINE", "").lower()
RUNNER_TOKEN = os.getenv("ENGINE_RUNNER_TOKEN", "")
ALLOW_PRIVATE = os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"
MAX_OUTPUT = int(os.getenv("ENGINE_MAX_OUTPUT", str(5 * 1024 * 1024)))
MAX_PROXY_BODY = int(os.getenv("ENGINE_MAX_PROXY_BODY", str(2 * 1024 * 1024)))
RUNNER_INTERNAL_URL = os.getenv("RUNNER_INTERNAL_URL", "http://127.0.0.1:8093")

# A bounded, API-focused subset of the pinned official template bundle. Running
# entire web-technology directories makes a request budget unpredictable and is
# inappropriate for an API scanner that promises a hard operational ceiling.
NUCLEI_API_TEMPLATES = (
    "/opt/nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml",
    "/opt/nuclei-templates/http/vulnerabilities/generic/cors-misconfig.yaml",
    "/opt/nuclei-templates/http/misconfiguration/database-error.yaml",
    "/opt/nuclei-templates/http/misconfiguration/express-stack-trace.yaml",
    "/opt/nuclei-templates/http/misconfiguration/dont-panic-traceback.yaml",
    "/opt/nuclei-templates/http/exposures/apis/openapi.yaml",
    "/opt/nuclei-templates/http/exposures/apis/swagger-api.yaml",
    "/opt/nuclei-templates/http/exposures/apis/redoc-api-docs.yaml",
    "/opt/nuclei-templates/http/exposures/configs/git-config.yaml",
    "/opt/nuclei-templates/http/exposures/configs/htpasswd-detection.yaml",
    "/opt/nuclei-templates/http/exposures/configs/aws-credentials.yaml",
    "/opt/nuclei-templates/http/exposures/configs/dockerfile-hidden-disclosure.yaml",
    "/opt/nuclei-templates/http/exposures/logs/access-log-file.yaml",
)


class RunRequest(BaseModel):
    target_url: str = Field(max_length=2048)
    endpoints: list[dict[str, Any]] = Field(default_factory=list, max_length=10_000)
    specification: dict[str, Any] | None = None
    profile: str
    rate_limit: float = Field(ge=0.1, le=1000)
    concurrency: int = Field(ge=1, le=100)
    request_timeout: float = Field(ge=1, le=120)
    max_requests: int = Field(ge=1, le=100_000)
    max_duration: int = Field(ge=1, le=86_400)
    allowed_hosts: list[str] = Field(min_length=1, max_length=100)
    authentication: dict[str, Any] | None = None


app = FastAPI(title=f"{ENGINE or 'security-tool'} isolated runner", docs_url=None, redoc_url=None)


@dataclass
class ProxyJob:
    target_url: str
    allowed_hosts: list[str]
    rate_limit: float
    max_requests: int
    request_timeout: float
    count: int = 0
    last_request: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def take(self) -> None:
        async with self.lock:
            if self.count >= self.max_requests:
                raise HTTPException(status_code=429, detail="engine request budget exhausted")
            delay = max(0.0, (1 / self.rate_limit) - (time.monotonic() - self.last_request))
            if delay:
                await asyncio.sleep(delay)
            self.count += 1
            self.last_request = time.monotonic()


PROXY_JOBS: dict[str, ProxyJob] = {}
HOP_BY_HOP = {
    "connection",
    "content-encoding",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def _authenticate(value: str | None) -> None:
    if not RUNNER_TOKEN or not value or not hmac.compare_digest(RUNNER_TOKEN, value):
        raise HTTPException(status_code=401, detail="invalid runner token")


def _limit_child(duration: int) -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (duration + 5, duration + 10))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024**2, 64 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))


async def _run_process(arguments: list[str], cwd: str, timeout: int) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_exec(
        *arguments,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": cwd,
            "NO_COLOR": "1",
        },
        start_new_session=True,
        preexec_fn=lambda: _limit_child(timeout),
    )
    try:
        stdout_task = asyncio.create_task(process.stdout.read(MAX_OUTPUT + 1))
        stderr_task = asyncio.create_task(process.stderr.read(MAX_OUTPUT + 1))
        stdout, stderr = await asyncio.wait_for(
            asyncio.gather(stdout_task, stderr_task), timeout=timeout
        )
        if len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT:
            os.killpg(process.pid, signal.SIGKILL)
            await process.wait()
            raise ValueError("engine output exceeded limit")
        return (
            await process.wait(),
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )
    except TimeoutError:
        os.killpg(process.pid, signal.SIGKILL)
        await process.wait()
        raise


def _nuclei_command(request: RunRequest, directory: Path) -> tuple[list[str], Path]:
    output = directory / "nuclei.jsonl"
    if request.rate_limit >= 1:
        rate_count = max(1, int(request.rate_limit))
        rate_window = "1s"
    else:
        rate_count = 1
        rate_window = f"{math.ceil(1 / request.rate_limit)}s"
    command = [
        "nuclei",
        "-u",
        request.target_url,
        "-jsonl-export",
        str(output),
        "-silent",
        "-disable-update-check",
        "-disable-redirects",
        "-rate-limit",
        str(rate_count),
        "-rate-limit-duration",
        rate_window,
        "-bulk-size",
        str(request.concurrency),
        "-timeout",
        str(int(request.request_timeout)),
        "-no-interactsh",
    ]
    for template in NUCLEI_API_TEMPLATES:
        command.extend(["-templates", template])
    auth_headers = _authentication_headers(request.authentication)
    for name, value in auth_headers.items():
        command.extend(["-header", f"{name}: {value}"])
    return command, output


def _wfuzz_command(request: RunRequest, directory: Path) -> tuple[list[str], Path]:
    output = directory / "wfuzz.json"
    source_payloads = Path("/opt/payloads/safe-paths.txt").read_text(encoding="utf-8").splitlines()
    payload = directory / "safe-paths.txt"
    payload.write_text("\n".join(source_payloads[: request.max_requests]) + "\n", encoding="utf-8")
    target = request.target_url.rstrip("/") + "/FUZZ"
    command = [
        "wfuzz",
        "--no-cache",
        "--hc",
        "404",
        "-t",
        "1",
        "-s",
        str(1 / request.rate_limit),
        "-z",
        f"file,{payload}",
        "-f",
        f"{output},json",
        target,
    ]
    for name, value in _authentication_headers(request.authentication).items():
        command[1:1] = ["-H", f"{name}: {value}"]
    return command, output


def _authentication_headers(auth: dict[str, Any] | None) -> dict[str, str]:
    if not auth or auth.get("type") in {None, "NONE"}:
        return {}
    if auth.get("type") == "BEARER":
        return {"Authorization": f"Bearer {auth['token']}"}
    if auth.get("type") == "BASIC":
        import base64

        encoded = base64.b64encode(f"{auth['username']}:{auth['password']}".encode()).decode()
        return {"Authorization": f"Basic {encoded}"}
    if auth.get("type") == "API_KEY" and auth.get("location", "header") == "header":
        return {str(auth["name"]): str(auth["key"])}
    return {}


def _rewrite_wuppie_specification(document: dict[str, Any], proxy_url: str) -> dict[str, Any]:
    rewritten = json.loads(json.dumps(document))

    def replace_servers(value: Any) -> None:
        if isinstance(value, dict):
            if "servers" in value:
                value["servers"] = [{"url": proxy_url}]
            for child in value.values():
                replace_servers(child)
        elif isinstance(value, list):
            for child in value:
                replace_servers(child)

    if "openapi" in rewritten:
        rewritten["servers"] = [{"url": proxy_url}]
        replace_servers(rewritten)
    elif str(rewritten.get("swagger")) == "2.0":
        parsed = httpx.URL(proxy_url)
        rewritten["schemes"] = [parsed.scheme]
        rewritten["host"] = parsed.netloc.decode()
        rewritten["basePath"] = parsed.path
    return rewritten


def _contains_external_reference(value: Any) -> bool:
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str) and not reference.startswith("#/"):
            return True
        return any(_contains_external_reference(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_external_reference(child) for child in value)
    return False


def _wuppie_command(request: RunRequest, directory: Path, proxy_url: str) -> tuple[list[str], Path]:
    spec = directory / "openapi.json"
    spec.write_text(
        json.dumps(_rewrite_wuppie_specification(request.specification or {}, proxy_url)),
        encoding="utf-8",
    )
    command = [
        "wuppiefuzz",
        "fuzz",
        "--target",
        proxy_url,
        "--timeout",
        str(min(request.max_duration, max(1, int(request.max_requests / request.rate_limit)))),
        "--request-timeout",
        str(int(request.request_timeout * 1000)),
        "--method-mutation-strategy",
        "follow-spec",
        "--output-format",
        "json",
        "--report",
        str(spec),
    ]
    auth_headers = _authentication_headers(request.authentication)
    if auth_headers:
        auth_file = directory / "authentication.json"
        auth_file.write_text(
            json.dumps(
                {
                    "schemaVersion": "0.4.0",
                    "auth": [
                        {
                            "name": "scanner",
                            "fixedHeaders": [
                                {"name": name, "value": value}
                                for name, value in auth_headers.items()
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        auth_file.chmod(0o600)
        command[2:2] = ["--authentication", str(auth_file)]
    return command, directory / "unused"


def _sanitize_tool_output(value: str, authentication: dict[str, Any] | None) -> str:
    if authentication:
        for name in ("token", "key", "password"):
            secret = authentication.get(name)
            if secret and len(str(secret)) >= 3:
                value = value.replace(str(secret), "[REDACTED]")
    return re.sub(
        r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+",
        r"\1 [REDACTED]",
        value,
    )


def _read_json_events(path: Path, stdout: str) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else stdout
    events: list[dict[str, Any]] = []
    try:
        value = json.loads(text)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value]
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                events.append(value)
        except json.JSONDecodeError:
            continue
    return events


def _wuppie_events(directory: Path, stdout: str, stderr: str) -> tuple[list[dict[str, Any]], int]:
    events = []
    request_count = 0
    report = directory / "reports" / "grafana" / "report.db"
    if report.exists():
        with sqlite3.connect(f"file:{report}?mode=ro", uri=True) as connection:
            rows = connection.execute(
                """
                SELECT req.path, req.type, req.url, res.status, res.error
                FROM responses AS res
                JOIN requests AS req ON req.id = res.reqid
                ORDER BY res.id
                """
            ).fetchall()
        request_count = len(rows)
        for path, method, url, status, error in rows:
            status_code = int(status) if status is not None else 0
            if status_code < 500 and not error:
                continue
            if status_code == 599:
                events.append(
                    {
                        "kind": "transport_error",
                        "title": "REST API transport error",
                        "category": "transport-error",
                        "description": "The isolated proxy could not complete the target request.",
                        "severity": "INFO",
                        "confidence": "HIGH",
                        "endpoint": str(url or path),
                        "method": str(method).upper(),
                        "status": status_code,
                    }
                )
                continue
            events.append(
                {
                    "kind": "server_error" if status_code >= 500 else "crash",
                    "title": "REST API fuzzing anomaly",
                    "category": "server-error" if status_code >= 500 else "transport-error",
                    "description": (
                        f"WuppieFuzz received HTTP {status_code}."
                        if status_code
                        else f"WuppieFuzz observed a transport error: {str(error)[:500]}"
                    ),
                    "severity": "MEDIUM",
                    "confidence": "HIGH" if status_code >= 500 else "LOW",
                    "endpoint": str(url or path),
                    "method": str(method).upper(),
                    "status": status_code or None,
                }
            )
    pattern = re.compile(r"(?i)(server error|crash|panic|bug).*?(https?://\S+)?")
    for line in (stdout + "\n" + stderr).splitlines():
        if pattern.search(line):
            events.append(
                {
                    "kind": "server_error" if "server error" in line.lower() else "crash",
                    "title": "REST API fuzzing anomaly",
                    "description": line[:1000],
                    "severity": "MEDIUM",
                    "confidence": "MEDIUM",
                }
            )
    return events, request_count


@app.api_route(
    "/_wuppie_proxy/{job_id}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"],
    include_in_schema=False,
)
async def wuppie_proxy(job_id: str, path: str, request: Request) -> Response:
    job = PROXY_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="unknown or expired proxy job")
    body = await request.body()
    if len(body) > MAX_PROXY_BODY:
        raise HTTPException(status_code=413, detail="proxied request body is too large")
    await job.take()
    query = urlencode(list(request.query_params.multi_items()))
    target = f"{job.target_url.rstrip('/')}/{path.lstrip('/')}"
    if query:
        target = f"{target}?{query}"
    headers = {
        name: value
        for name, value in request.headers.items()
        if name.lower() not in HOP_BY_HOP and name.lower() != "x-runner-token"
    }
    client = ScopedHttpClient(
        ScopeGuard(job.allowed_hosts, allow_private=ALLOW_PRIVATE),
        timeout=job.request_timeout,
        max_response_size=MAX_PROXY_BODY,
    )
    try:
        upstream = await client.request(request.method, target, headers=headers, content=body)
    except (httpx.HTTPError, ScopeViolation, ValueError) as exc:
        # 599 is only used on this private runner hop. It prevents a proxy/network
        # failure from being misreported as an HTTP 5xx vulnerability in the target.
        return Response(
            content=f"target request failed: {type(exc).__name__}",
            status_code=599,
            media_type="text/plain",
        )
    response_headers = {
        name: value for name, value in upstream.headers.items() if name.lower() not in HOP_BY_HOP
    }
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=response_headers,
        media_type=upstream.headers.get("content-type"),
    )


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "engine": ENGINE}


@app.post("/run")
async def run(request: RunRequest, x_runner_token: str | None = Header(default=None)) -> dict:
    _authenticate(x_runner_token)
    if ENGINE not in {"nuclei", "wfuzz", "wuppiefuzz"}:
        raise HTTPException(status_code=500, detail="runner ENGINE is invalid")
    guard = ScopeGuard(request.allowed_hosts, allow_private=ALLOW_PRIVATE)
    try:
        await guard.validate(request.target_url)
        for endpoint in request.endpoints:
            base_url = endpoint.get("base_url")
            if base_url:
                await guard.validate(str(base_url))
    except ScopeViolation as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if ENGINE == "wuppiefuzz" and (
        not request.specification
        or not (
            "openapi" in request.specification or str(request.specification.get("swagger")) == "2.0"
        )
    ):
        return {"status": "SKIPPED", "events": [], "reason": "OpenAPI specification required"}
    if ENGINE == "wuppiefuzz" and _contains_external_reference(request.specification):
        return {
            "status": "SKIPPED",
            "events": [],
            "reason": "external specification references are not fetched by the isolated runner",
        }
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix=f"{ENGINE}-") as temporary:
        directory = Path(temporary)
        proxy_job_id: str | None = None
        if ENGINE == "wuppiefuzz":
            proxy_job_id = secrets.token_urlsafe(24)
            PROXY_JOBS[proxy_job_id] = ProxyJob(
                target_url=request.target_url,
                allowed_hosts=request.allowed_hosts,
                rate_limit=request.rate_limit,
                max_requests=request.max_requests,
                request_timeout=request.request_timeout,
            )
            proxy_url = f"{RUNNER_INTERNAL_URL.rstrip('/')}/_wuppie_proxy/{proxy_job_id}"
            command, output = _wuppie_command(request, directory, proxy_url)
        elif ENGINE == "nuclei":
            command, output = _nuclei_command(request, directory)
        else:
            command, output = _wfuzz_command(request, directory)
        effective_duration = min(
            request.max_duration,
            max(1, int(request.max_requests / request.rate_limit) + 1),
        )
        try:
            return_code, stdout, stderr = await _run_process(command, temporary, effective_duration)
        except TimeoutError:
            return {
                "status": "TIMEOUT",
                "events": [],
                "reason": "tool process exceeded duration limit",
                "duration_seconds": time.monotonic() - started,
            }
        except (OSError, ValueError) as exc:
            return {
                "status": "FAILED",
                "events": [],
                "reason": f"tool process failed: {type(exc).__name__}",
                "duration_seconds": time.monotonic() - started,
            }
        finally:
            proxy_job = PROXY_JOBS.pop(proxy_job_id, None) if proxy_job_id else None
        if ENGINE == "wuppiefuzz":
            events, request_count = _wuppie_events(directory, stdout, stderr)
            if proxy_job:
                request_count = proxy_job.count
        else:
            events = _read_json_events(output, stdout)
            request_count = len(events)
        return {
            "status": "COMPLETED" if return_code in {0, 1} else "FAILED",
            "events": events,
            "request_count": min(request.max_requests, request_count),
            "duration_seconds": time.monotonic() - started,
            "reason": None if return_code in {0, 1} else f"tool exited with code {return_code}",
            "stderr": _sanitize_tool_output(stderr[-4000:], request.authentication),
        }
