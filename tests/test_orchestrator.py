import asyncio
import socket
import threading
import time
from pathlib import Path

import uvicorn
import yaml
from sqlalchemy import select

from app.core.config import get_settings
from app.models.database import Endpoint, Finding, Report, Scan, ScanEngine
from app.schemas.scans import ScanCreate
from app.services.orchestrator import Orchestrator
from app.services.scan_service import create_scan
from vulnerable_test_api.main import app as vulnerable_app


def _free_port() -> int:
    with socket.socket() as value:
        value.bind(("127.0.0.1", 0))
        return value.getsockname()[1]


def test_complete_local_orchestration(db):
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(vulnerable_app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started
    try:
        specification = yaml.safe_load(
            Path("vulnerable_test_api/openapi.yaml").read_text(encoding="utf-8")
        )
        target_url = f"http://127.0.0.1:{port}"
        specification["servers"] = [{"url": target_url}]
        specification["paths"]["/users/{user_id}"]["get"]["parameters"][0]["schema"]["example"] = (
            "100"
        )
        request = ScanCreate(
            target_url=target_url,
            authorized=True,
            profile="STANDARD",
            specification=specification,
            authentication={"type": "BEARER", "token": "user-a-token"},
            identities=[
                {
                    "name": "User A",
                    "resource_ids": ["100"],
                    "auth": {"type": "BEARER", "token": "user-a-token"},
                },
                {
                    "name": "User B",
                    "resource_ids": ["200"],
                    "auth": {"type": "BEARER", "token": "user-b-token"},
                },
                {
                    "name": "Admin",
                    "role": "admin",
                    "is_admin": True,
                    "auth": {"type": "BEARER", "token": "admin-token"},
                },
            ],
            policy={"rate_limit": 100, "concurrency": 4, "max_requests": 250},
        )
        settings = get_settings()
        scan = asyncio.run(
            create_scan(db, request, settings, actor="orchestrator-test", correlation_id="test")
        )
        Orchestrator(db, settings).run_sync(scan.id)
        db.expire_all()
        completed = db.get(Scan, scan.id)
        # This in-process test intentionally has no OAST collector. The reachable scan
        # completes useful work but is PARTIAL because its documented URL input cannot
        # receive the required SSRF callback coverage.
        assert completed.status == "PARTIAL", completed.error
        assert completed.progress == 100
        assert completed.result_summary["coverage"]["assessment"]["status"] == "PARTIAL"

        findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan.id)))
        categories = {finding.category for finding in findings}
        assert {
            "bola",
            "bfla",
            "missing-authentication",
            "sql-injection",
            "nosql-injection",
            "path-traversal",
            "xss",
            "open-redirect",
            "command-injection",
            "cors-misconfiguration",
            "excessive-data-exposure",
        } <= categories
        engines = list(db.scalars(select(ScanEngine).where(ScanEngine.scan_id == scan.id)))
        assert {engine.name for engine in engines} == {
            "custom",
            "zap",
            "nuclei",
            "wfuzz",
            "wuppiefuzz",
        }
        assert next(engine for engine in engines if engine.name == "custom").status == "COMPLETED"
        assert next(engine for engine in engines if engine.name == "wuppiefuzz").status == "SKIPPED"
        reports = list(db.scalars(select(Report).where(Report.scan_id == scan.id)))
        assert {report.format for report in reports} == {
            "JSON",
            "TECHNICAL_JSON",
            "HTML",
            "PDF",
        }
        json_report = next(report for report in reports if report.format == "JSON")
        assert "user-a-token" not in Path(json_report.path).read_text(encoding="utf-8")
        technical_report = next(
            report for report in reports if report.format == "TECHNICAL_JSON"
        )
        assert "user-a-token" not in Path(technical_report.path).read_text(encoding="utf-8")
        assert completed.result_summary["coverage"]["endpoints"]["tested"] >= 6
        security_checks = completed.result_summary["coverage"]["security_checks"]
        for check in (
            "sql-injection",
            "nosql-injection",
            "path-traversal",
            "reflected-xss",
            "open-redirect",
            "command-injection",
        ):
            assert security_checks[check]["detected_endpoints"] >= 1
        assert (
            completed.result_summary["coverage"]["security_check_summary"][
                "eligible_endpoint_checks"
            ]
            > 0
        )
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_unreachable_target_fails_before_authoritative_reporting(db):
    port = _free_port()
    target_url = f"http://127.0.0.1:{port}"
    request = ScanCreate(
        target_url=target_url,
        authorized=True,
        profile="STANDARD",
        specification={
            "openapi": "3.1.0",
            "info": {"title": "Unavailable API", "version": "1.0.0"},
            "servers": [{"url": target_url}],
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [
                            {
                                "name": "q",
                                "in": "query",
                                "schema": {"type": "string"},
                            }
                        ],
                        "responses": {"200": {"description": "Search results"}},
                    }
                }
            },
        },
        policy={"enabled_engines": ["custom"], "request_timeout": 1},
    )
    settings = get_settings()
    scan = asyncio.run(
        create_scan(db, request, settings, actor="orchestrator-test", correlation_id="unreachable")
    )

    Orchestrator(db, settings).run_sync(scan.id)
    db.expire_all()

    failed = db.get(Scan, scan.id)
    assert failed.status == "FAILED"
    assert "0 of 1 documented endpoints" in failed.error
    assert "reachable from the scanner containers" in failed.error
    assert failed.result_summary["coverage"]["assessment"]["status"] == "INCOMPLETE"
    assert failed.result_summary["coverage"]["endpoints"]["tested"] == 0
    assert (
        failed.result_summary["coverage"]["runtime_check_summary"][
            "attempted_endpoint_checks"
        ]
        == 0
    )
    assert list(db.scalars(select(Finding).where(Finding.scan_id == scan.id))) == []
    assert list(db.scalars(select(Report).where(Report.scan_id == scan.id))) == []
    endpoint = db.scalar(select(Endpoint).where(Endpoint.scan_id == scan.id))
    assert endpoint.test_status == "SKIPPED"
    assert any(
        failure in endpoint.skip_reason for failure in ("ConnectError", "ConnectTimeout")
    )
    engine = db.scalar(select(ScanEngine).where(ScanEngine.scan_id == scan.id))
    assert engine.status == "FAILED"
