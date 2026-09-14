"""Run authorized end-to-end scans against the local deliberately vulnerable API."""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_env() -> dict[str, str]:
    values = dict(os.environ)
    path = ROOT / ".env"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values.setdefault(key, value)
    return values


ENV = load_env()
BASE = ENV.get("SCANNER_URL", "http://localhost:8000")
API_KEY = ENV.get("SCANNER_API_KEY", "local-development-key")


def request(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"X-API-Key": API_KEY, "Content-Type": "application/json", "X-Actor": "e2e-script"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{method} {path} failed: {exc.code} {exc.read().decode()}") from exc


def download(path: str) -> bytes:
    req = urllib.request.Request(BASE + path, headers={"X-API-Key": API_KEY})
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read()


def wait_for(scan_id: str, maximum: int = 2400) -> dict:
    deadline = time.monotonic() + maximum
    while time.monotonic() < deadline:
        status = request("GET", f"/api/v1/scans/{scan_id}/status")
        print(f"{scan_id}: {status['status']} {status['progress']}% {status['stage']}")
        if status["terminal"]:
            if status["status"] not in {"COMPLETED", "PARTIAL"}:
                raise RuntimeError(f"scan terminated as {status['status']}: {status.get('error')}")
            return request("GET", f"/api/v1/scans/{scan_id}")
        time.sleep(3)
    request("POST", f"/api/v1/scans/{scan_id}/cancel")
    raise TimeoutError(f"scan {scan_id} exceeded e2e timeout")


def submit(payload: dict) -> dict:
    accepted = request("POST", "/api/v1/scans", payload)
    return wait_for(accepted["scan_id"])


def multi_identity_payload(profile: str = "STANDARD") -> dict:
    payload = json.loads((ROOT / "examples" / "multi-identity-scan.json").read_text())
    payload["profile"] = profile
    if profile == "DEEP":
        payload["policy"].update({"max_requests": 1000, "max_duration": 900})
    return payload


def verify_primary(scan: dict) -> None:
    scan_id = scan["id"]
    findings = request("GET", f"/api/v1/scans/{scan_id}/findings?limit=500")["items"]
    endpoints = request("GET", f"/api/v1/scans/{scan_id}/endpoints?limit=500")
    coverage = request("GET", f"/api/v1/scans/{scan_id}/coverage")
    reports = request("GET", f"/api/v1/scans/{scan_id}/reports")["items"]
    categories = {item["category"] for item in findings}
    required = {
        "missing-authentication",
        "bola",
        "bfla",
        "sql-injection",
        "nosql-injection",
        "path-traversal",
        "xss",
        "open-redirect",
        "command-injection",
        "ssrf",
        "cors-misconfiguration",
    }
    missing = required - categories
    if missing:
        raise AssertionError(
            f"expected vulnerable fixture findings were absent: {sorted(missing)}; got {sorted(categories)}"
        )
    engine_status = coverage["engines"]
    if set(engine_status) != {"custom", "zap", "nuclei", "wfuzz", "wuppiefuzz"}:
        raise AssertionError(f"engine plan was incomplete: {engine_status}")
    if endpoints["total"] < 6 or coverage["endpoints"]["tested"] < 6:
        raise AssertionError("endpoint inventory/coverage is incomplete")
    required_checks = {
        "sql-injection",
        "nosql-injection",
        "path-traversal",
        "reflected-xss",
        "open-redirect",
        "command-injection",
        "ssrf",
    }
    if not required_checks <= set(coverage.get("security_checks", {})):
        raise AssertionError("per-vulnerability coverage matrix is incomplete")
    for check in required_checks:
        if coverage["security_checks"][check]["detected_endpoints"] < 1:
            raise AssertionError(f"expected fixture detection was absent for {check}")
    if {item["format"] for item in reports} != {"JSON", "TECHNICAL_JSON", "HTML", "PDF"}:
        raise AssertionError("all report formats were not generated")
    for report in reports:
        content = download(report["download_url"])
        if hashlib.sha256(content).hexdigest() != report["sha256"]:
            raise AssertionError(f"{report['format']} report checksum did not match metadata")
        if any(
            secret.encode() in content for secret in ("user-a-token", "user-b-token", "admin-token")
        ):
            raise AssertionError(f"{report['format']} report contains an authentication secret")
    print(
        f"Verified primary scan {scan_id}: {len(findings)} findings, {endpoints['total']} endpoints"
    )


def full_matrix() -> None:
    base = "http://vulnerable-api:8001"
    cases = [
        {
            "target_url": base,
            "authorized": True,
            "profile": "QUICK",
            "policy": {"user_paths": ["/public", "/search"]},
        },
        {
            "target_url": base,
            "authorized": True,
            "profile": "SAFE",
            "specification_url": f"{base}/openapi.json",
            "authentication": {"type": "BEARER", "token": "user-a-token"},
        },
        multi_identity_payload("STANDARD"),
        multi_identity_payload("DEEP"),
    ]
    inline = multi_identity_payload("STANDARD")
    inline.pop("specification_url", None)
    # JSON is equally authoritative; the multipart upload path is covered by API tests.
    import yaml

    inline["specification"] = yaml.safe_load(
        (ROOT / "vulnerable_test_api" / "openapi.yaml").read_text()
    )
    cases.insert(1, inline)
    for case in cases:
        result = submit(case)
        print(f"Verified {case['profile']} input mode: {result['id']} ({result['status']})")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--full",
        action="store_true",
        help="run URL-only, OpenAPI, auth, multi-user, and deep scans",
    )
    args = parser.parse_args()
    health = urllib.request.urlopen(BASE + "/health", timeout=5)
    if health.status != 200:
        raise RuntimeError("scanner health check failed")
    primary = submit(multi_identity_payload())
    verify_primary(primary)
    if args.full:
        full_matrix()
    print("End-to-end verification passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
