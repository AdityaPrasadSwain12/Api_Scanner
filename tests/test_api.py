from app.api import routes
from app.core.config import get_settings
from app.main import app
from app.security.scope import ValidatedTarget


async def valid_target(self, url):
    return ValidatedTarget(url=url, host="api.example.test", addresses=("203.0.113.1",))


def test_health_is_public(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_browser_integration_configuration_is_public_and_contains_no_secret(client):
    response = client.get("/ui-config")
    assert response.status_code == 200
    assert response.json()["auth_mode"] == "api_key"
    assert "key" not in response.json()


def test_scanner_api_requires_key(client):
    assert client.get("/api/v1/scans").status_code == 401


def test_development_dashboard_mode_can_remove_browser_key_prompt(client):
    settings = get_settings().model_copy(update={"dashboard_auth_mode": "disabled"})
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        response = client.get("/api/v1/scans")
        assert response.status_code == 200
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_create_and_control_scan(client, api_headers, monkeypatch):
    monkeypatch.setattr("app.security.scope.ScopeGuard.validate", valid_target)
    monkeypatch.setattr(routes.run_scan, "delay", lambda scan_id: None)
    response = client.post(
        "/api/v1/scans",
        headers=api_headers,
        json={
            "target_url": "https://api.example.test",
            "authorized": True,
            "profile": "SAFE",
            "specification": {
                "openapi": "3.1.0",
                "info": {"title": "Test", "version": "1"},
                "paths": {"/ping": {"get": {"responses": {"200": {"description": "ok"}}}}},
            },
        },
    )
    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]
    status = client.get(f"/api/v1/scans/{scan_id}/status", headers=api_headers)
    assert status.json()["status"] == "QUEUED"
    cancelled = client.post(f"/api/v1/scans/{scan_id}/cancel", headers=api_headers)
    assert cancelled.status_code == 200
    assert (
        client.get(f"/api/v1/scans/{scan_id}/status", headers=api_headers).json()["status"]
        == "CANCELLED"
    )
    assert client.post(f"/api/v1/scans/{scan_id}/pause", headers=api_headers).status_code == 409


def test_target_authorization_confirmation_is_mandatory(client, api_headers):
    response = client.post(
        "/api/v1/scans",
        headers=api_headers,
        json={"target_url": "https://api.example.test", "authorized": False},
    )
    assert response.status_code == 422


def test_invalid_api_document_is_rejected_before_queueing(client, api_headers, monkeypatch):
    monkeypatch.setattr("app.security.scope.ScopeGuard.validate", valid_target)
    response = client.post(
        "/api/v1/scans",
        headers=api_headers,
        json={
            "target_url": "https://api.example.test",
            "authorized": True,
            "specification": {"not": "an OpenAPI document"},
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_API_DOCUMENT"


def test_document_server_must_be_inside_target_scope(client, api_headers, monkeypatch):
    async def resolve_public(self, host, port):
        return {"192.0.2.10"}

    monkeypatch.setattr("app.security.scope.ScopeGuard._resolve", resolve_public)
    response = client.post(
        "/api/v1/scans",
        headers=api_headers,
        json={
            "target_url": "https://api.example.test",
            "authorized": True,
            "specification": {
                "openapi": "3.1.0",
                "info": {"title": "Wrong host", "version": "1"},
                "servers": [{"url": "https://other.example.test"}],
                "paths": {"/ping": {"get": {"responses": {"200": {"description": "ok"}}}}},
            },
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "SPEC_TARGET_MISMATCH"


def test_dashboard_has_simple_document_workflow_without_key_form(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Verify and start scan" in response.text
    assert "Scanner service API key" not in response.text


def test_scope_blocks_non_deployment_host(client, api_headers):
    response = client.post(
        "/api/v1/scans",
        headers=api_headers,
        json={"target_url": "https://unapproved.example", "authorized": True},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "SCOPE_VIOLATION"


def test_platform_managed_scope_requires_trusted_references(client, api_headers, monkeypatch):
    settings = get_settings().model_copy(
        update={"target_scope_mode": "platform_managed", "allowed_targets": []}
    )
    app.dependency_overrides[get_settings] = lambda: settings
    monkeypatch.setattr("app.security.scope.ScopeGuard.validate", valid_target)
    monkeypatch.setattr(routes.run_scan, "delay", lambda scan_id: None)
    try:
        missing = client.post(
            "/api/v1/scans",
            headers=api_headers,
            json={"target_url": "https://customer.example", "authorized": True},
        )
        assert missing.status_code == 422
        assert missing.json()["error"]["code"] == "PLATFORM_AUTHORIZATION_REQUIRED"

        accepted = client.post(
            "/api/v1/scans",
            headers=api_headers,
            json={
                "external_project_id": "platform-project-123",
                "authorization_reference": "engagement-456",
                "target_url": "https://customer.example",
                "authorized": True,
                "profile": "SAFE",
            },
        )
        assert accepted.status_code == 202, accepted.text
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_pagination_and_not_found(client, api_headers):
    response = client.get("/api/v1/scans?limit=10&offset=0", headers=api_headers)
    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0, "limit": 10, "offset": 0}
    missing = client.get("/api/v1/scans/does-not-exist", headers=api_headers)
    assert missing.status_code == 404
