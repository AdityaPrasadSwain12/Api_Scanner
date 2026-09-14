import pytest
from pydantic import ValidationError

from app.core.config import Settings

PRODUCTION_SECRETS = {
    "scanner_api_key": "scanner-service-secret",
    "secret_encryption_key": "NQ4M5lY8yl5wE9bG6vRCcQ5Rk4j1g5HVFFOS5iQlJ0k=",
    "engine_runner_token": "runner-service-secret",
}


def test_production_deployment_allowlist_cannot_be_empty():
    with pytest.raises(ValidationError, match="ALLOWED_TARGETS"):
        Settings(
            environment="production",
            target_scope_mode="deployment_allowlist",
            allowed_targets=[],
            **PRODUCTION_SECRETS,
        )


def test_platform_managed_production_accepts_dynamic_scope_configuration():
    settings = Settings(
        environment="production",
        target_scope_mode="platform_managed",
        allowed_targets=[],
        dashboard_auth_mode="gateway",
        **PRODUCTION_SECRETS,
    )

    assert settings.target_scope_mode == "platform_managed"
    assert settings.dashboard_auth_mode == "gateway"


def test_production_rejects_disabled_dashboard_authentication():
    with pytest.raises(ValidationError, match="DASHBOARD_AUTH_MODE=disabled"):
        Settings(
            environment="production",
            target_scope_mode="deployment_allowlist",
            allowed_targets=["api.example.test"],
            dashboard_auth_mode="disabled",
            **PRODUCTION_SECRETS,
        )


def test_oast_configuration_requires_poll_url_and_service_key():
    with pytest.raises(ValidationError, match="OAST_CALLBACK_BASE_URL"):
        Settings(oast_callback_base_url="https://oast.example.test/c")
    with pytest.raises(ValidationError, match="OAST_API_KEY"):
        Settings(
            oast_callback_base_url="https://oast.example.test/c",
            oast_poll_base_url="http://oast:8094",
        )
