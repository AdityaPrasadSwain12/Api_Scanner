from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./api_scanner.db"
    redis_url: str = "redis://localhost:6379/0"
    scanner_api_key: str = ""
    secret_encryption_key: str = ""
    engine_runner_token: str = ""
    zap_url: str | None = None
    zap_api_key: str = ""
    zap_shared_directory: Path | None = None
    nuclei_runner_url: str | None = None
    wfuzz_runner_url: str | None = None
    wuppiefuzz_runner_url: str | None = None
    oast_callback_base_url: str | None = None
    oast_poll_base_url: str | None = None
    oast_api_key: str = ""
    scan_timeout: int = Field(default=1800, ge=30, le=86_400)
    request_timeout: float = Field(default=10, ge=1, le=120)
    max_concurrency: int = Field(default=10, ge=1, le=100)
    max_requests: int = Field(default=2000, ge=1, le=100_000)
    default_rate_limit: float = Field(default=10, ge=0.1, le=1000)
    max_spec_size: int = Field(default=5 * 1024 * 1024, ge=1024, le=50 * 1024 * 1024)
    max_response_size: int = Field(default=2 * 1024 * 1024, ge=1024, le=20 * 1024 * 1024)
    allowed_targets: Annotated[list[str], NoDecode] = Field(default_factory=list)
    allow_private_targets: bool = False
    target_scope_mode: Literal["deployment_allowlist", "platform_managed"] = "deployment_allowlist"
    dashboard_auth_mode: Literal["api_key", "gateway", "disabled"] = "api_key"
    log_level: str = "INFO"
    task_always_eager: bool = False
    report_directory: Path = Path("./reports")
    metrics_enabled: bool = True

    @field_validator("allowed_targets", mode="before")
    @classmethod
    def parse_allowed_targets(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip().lower().rstrip(".") for item in value.split(",") if item.strip()]
        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        value = value.upper()
        if value not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("invalid log level")
        return value

    @model_validator(mode="after")
    def production_secrets(self) -> "Settings":
        if bool(self.oast_callback_base_url) != bool(self.oast_poll_base_url):
            raise ValueError("OAST_CALLBACK_BASE_URL and OAST_POLL_BASE_URL must be set together")
        if self.oast_callback_base_url and not self.oast_api_key:
            raise ValueError("OAST_API_KEY is required when OAST callback testing is enabled")
        if self.environment == "production":
            missing = [
                name
                for name in ("scanner_api_key", "secret_encryption_key", "engine_runner_token")
                if not getattr(self, name)
            ]
            if missing:
                raise ValueError(f"production requires: {', '.join(missing)}")
            if self.target_scope_mode == "deployment_allowlist" and not self.allowed_targets:
                raise ValueError("production requires ALLOWED_TARGETS")
            if self.dashboard_auth_mode == "disabled":
                raise ValueError("production cannot use DASHBOARD_AUTH_MODE=disabled")
        return self


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.report_directory.mkdir(parents=True, exist_ok=True)
    return settings
