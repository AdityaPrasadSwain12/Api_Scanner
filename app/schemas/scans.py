import enum
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


class ScanProfileName(str, enum.Enum):
    QUICK = "QUICK"
    STANDARD = "STANDARD"
    DEEP = "DEEP"
    SAFE = "SAFE"
    AGGRESSIVE = "AGGRESSIVE"


class AuthType(str, enum.Enum):
    NONE = "NONE"
    BEARER = "BEARER"
    API_KEY = "API_KEY"
    BASIC = "BASIC"


class AuthenticationInput(BaseModel):
    type: AuthType = AuthType.NONE
    token: str | None = Field(default=None, max_length=8192)
    key: str | None = Field(default=None, max_length=8192)
    name: str | None = Field(default=None, max_length=200)
    location: Literal["header", "query"] = "header"
    username: str | None = Field(default=None, max_length=500)
    password: str | None = Field(default=None, max_length=8192)

    @model_validator(mode="after")
    def required_fields(self) -> "AuthenticationInput":
        required = {
            AuthType.BEARER: bool(self.token),
            AuthType.API_KEY: bool(self.key and self.name),
            AuthType.BASIC: bool(self.username and self.password),
            AuthType.NONE: True,
        }
        if not required[self.type]:
            raise ValueError(f"missing credential fields for {self.type.value}")
        return self


class IdentityInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    role: str = Field(default="user", max_length=100)
    is_admin: bool = False
    resource_ids: list[str] = Field(default_factory=list, max_length=50)
    auth: AuthenticationInput


class ScanPolicyInput(BaseModel):
    rate_limit: float | None = Field(default=None, ge=0.1, le=1000)
    concurrency: int | None = Field(default=None, ge=1, le=100)
    request_timeout: float | None = Field(default=None, ge=1, le=120)
    max_requests: int | None = Field(default=None, ge=1, le=100_000)
    max_duration: int | None = Field(default=None, ge=30, le=86_400)
    allowed_hosts: list[str] = Field(default_factory=list, max_length=100)
    user_paths: list[str] = Field(default_factory=list, max_length=1000)
    additional_discovery: bool = False
    enabled_engines: list[Literal["zap", "nuclei", "wfuzz", "wuppiefuzz", "custom"]] | None = None


class ScanCreate(BaseModel):
    project_name: str = Field(default="Default", min_length=1, max_length=200)
    external_project_id: str | None = Field(default=None, max_length=200)
    authorization_reference: str | None = Field(default=None, min_length=1, max_length=500)
    target_url: HttpUrl
    authorized: Literal[True]
    profile: ScanProfileName = ScanProfileName.STANDARD
    specification: str | dict[str, Any] | None = None
    specification_url: HttpUrl | None = None
    postman_collection: dict[str, Any] | None = None
    authentication: AuthenticationInput | None = None
    identities: list[IdentityInput] = Field(default_factory=list, max_length=10)
    policy: ScanPolicyInput = Field(default_factory=ScanPolicyInput)

    @model_validator(mode="after")
    def one_inventory_source(self) -> "ScanCreate":
        supplied = sum(
            value is not None
            for value in (self.specification, self.specification_url, self.postman_collection)
        )
        if supplied > 1:
            raise ValueError("provide only one specification source")
        if self.profile == ScanProfileName.AGGRESSIVE and not self.policy.enabled_engines:
            raise ValueError("AGGRESSIVE requires an explicit enabled_engines list")
        return self


class ScanAccepted(BaseModel):
    scan_id: str
    status: str
    status_url: str


class ScanView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: str
    target_id: str
    target_url: str
    profile: str
    status: str
    progress: int
    stage: str
    result_summary: dict[str, Any]
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class Paginated(BaseModel):
    items: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


class ErrorResponse(BaseModel):
    error: dict[str, Any]
