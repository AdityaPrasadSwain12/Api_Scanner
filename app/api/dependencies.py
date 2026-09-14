from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request

from app.core.config import Settings, get_settings
from app.core.secrets import api_key_matches


def require_api_key(
    settings: Annotated[Settings, Depends(get_settings)],
    x_api_key: Annotated[str | None, Header()] = None,
) -> str:
    # The simplified local dashboard has no credential prompt. This mode is rejected by
    # Settings in production, where the parent gateway must protect scanner requests.
    if settings.dashboard_auth_mode == "disabled":
        return "local-dashboard"
    if not api_key_matches(settings.scanner_api_key, x_api_key):
        raise HTTPException(
            status_code=401,
            detail={"code": "UNAUTHORIZED", "message": "invalid or missing API key"},
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return x_api_key or "development"


def actor_identity(x_actor: Annotated[str | None, Header(max_length=200)] = None) -> str:
    return x_actor or "api-client"


def correlation_id(request: Request) -> str:
    return request.state.correlation_id
