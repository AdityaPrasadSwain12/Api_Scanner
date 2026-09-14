"""Minimal deployment-owned out-of-band callback collector for SSRF confirmation.

Only opaque callback tokens are retained, with a short TTL. The public callback route
does not store headers, bodies, source addresses, or credentials. Deployments should
publish only ``/c/*`` and keep ``/events/*`` on the private scanner network.
"""

import hmac
import os
import re

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import Response
from redis.asyncio import Redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
OAST_API_KEY = os.getenv("OAST_API_KEY", "")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")

app = FastAPI(title="Scanner OAST Callback Collector", docs_url=None, redoc_url=None)


def _token(value: str) -> str:
    if not TOKEN_PATTERN.fullmatch(value):
        raise HTTPException(status_code=404, detail="unknown callback")
    return value


def _authorize(value: str | None) -> None:
    if not OAST_API_KEY or not value or not hmac.compare_digest(OAST_API_KEY, value):
        raise HTTPException(status_code=401, detail="invalid service credential")


@app.api_route(
    "/c/{token}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    include_in_schema=False,
)
async def callback(token: str) -> Response:
    redis = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        key = f"oast:{_token(token)}"
        if await redis.exists(key):
            await redis.set(key, "1", ex=600)
    finally:
        await redis.aclose()
    return Response(status_code=204, headers={"Cache-Control": "no-store"})


@app.post("/events/{token}/register", include_in_schema=False)
async def register(token: str, x_oast_key: str | None = Header(default=None)) -> dict[str, bool]:
    _authorize(x_oast_key)
    redis = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis.set(f"oast:{_token(token)}", "0", ex=600)
    finally:
        await redis.aclose()
    return {"registered": True}


@app.get("/events/{token}", include_in_schema=False)
async def event(token: str, x_oast_key: str | None = Header(default=None)) -> dict[str, bool]:
    _authorize(x_oast_key)
    redis = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        hit = (await redis.get(f"oast:{_token(token)}")) == "1"
        if hit:
            await redis.delete(f"oast:{token}")
    finally:
        await redis.aclose()
    return {"hit": hit}


@app.get("/health", include_in_schema=False)
async def health() -> dict[str, str]:
    redis = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis.ping()
    finally:
        await redis.aclose()
    return {"status": "healthy"}
