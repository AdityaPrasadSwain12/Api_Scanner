from typing import Annotated
from urllib.parse import unquote, urlsplit
from urllib.request import urlopen

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI(
    title="Deliberately Vulnerable API",
    version="1.0.0",
    description="Local test fixture. Never expose this service publicly.",
)
bearer = HTTPBearer(auto_error=False)

USERS = {
    "100": {
        "id": "100",
        "owner": "user-a",
        "name": "Alice",
        "email": "alice@example.test",
        "ssn": "111-22-3333",
    },
    "200": {
        "id": "200",
        "owner": "user-b",
        "name": "Bob",
        "email": "bob@example.test",
        "ssn": "444-55-6666",
    },
}
TOKENS = {"user-a-token": "user-a", "user-b-token": "user-b", "admin-token": "admin"}


def identity(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> str:
    if not credentials or credentials.credentials not in TOKENS:
        raise HTTPException(status_code=401, detail="missing or invalid token")
    return TOKENS[credentials.credentials]


@app.middleware("http")
async def intentionally_weak_headers(request: Request, call_next):
    response = await call_next(request)
    if request.headers.get("origin"):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Server"] = "VulnerableAPI/0.1 debug"
    return response


@app.get("/")
def root() -> dict:
    return {
        "service": "vulnerable-test-api",
        "documentation": "/openapi.json",
        "users": "/users/100",
    }


@app.get("/health", include_in_schema=False)
def health() -> dict:
    return {"status": "deliberately-vulnerable"}


@app.get("/public")
def public() -> dict:
    return {"message": "public endpoint"}


@app.get("/private", openapi_extra={"security": [{"HTTPBearer": []}]})
def private_data() -> dict:
    # Intentionally vulnerable: the OpenAPI contract marks this operation protected, but it is not.
    return {"internal": "restricted-value"}


@app.get("/users/{user_id}")
def get_user(user_id: str, _: Annotated[str, Depends(identity)]) -> dict:
    # Intentionally vulnerable: the object owner is never compared with the authenticated subject.
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="user not found")
    return USERS[user_id]


@app.get("/admin/stats")
def admin_stats(_: Annotated[str, Depends(identity)]) -> dict:
    # Intentionally vulnerable: every authenticated user can invoke an admin function.
    return {"users": len(USERS), "revenue": 125000, "mode": "admin"}


@app.get("/search")
def search(q: Annotated[str, Query(max_length=200)] = ""):
    return vulnerable_user_search(q)


def vulnerable_user_search(q: str):
    normalized = " ".join(q.lower().split())
    if "or '1'='1'" in normalized or "or 1=1" in normalized:
        return {"query": q, "results": list(USERS.values())}
    if "and '1'='2'" in normalized or "and 1=2" in normalized:
        return {"query": q, "results": []}
    if "'" in q or '"' in q:
        return JSONResponse(
            status_code=500,
            content={
                "error": "SQLite_ERROR: near quoted value: syntax error",
                "traceback": "query_users() line 42",
            },
        )
    matches = [value for value in USERS.values() if q.lower() in value["name"].lower()]
    return {"query": q, "results": matches}


@app.get("/api/vulnerable/users/search")
def vulnerable_users_search(q: str = "alice"):
    # Simulates unsafe query concatenation without connecting the fixture to a real database.
    return vulnerable_user_search(q)


@app.get("/api/vulnerable/files")
def vulnerable_files(name: str = "welcome.txt"):
    normalized = unquote(unquote(name)).replace("\\", "/")
    if "../" in normalized:
        # Controlled marker representing a successful local-file read. No host file is accessed.
        return PlainTextResponse("root:x:0:0:root:/root:/bin/sh\nAPI_SCANNER_TRAVERSAL_CANARY")
    return PlainTextResponse("Welcome to the deliberately vulnerable API fixture.")


@app.get("/api/vulnerable/message", response_class=HTMLResponse)
def vulnerable_message(name: str = "visitor"):
    # Intentionally unescaped for deterministic reflected-XSS testing.
    return HTMLResponse(f"<html><body><h1>Hello {name}</h1></body></html>")


@app.get("/api/vulnerable/redirect")
def vulnerable_redirect(to: str = "/"):
    return RedirectResponse(to, status_code=302)


@app.get("/api/vulnerable/command")
def vulnerable_command(host: str = "localhost"):
    # Simulates command output while ensuring the deliberately vulnerable fixture never invokes a shell.
    for marker in ("API_SCANNER_CMD_7F3A", "API_SCANNER_CMD_9C2D"):
        if marker in host:
            return PlainTextResponse(marker)
    return PlainTextResponse(f"PING {host}: simulated")


@app.get("/api/vulnerable/nosql")
def vulnerable_nosql(request: Request, username: str = "alice"):
    if "username[$ne]" in request.query_params:
        return {"results": list(USERS.values())}
    if "username[$scanner_control]" in request.query_params:
        return {"results": []}
    return {
        "results": [
            value for value in USERS.values() if value["name"].lower() == username.lower()
        ]
    }


@app.get("/api/vulnerable/fetch")
def vulnerable_fetch(url: str = "https://example.invalid"):
    parsed = urlsplit(url)
    # The fixture permits only the Compose callback collector so tests cannot turn it
    # into a general-purpose network pivot.
    if parsed.hostname == "oast" and parsed.port == 8094 and parsed.path.startswith("/c/"):
        with urlopen(url, timeout=2) as response:  # noqa: S310 - allowlisted local test collector
            return {"fetched_status": response.status}
    return {"fetched_status": "blocked by fixture safety boundary"}


@app.post("/bulk")
def bulk(records: list[dict]) -> dict:
    # Intentionally no practical item limit and no rate limiter.
    return {"accepted": len(records)}
