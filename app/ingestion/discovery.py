import json
from urllib.parse import urljoin, urlsplit

from app.domain import EndpointDefinition
from app.ingestion.openapi import IngestionError, ParsedInventory, parse_api_document
from app.security.scope import ScopedHttpClient

COMMON_SPEC_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/v3/api-docs",
)


async def fetch_specification(
    client: ScopedHttpClient, url: str, max_size: int, target_url: str | None = None
) -> ParsedInventory:
    response = await client.request(
        "GET", url, headers={"Accept": "application/json, application/yaml"}
    )
    if response.status_code != 200:
        raise IngestionError(f"specification URL returned HTTP {response.status_code}")
    content_type = response.headers.get("content-type", "").lower()
    if not any(
        value in content_type for value in ("json", "yaml", "yml", "text/plain", "octet-stream")
    ):
        raise IngestionError(f"unsupported specification content type: {content_type or 'missing'}")
    return parse_api_document(response.content, target_url or url, max_size)


async def discover_inventory(
    client: ScopedHttpClient,
    target_url: str,
    max_size: int,
    user_paths: list[str] | None = None,
) -> tuple[ParsedInventory | None, list[EndpointDefinition], list[dict]]:
    observations: list[dict] = []
    base = f"{urlsplit(target_url).scheme}://{urlsplit(target_url).netloc}"
    for path in COMMON_SPEC_PATHS:
        url = urljoin(base, path)
        try:
            response = await client.request("GET", url, headers={"Accept": "application/json, */*"})
        except Exception as exc:
            observations.append({"url": url, "outcome": "error", "detail": str(exc)})
            continue
        observations.append({"url": url, "outcome": response.status_code})
        if response.status_code != 200:
            continue
        try:
            return parse_api_document(response.content, target_url, max_size), [], observations
        except IngestionError:
            continue

    endpoints: dict[str, EndpointDefinition] = {}
    seed_paths = [urlsplit(target_url).path or "/", *(user_paths or [])]
    for path in seed_paths:
        if not path.startswith("/"):
            path = "/" + path
        url = urljoin(base, path)
        try:
            response = await client.request("GET", url, headers={"Accept": "application/json"})
        except Exception as exc:
            observations.append({"url": url, "outcome": "error", "detail": str(exc)})
            continue
        observations.append({"url": url, "outcome": response.status_code})
        content_type = response.headers.get("content-type", "").lower()
        if response.status_code < 500 and ("json" in content_type or path != "/"):
            endpoint = EndpointDefinition(
                endpoint_id=EndpointDefinition.build_id(base, path, "GET"),
                base_url=base,
                path=path,
                method="GET",
                source="CONTROLLED_DISCOVERY",
                confidence="MEDIUM" if "json" in content_type else "LOW",
            )
            endpoints[endpoint.endpoint_id] = endpoint
            if "json" in content_type:
                try:
                    body = response.json()
                except json.JSONDecodeError:
                    body = None
                if isinstance(body, dict):
                    for value in body.values():
                        if isinstance(value, str) and value.startswith("/") and len(value) < 500:
                            linked = EndpointDefinition(
                                endpoint_id=EndpointDefinition.build_id(base, value, "GET"),
                                base_url=base,
                                path=value,
                                method="GET",
                                source="RESPONSE_LINK",
                                confidence="LOW",
                            )
                            endpoints[linked.endpoint_id] = linked
    return None, list(endpoints.values()), observations
