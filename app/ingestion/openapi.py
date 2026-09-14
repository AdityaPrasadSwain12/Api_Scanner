import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import yaml

from app.domain import EndpointDefinition, ParameterDefinition

HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


class IngestionError(ValueError):
    pass


@dataclass
class ParsedInventory:
    version: str
    base_urls: list[str]
    endpoints: list[EndpointDefinition]
    document: dict[str, Any]
    sha256: str


def load_document(raw: str | bytes | dict[str, Any], max_size: int) -> dict[str, Any]:
    if isinstance(raw, dict):
        serialized = json.dumps(raw).encode()
        document = raw
    else:
        serialized = raw.encode() if isinstance(raw, str) else raw
        if len(serialized) > max_size:
            raise IngestionError("specification exceeds MAX_SPEC_SIZE")
        text = serialized.decode("utf-8-sig")
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            try:
                document = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                raise IngestionError("invalid JSON or YAML specification") from exc
    if len(serialized) > max_size:
        raise IngestionError("specification exceeds MAX_SPEC_SIZE")
    if not isinstance(document, dict):
        raise IngestionError("specification root must be an object")
    return document


def _local_ref(document: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        return {}
    current: Any = document
    for part in reference[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            return {}
        current = current[part]
    return current if isinstance(current, dict) else {}


def _resolve(document: dict[str, Any], value: Any) -> Any:
    if isinstance(value, dict) and "$ref" in value:
        return {
            **_local_ref(document, str(value["$ref"])),
            **{k: v for k, v in value.items() if k != "$ref"},
        }
    return value


def _resolve_deep(
    document: dict[str, Any], value: Any, *, seen: frozenset[str] = frozenset(), depth: int = 0
) -> Any:
    """Resolve local references used by request schemas without fetching external resources."""
    if depth > 30:
        return {}
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/"):
            if reference in seen:
                return {}
            resolved = {
                **_local_ref(document, reference),
                **{key: child for key, child in value.items() if key != "$ref"},
            }
            return _resolve_deep(
                document, resolved, seen=seen | {reference}, depth=depth + 1
            )
        return {
            str(key): _resolve_deep(document, child, seen=seen, depth=depth + 1)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [
            _resolve_deep(document, child, seen=seen, depth=depth + 1) for child in value
        ]
    return value


def _servers(document: dict[str, Any], target_url: str) -> tuple[str, list[str]]:
    if "openapi" in document:
        version = str(document["openapi"])
        if not (version.startswith("3.0") or version.startswith("3.1")):
            raise IngestionError(f"unsupported OpenAPI version: {version}")
        urls = []
        for server in document.get("servers", []):
            if isinstance(server, dict) and server.get("url"):
                server_url = str(server["url"])
                for name, variable in server.get("variables", {}).items():
                    default = variable.get("default", "") if isinstance(variable, dict) else ""
                    server_url = server_url.replace("{" + name + "}", str(default))
                urls.append(urljoin(target_url.rstrip("/") + "/", server_url))
        return version, urls or [target_url]
    if str(document.get("swagger", "")) == "2.0":
        schemes = document.get("schemes") or [target_url.split(":", 1)[0]]
        host = document.get("host")
        base_path = str(document.get("basePath", "/"))
        if host:
            return "2.0", [f"{schemes[0]}://{host}{base_path}".rstrip("/")]
        return "2.0", [urljoin(target_url.rstrip("/") + "/", base_path.lstrip("/"))]
    raise IngestionError("document is neither OpenAPI 3.x nor Swagger 2.0")


def _security_required(document: dict[str, Any], operation: dict[str, Any]) -> bool:
    security = operation.get("security", document.get("security", []))
    return bool(security)


def _parameters(
    document: dict[str, Any], path_item: dict[str, Any], operation: dict[str, Any]
) -> list[ParameterDefinition]:
    values = [*path_item.get("parameters", []), *operation.get("parameters", [])]
    by_key: dict[tuple[str, str], ParameterDefinition] = {}
    for raw in values:
        item = _resolve(document, raw)
        if not isinstance(item, dict) or not item.get("name") or not item.get("in"):
            continue
        location = str(item["in"])
        if location not in {"path", "query", "header", "cookie"}:
            continue
        schema = _resolve(document, item.get("schema", {}))
        example = item.get("example", schema.get("example") if isinstance(schema, dict) else None)
        by_key[(str(item["name"]), location)] = ParameterDefinition(
            name=str(item["name"]),
            location=location,
            required=bool(item.get("required", location == "path")),
            schema=schema if isinstance(schema, dict) else {},
            example=example,
        )
    return list(by_key.values())


def _request_body(document: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any] | None:
    if "requestBody" in operation:
        body = _resolve(document, operation["requestBody"])
        return _resolve_deep(document, body) if isinstance(body, dict) else None
    for parameter in operation.get("parameters", []):
        item = _resolve(document, parameter)
        if isinstance(item, dict) and item.get("in") == "body":
            return {
                "required": bool(item.get("required")),
                "content": {
                    "application/json": {
                        "schema": _resolve_deep(document, item.get("schema", {}))
                    }
                },
            }
    return None


def parse_api_document(
    raw: str | bytes | dict[str, Any], target_url: str, max_size: int
) -> ParsedInventory:
    document = load_document(raw, max_size)
    version, base_urls = _servers(document, target_url)
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise IngestionError("specification has no paths object")
    endpoints: list[EndpointDefinition] = []
    for path, unresolved_path_item in paths.items():
        path_item = _resolve(document, unresolved_path_item)
        if not isinstance(path_item, dict) or not str(path).startswith("/"):
            continue
        for method, unresolved_operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            operation = _resolve(document, unresolved_operation)
            if not isinstance(operation, dict):
                continue
            request_body = _request_body(document, operation)
            content = request_body.get("content", {}) if request_body else {}
            if version == "2.0" and document.get("consumes"):
                content_types = [str(v) for v in document["consumes"]]
            else:
                content_types = list(content) if isinstance(content, dict) else []
            base_url = base_urls[0].rstrip("/")
            endpoints.append(
                EndpointDefinition(
                    endpoint_id=EndpointDefinition.build_id(base_url, str(path), method),
                    base_url=base_url,
                    path=str(path),
                    method=method.upper(),
                    operation_id=operation.get("operationId"),
                    tags=[str(v) for v in operation.get("tags", [])],
                    parameters=_parameters(document, path_item, operation),
                    request_body=request_body,
                    responses=operation.get("responses", {}),
                    content_types=content_types,
                    auth_required=_security_required(document, operation),
                    source=f"OPENAPI_{version}",
                )
            )
    if not endpoints:
        raise IngestionError("specification contains no supported operations")
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return ParsedInventory(
        version, base_urls, endpoints, document, hashlib.sha256(serialized).hexdigest()
    )


def parse_postman_collection(
    document: dict[str, Any], target_url: str, max_size: int
) -> ParsedInventory:
    serialized = json.dumps(document).encode()
    if len(serialized) > max_size:
        raise IngestionError("Postman collection exceeds MAX_SPEC_SIZE")
    schema = str(document.get("info", {}).get("schema", ""))
    if "schema.getpostman.com" not in schema:
        raise IngestionError("unsupported Postman collection")
    variables = {str(v.get("key")): str(v.get("value", "")) for v in document.get("variable", [])}
    variables.setdefault("baseUrl", target_url.rstrip("/"))
    endpoints: list[EndpointDefinition] = []

    def substitute(value: str) -> str:
        return re.sub(r"{{([^}]+)}}", lambda m: variables.get(m.group(1), m.group(0)), value)

    def walk(items: list[Any], folders: list[str]) -> None:
        for item in items:
            if not isinstance(item, dict):
                continue
            if "item" in item:
                walk(item.get("item", []), [*folders, str(item.get("name", "folder"))])
                continue
            request = item.get("request", {})
            if isinstance(request, str):
                request = {"url": request, "method": "GET"}
            url_value = request.get("url", "")
            if isinstance(url_value, dict):
                raw_url = str(url_value.get("raw", ""))
            else:
                raw_url = str(url_value)
            raw_url = substitute(raw_url)
            if not raw_url:
                continue
            from urllib.parse import urlsplit

            parsed = urlsplit(raw_url)
            path = parsed.path or "/"
            method = str(request.get("method", "GET")).upper()
            endpoints.append(
                EndpointDefinition(
                    endpoint_id=EndpointDefinition.build_id(target_url, path, method),
                    base_url=f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url,
                    path=path,
                    method=method,
                    operation_id=str(item.get("name", "")) or None,
                    tags=folders,
                    auth_required=bool(request.get("auth") or document.get("auth")),
                    source="POSTMAN",
                    confidence="HIGH",
                )
            )

    walk(document.get("item", []), [])
    if not endpoints:
        raise IngestionError("Postman collection contains no requests")
    digest = hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
    return ParsedInventory("postman-2.x", [target_url], endpoints, document, digest)
