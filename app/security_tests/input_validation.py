"""Bounded request construction and high-signal input-validation analysis.

The helpers in this module are deliberately deterministic. They generate requests from
the normalized endpoint model and only promote a runtime finding when the response
contains vulnerability-specific evidence. Merely receiving a different HTTP response is
not sufficient.
"""

from __future__ import annotations

import copy
import html
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import quote, urljoin, urlsplit

import httpx

from app.analysis.authorization import response_similarity

PointLocation = Literal["path", "query", "header", "cookie", "body"]

SQL_ERROR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PostgreSQL", re.compile(r"(?i)(postgresql|pg_query|psycopg|unterminated quoted string)")),
    ("MySQL/MariaDB", re.compile(r"(?i)(mysql|mariadb|you have an error in your sql syntax)")),
    ("SQLite", re.compile(r"(?i)(sqlite[_ ]?error|sqlite3?\.|near [\"'].*syntax error)")),
    ("Microsoft SQL Server", re.compile(r"(?i)(sql server|sqlstate|unclosed quotation mark|odbc sql)")),
    ("Oracle", re.compile(r"(?i)(ora-\d{4,5}|oracle.*error|quoted string not properly terminated)")),
    ("JDBC", re.compile(r"(?i)(jdbc.*exception|java\.sql\.sqlexception)")),
    ("Generic SQL", re.compile(r"(?i)(sql syntax|syntax error.*sql|database error|query failed)")),
)
NOSQL_ERROR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("MongoDB", re.compile(r"(?i)(mongo(error|servererror)|mongodb|bson|mongoose.*(cast|error))")),
    ("CouchDB", re.compile(r"(?i)(couchdb|invalid.*selector|mango query)")),
    ("NoSQL operator", re.compile(r"(?i)(unknown|invalid|unsupported).*(\$ne|\$where|operator)")),
)

TRAVERSAL_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Unix passwd file", re.compile(r"(?m)^root:x:0:0:")),
    ("Unix passwd file", re.compile(r"(?m)^(daemon|bin|nobody):x?:\d+:\d+:")),
    ("Windows initialization file", re.compile(r"(?im)^\s*\[(fonts|extensions|mci extensions|files)\]\s*$")),
    ("controlled traversal canary", re.compile(r"API_SCANNER_TRAVERSAL_CANARY")),
)

PATH_HINT = re.compile(
    r"(?i)(file|filename|filepath|path|directory|dir|folder|document|template|include|download|attachment|object|key|name)"
)
URL_HINT = re.compile(
    r"(?i)(url|uri|redirect|return|next|continue|destination|dest|callback|webhook|link|to)"
)
COMMAND_HINT = re.compile(r"(?i)(cmd|command|exec|execute|shell|process|ping|host|hostname|ip|lookup)")
UNSAFE_HEADER_NAMES = {"authorization", "cookie", "host", "content-length", "transfer-encoding"}


def _wire_safe_header_value(value: Any) -> str:
    """Serialize a documented or mutated header value without HTTP control bytes.

    HTTP/1.1 clients reject leading/trailing whitespace and CR/LF in header values
    before a request reaches the target. Active probes must remain valid HTTP so a
    single header mutation cannot abort the rest of an endpoint assessment.
    """
    serialized = str(value)
    without_controls = "".join(
        " " if ord(character) < 32 or ord(character) == 127 else character
        for character in serialized
    )
    return without_controls.strip()


@dataclass(frozen=True)
class MutationPoint:
    key: str
    name: str
    location: PointLocation
    baseline: Any
    schema_type: str = "string"
    body_path: tuple[str | int, ...] = ()
    media_type: str | None = None

    @property
    def label(self) -> str:
        return f"{self.name} ({self.location})"


@dataclass
class PreparedRequest:
    url: str
    params: list[tuple[str, str]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    json_body: Any = None
    data_body: dict[str, Any] | None = None
    media_type: str | None = None

    def kwargs(self) -> dict[str, Any]:
        values: dict[str, Any] = {}
        if self.params:
            values["params"] = self.params
        if self.headers:
            values["headers"] = self.headers
        if self.cookies:
            values["cookies"] = self.cookies
        if self.json_body is not None:
            values["json"] = self.json_body
        elif self.data_body is not None:
            values["data"] = self.data_body
        return values


def _schema_type(schema: dict[str, Any]) -> str:
    declared = schema.get("type")
    if isinstance(declared, list):
        declared = next((value for value in declared if value != "null"), "string")
    if declared:
        return str(declared)
    if "properties" in schema:
        return "object"
    if "items" in schema:
        return "array"
    return "string"


def _sample(schema: dict[str, Any], *, fallback: Any = "test", depth: int = 0) -> Any:
    if depth > 8:
        return fallback
    for key in ("example", "default", "const"):
        if key in schema:
            return copy.deepcopy(schema[key])
    examples = schema.get("examples")
    if isinstance(examples, list) and examples:
        return copy.deepcopy(examples[0])
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return copy.deepcopy(enum[0])
    for choice_key in ("oneOf", "anyOf"):
        choices = schema.get(choice_key)
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            return _sample(choices[0], fallback=fallback, depth=depth + 1)
    if isinstance(schema.get("allOf"), list):
        merged: dict[str, Any] = {"type": "object", "properties": {}}
        for part in schema["allOf"]:
            if isinstance(part, dict):
                merged["properties"].update(part.get("properties", {}))
        if merged["properties"]:
            return _sample(merged, fallback=fallback, depth=depth + 1)
    kind = _schema_type(schema)
    if kind == "object":
        properties = schema.get("properties", {})
        return {
            str(name): _sample(value if isinstance(value, dict) else {}, depth=depth + 1)
            for name, value in properties.items()
        }
    if kind == "array":
        items = schema.get("items", {})
        return [_sample(items if isinstance(items, dict) else {}, depth=depth + 1)]
    if kind == "integer":
        return int(schema.get("minimum", 1))
    if kind == "number":
        return float(schema.get("minimum", 1))
    if kind == "boolean":
        return True
    return fallback


def _body_definition(endpoint: dict[str, Any]) -> tuple[str | None, Any, dict[str, Any]]:
    request_body = endpoint.get("request_body") or {}
    content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
    if not isinstance(content, dict) or not content:
        return None, None, {}
    preferred = next(
        (
            value
            for value in (
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
            )
            if value in content
        ),
        next(iter(content)),
    )
    definition = content.get(preferred, {})
    definition = definition if isinstance(definition, dict) else {}
    schema = definition.get("schema", {})
    schema = schema if isinstance(schema, dict) else {}
    example = definition.get("example", request_body.get("example"))
    body = copy.deepcopy(example) if example is not None else _sample(schema, fallback={})
    return preferred, body, schema


def _body_points(
    value: Any,
    schema: dict[str, Any],
    media_type: str,
    path: tuple[str | int, ...] = (),
) -> list[MutationPoint]:
    output: list[MutationPoint] = []
    if isinstance(value, dict):
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        for key, child in value.items():
            child_schema = properties.get(key, {}) if isinstance(properties, dict) else {}
            output.extend(
                _body_points(
                    child,
                    child_schema if isinstance(child_schema, dict) else {},
                    media_type,
                    (*path, str(key)),
                )
            )
        return output
    if isinstance(value, list):
        item_schema = schema.get("items", {}) if isinstance(schema, dict) else {}
        for index, child in enumerate(value[:3]):
            output.extend(
                _body_points(
                    child,
                    item_schema if isinstance(item_schema, dict) else {},
                    media_type,
                    (*path, index),
                )
            )
        return output
    if isinstance(value, str | int | float) or value is None:
        name = ".".join(str(part) for part in path) or "$body"
        output.append(
            MutationPoint(
                key=f"body:{name}",
                name=name,
                location="body",
                baseline=value,
                schema_type=_schema_type(schema),
                body_path=path,
                media_type=media_type,
            )
        )
    return output


def eligible_points(endpoint: dict[str, Any]) -> list[MutationPoint]:
    """Return deterministic scalar mutation points for parameters and request bodies."""
    points: list[MutationPoint] = []
    for parameter in endpoint.get("parameters", []):
        location = str(parameter.get("location", ""))
        name = str(parameter.get("name", ""))
        if location not in {"path", "query", "header", "cookie"} or not name:
            continue
        if location == "header" and name.lower() in UNSAFE_HEADER_NAMES:
            continue
        schema = parameter.get("schema") or {}
        schema = schema if isinstance(schema, dict) else {}
        sample = parameter.get("example")
        if sample is None:
            sample = _sample(schema)
        if not isinstance(sample, str | int | float) and sample is not None:
            continue
        points.append(
            MutationPoint(
                key=f"{location}:{name}",
                name=name,
                location=location,  # type: ignore[arg-type]
                baseline=sample,
                schema_type=_schema_type(schema),
            )
        )
    media_type, body, schema = _body_definition(endpoint)
    if media_type and body is not None:
        points.extend(_body_points(body, schema, media_type))
    return points


def _replace_body_value(body: Any, path: tuple[str | int, ...], value: Any) -> Any:
    if not path:
        return value
    current = body
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = value
    return body


def build_prepared_request(
    endpoint: dict[str, Any], overrides: dict[str, Any] | None = None
) -> PreparedRequest:
    overrides = overrides or {}
    points = {point.key: point for point in eligible_points(endpoint)}
    path = str(endpoint["path"])
    params: list[tuple[str, str]] = []
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    for point in points.values():
        if point.location == "body":
            continue
        value = overrides.get(point.key, point.baseline)
        serialized = str(value)
        if point.location == "path":
            path = path.replace("{" + point.name + "}", quote(serialized, safe=""))
        elif point.location == "query":
            params.append((point.name, serialized))
        elif point.location == "header":
            headers[point.name] = _wire_safe_header_value(value)
        elif point.location == "cookie":
            cookies[point.name] = serialized
    media_type, body, _ = _body_definition(endpoint)
    if media_type and body is not None:
        body = copy.deepcopy(body)
        for key, value in overrides.items():
            point = points.get(key)
            if point and point.location == "body":
                body = _replace_body_value(body, point.body_path, value)
    url = urljoin(str(endpoint["base_url"]).rstrip("/") + "/", path.lstrip("/"))
    prepared = PreparedRequest(url=url, params=params, headers=headers, cookies=cookies)
    if media_type and (media_type == "application/json" or media_type.endswith("+json")):
        prepared.json_body = body
    elif media_type in {"application/x-www-form-urlencoded", "multipart/form-data"}:
        prepared.data_body = body if isinstance(body, dict) else {"value": body}
    elif media_type and body is not None:
        prepared.data_body = {"value": body}
    prepared.media_type = media_type
    return prepared


def _new_sql_markers(baseline: str, mutated: str) -> list[str]:
    baseline_names = {name for name, pattern in SQL_ERROR_PATTERNS if pattern.search(baseline)}
    return [
        name
        for name, pattern in SQL_ERROR_PATTERNS
        if name not in baseline_names and pattern.search(mutated)
    ]


def sql_error_evidence(baseline: httpx.Response, mutated: httpx.Response) -> dict[str, Any] | None:
    markers = _new_sql_markers(baseline.text, mutated.text)
    if not markers:
        return None
    return {
        "technique": "error-based",
        "database_markers": markers,
        "baseline_status": baseline.status_code,
        "mutated_status": mutated.status_code,
    }


def _without_reflection(text: str, payloads: tuple[str, ...]) -> str:
    output = text
    for payload in payloads:
        variants = (payload, html.escape(payload), quote(payload, safe=""), quote(payload))
        for value in variants:
            output = output.replace(value, "<SCANNER_INPUT>")
    return output


def _collection_count(text: str) -> int | None:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("results", "items", "data", "users", "records", "rows"):
            child = value.get(key)
            if isinstance(child, list):
                return len(child)
    return None


def sql_boolean_evidence(
    true_response: httpx.Response,
    false_response: httpx.Response,
    true_payload: str,
    false_payload: str,
) -> dict[str, Any] | None:
    if not (200 <= true_response.status_code < 400 and 200 <= false_response.status_code < 400):
        return None
    true_body = _without_reflection(true_response.text, (true_payload, false_payload))
    false_body = _without_reflection(false_response.text, (true_payload, false_payload))
    similarity = response_similarity(true_body, false_body)
    true_count = _collection_count(true_body)
    false_count = _collection_count(false_body)
    cardinality_signal = (
        true_count is not None
        and false_count is not None
        and true_count > false_count
        and (true_count - false_count >= 1)
    )
    length_delta = abs(len(true_body) - len(false_body))
    differential_signal = similarity < 0.72 and length_delta >= 20
    if not (cardinality_signal or differential_signal):
        return None
    return {
        "technique": "boolean-based differential",
        "true_status": true_response.status_code,
        "false_status": false_response.status_code,
        "response_similarity": round(similarity, 3),
        "response_length_delta": length_delta,
        "true_collection_items": true_count,
        "false_collection_items": false_count,
    }


def nosql_injection_evidence(
    baseline: httpx.Response,
    operator_response: httpx.Response,
    control_response: httpx.Response,
) -> dict[str, Any] | None:
    baseline_markers = {
        name for name, pattern in NOSQL_ERROR_PATTERNS if pattern.search(baseline.text)
    }
    new_markers = [
        name
        for name, pattern in NOSQL_ERROR_PATTERNS
        if name not in baseline_markers and pattern.search(operator_response.text)
    ]
    if new_markers:
        return {
            "technique": "NoSQL operator error",
            "database_markers": new_markers,
            "baseline_status": baseline.status_code,
            "mutated_status": operator_response.status_code,
        }
    if not (
        200 <= operator_response.status_code < 400
        and 200 <= control_response.status_code < 400
    ):
        return None
    operator_count = _collection_count(operator_response.text)
    control_count = _collection_count(control_response.text)
    similarity = response_similarity(operator_response.text, control_response.text)
    if not (
        operator_count is not None
        and control_count is not None
        and operator_count > control_count
        and similarity < 0.85
    ):
        return None
    return {
        "technique": "NoSQL operator differential",
        "operator_collection_items": operator_count,
        "control_collection_items": control_count,
        "response_similarity": round(similarity, 3),
    }


def path_traversal_evidence(
    baseline: httpx.Response, mutated: httpx.Response
) -> dict[str, Any] | None:
    baseline_markers = {name for name, pattern in TRAVERSAL_MARKERS if pattern.search(baseline.text)}
    markers = [
        name
        for name, pattern in TRAVERSAL_MARKERS
        if name not in baseline_markers and pattern.search(mutated.text)
    ]
    if not markers:
        return None
    return {
        "technique": "local-file-read marker",
        "matched_markers": markers,
        "baseline_status": baseline.status_code,
        "mutated_status": mutated.status_code,
    }


def reflected_xss_evidence(payload: str, response: httpx.Response) -> dict[str, Any] | None:
    content_type = response.headers.get("content-type", "").lower()
    if payload not in response.text or not any(
        value in content_type for value in ("text/html", "application/xhtml+xml")
    ):
        return None
    return {
        "technique": "unencoded active-content reflection",
        "content_type": content_type,
        "status_code": response.status_code,
    }


def open_redirect_evidence(
    callback_url: str, response: httpx.Response
) -> dict[str, Any] | None:
    location = response.headers.get("location")
    if response.status_code not in {301, 302, 303, 307, 308} or not location:
        return None
    expected = urlsplit(callback_url)
    destination = urlsplit(location)
    if destination.hostname != expected.hostname:
        return None
    return {
        "technique": "external Location header control",
        "status_code": response.status_code,
        "location_host": destination.hostname,
    }


def command_execution_evidence(
    payload: str, marker: str, response: httpx.Response
) -> dict[str, Any] | None:
    # A verbatim echo is input reflection, not proof of command execution.
    if marker not in response.text or payload in response.text:
        return None
    return {
        "technique": "non-destructive output canary",
        "status_code": response.status_code,
        "output_marker": marker,
    }


def point_matches(point: MutationPoint, pattern: re.Pattern[str], endpoint: dict[str, Any]) -> bool:
    return bool(pattern.search(point.name) or pattern.search(str(endpoint.get("path", ""))))
