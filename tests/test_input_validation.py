import httpx

from app.security_tests.input_validation import (
    build_prepared_request,
    eligible_points,
    path_traversal_evidence,
    sql_boolean_evidence,
    sql_error_evidence,
)


def _response(status: int, body: str, content_type: str = "application/json") -> httpx.Response:
    return httpx.Response(status, text=body, headers={"content-type": content_type})


def test_prepared_request_covers_parameter_locations_and_json_body():
    endpoint = {
        "base_url": "https://api.example.test/v1",
        "path": "/users/{user_id}",
        "method": "POST",
        "parameters": [
            {"name": "user_id", "location": "path", "schema": {"type": "string"}, "example": "42"},
            {"name": "q", "location": "query", "schema": {"type": "string"}, "example": "alice"},
            {"name": "X-Tenant", "location": "header", "schema": {"type": "string"}, "example": "acme"},
            {"name": "locale", "location": "cookie", "schema": {"type": "string"}, "example": "en"},
        ],
        "request_body": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "profile": {
                                "type": "object",
                                "properties": {"name": {"type": "string", "example": "Alice"}},
                            }
                        },
                    }
                }
            }
        },
    }
    points = {point.key: point for point in eligible_points(endpoint)}
    assert {"path:user_id", "query:q", "header:X-Tenant", "cookie:locale", "body:profile.name"} <= set(points)
    prepared = build_prepared_request(endpoint, {"body:profile.name": "changed"})
    assert prepared.url == "https://api.example.test/v1/users/42"
    assert prepared.params == [("q", "alice")]
    assert prepared.headers == {"X-Tenant": "acme"}
    assert prepared.cookies == {"locale": "en"}
    assert prepared.json_body == {"profile": {"name": "changed"}}


def test_header_mutations_are_serialized_as_valid_http_values():
    endpoint = {
        "base_url": "https://api.example.test",
        "path": "/orders/{order_id}",
        "method": "GET",
        "parameters": [
            {
                "name": "order_id",
                "location": "path",
                "required": True,
                "schema": {"type": "integer"},
                "example": 1002,
            },
            {
                "name": "X-User-Id",
                "location": "header",
                "schema": {"type": "string"},
                "example": "1",
            },
        ],
    }

    prepared = build_prepared_request(
        endpoint,
        {"header:X-User-Id": "' OR '1'='1' -- \r\n"},
    )

    assert prepared.headers["X-User-Id"] == "' OR '1'='1' --"
    # HTTPX/h11 must accept the serialized value instead of raising
    # LocalProtocolError before the request reaches the target.
    assert httpx.Request("GET", prepared.url, headers=prepared.headers).headers[
        "X-User-Id"
    ] == "' OR '1'='1' --"


def test_sql_analysis_requires_database_or_differential_evidence():
    baseline = _response(200, '{"results":[]}')
    sqlite_error = _response(500, '{"error":"SQLite_ERROR: near quote: syntax error"}')
    assert sql_error_evidence(baseline, sqlite_error)["database_markers"] == ["SQLite"]

    true_response = _response(200, '{"query":"payload","results":[{"id":1},{"id":2}]}')
    false_response = _response(200, '{"query":"payload","results":[]}')
    assert sql_boolean_evidence(true_response, false_response, "true", "false") is not None

    reflected_true = _response(200, '{"query":"true","results":[]}')
    reflected_false = _response(200, '{"query":"false","results":[]}')
    assert sql_boolean_evidence(reflected_true, reflected_false, "true", "false") is None


def test_path_traversal_analysis_requires_a_new_file_marker():
    baseline = _response(200, "Welcome")
    traversal = _response(200, "root:x:0:0:root:/root:/bin/sh", "text/plain")
    assert path_traversal_evidence(baseline, traversal)["matched_markers"] == [
        "Unix passwd file"
    ]
    assert path_traversal_evidence(traversal, traversal) is None
