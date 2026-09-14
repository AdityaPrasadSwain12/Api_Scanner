import json

import pytest

from app.ingestion.openapi import IngestionError, parse_api_document, parse_postman_collection

OPENAPI_31 = {
    "openapi": "3.1.0",
    "info": {"title": "Example", "version": "1"},
    "servers": [{"url": "https://api.example.test/v1"}],
    "components": {
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "parameters": {
            "ItemId": {
                "name": "item_id",
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
            }
        },
    },
    "security": [{"bearer": []}],
    "paths": {
        "/items/{item_id}": {
            "get": {
                "operationId": "getItem",
                "parameters": [{"$ref": "#/components/parameters/ItemId"}],
                "responses": {"200": {"description": "ok"}},
            },
            "post": {
                "security": [],
                "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"201": {"description": "created"}},
            },
        }
    },
}


def test_openapi_31_normalizes_operations():
    result = parse_api_document(OPENAPI_31, "https://fallback.test", 1_000_000)
    assert result.version == "3.1.0"
    assert len(result.endpoints) == 2
    get = next(item for item in result.endpoints if item.method == "GET")
    post = next(item for item in result.endpoints if item.method == "POST")
    assert get.base_url == "https://api.example.test/v1"
    assert get.parameters[0].name == "item_id"
    assert get.auth_required is True
    assert post.auth_required is False
    assert post.content_types == ["application/json"]


def test_openapi_yaml_and_30_are_supported():
    raw = """openapi: 3.0.3
info: {title: Test, version: '1'}
paths:
  /ping:
    get:
      responses:
        '200': {description: ok}
"""
    result = parse_api_document(raw, "https://api.example.test", 100_000)
    assert result.version == "3.0.3"
    assert result.endpoints[0].path == "/ping"


def test_swagger_2_normalizes_to_common_model():
    document = {
        "swagger": "2.0",
        "info": {"title": "Test", "version": "1"},
        "host": "api.example.test",
        "basePath": "/v2",
        "schemes": ["https"],
        "consumes": ["application/json"],
        "paths": {
            "/things": {
                "post": {
                    "parameters": [{"name": "body", "in": "body", "schema": {"type": "object"}}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    result = parse_api_document(json.dumps(document), "https://fallback.test", 100_000)
    assert result.version == "2.0"
    assert result.endpoints[0].base_url == "https://api.example.test/v2"
    assert result.endpoints[0].request_body is not None


def test_rejects_unsupported_or_oversize_document():
    with pytest.raises(IngestionError, match="neither OpenAPI"):
        parse_api_document({"paths": {}}, "https://api.example.test", 1000)
    with pytest.raises(IngestionError, match="MAX_SPEC_SIZE"):
        parse_api_document("x" * 2000, "https://api.example.test", 1000)


def test_postman_folders_variables_and_auth_are_normalized():
    collection = {
        "info": {
            "name": "Test",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [{"key": "baseUrl", "value": "https://api.example.test"}],
        "item": [
            {
                "name": "Users",
                "item": [
                    {
                        "name": "List",
                        "request": {
                            "method": "GET",
                            "url": {"raw": "{{baseUrl}}/users"},
                            "auth": {"type": "bearer"},
                        },
                    }
                ],
            }
        ],
    }
    result = parse_postman_collection(collection, "https://fallback.test", 100_000)
    assert result.endpoints[0].path == "/users"
    assert result.endpoints[0].tags == ["Users"]
    assert result.endpoints[0].auth_required is True
