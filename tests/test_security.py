from app.core.logging import redact, redact_known_values
from app.core.secrets import SecretStore, api_key_matches
from app.engines.custom import CustomApiEngine
from app.security.auth import apply_auth

KEY = "NQ4M5lY8yl5wE9bG6vRCcQ5Rk4j1g5HVFFOS5iQlJ0k="


def test_secret_store_encrypts_and_authentication_round_trips():
    store = SecretStore(KEY)
    encrypted = store.encrypt({"token": "super-secret-token"})
    assert "super-secret-token" not in encrypted
    assert store.decrypt(encrypted) == {"token": "super-secret-token"}


def test_recursive_secret_redaction():
    value = {
        "Authorization": "Bearer abc.def.ghi",
        "nested": {"api_key": "secret", "message": "use Basic dXNlcjpwYXNz"},
        "cookies": ["safe"],
    }
    safe = redact(value)
    assert safe["Authorization"] == "[REDACTED]"
    assert safe["nested"]["api_key"] == "[REDACTED]"
    assert "dXNlcjpwYXNz" not in safe["nested"]["message"]


def test_known_value_redaction_preserves_specification_schema():
    document = {
        "components": {"schemas": {"User": {"properties": {"password": {"type": "string"}}}}},
        "example": "Bearer live-token-value",
    }
    safe = redact_known_values(document, {"token": "live-token-value"})
    assert safe["components"]["schemas"]["User"]["properties"]["password"] == {"type": "string"}
    assert "live-token-value" not in safe["example"]


def test_supported_authentication_application():
    bearer = apply_auth("https://api.test/x", {"type": "BEARER", "token": "token"})
    assert bearer.headers == {"Authorization": "Bearer token"}
    basic = apply_auth("https://api.test/x", {"type": "BASIC", "username": "u", "password": "p"})
    assert basic.headers["Authorization"].startswith("Basic ")
    api_key = apply_auth(
        "https://api.test/x?a=1",
        {"type": "API_KEY", "name": "key", "key": "value", "location": "query"},
    )
    assert api_key.url == "https://api.test/x?a=1&key=value"


def test_api_key_comparison():
    assert api_key_matches("", None)
    assert api_key_matches("expected", "expected")
    assert not api_key_matches("expected", "wrong")


def test_bola_requires_a_documented_protected_object_operation():
    public_object_route = {
        "method": "GET",
        "auth_required": False,
        "parameters": [{"name": "id", "location": "path"}],
    }
    protected_object_route = {**public_object_route, "auth_required": True}

    assert not CustomApiEngine._bola_applicable(public_object_route)
    assert CustomApiEngine._bola_applicable(protected_object_route)
