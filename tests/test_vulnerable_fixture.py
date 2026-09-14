from vulnerable_test_api.main import app


def test_vulnerable_fixture_documents_the_deliberate_authentication_gap():
    schema = app.openapi()

    assert schema["paths"]["/private"]["get"]["security"] == [{"HTTPBearer": []}]
    assert "security" not in schema["paths"]["/public"]["get"]
    assert {
        "/api/vulnerable/users/search",
        "/api/vulnerable/files",
        "/api/vulnerable/message",
        "/api/vulnerable/redirect",
        "/api/vulnerable/command",
        "/api/vulnerable/nosql",
        "/api/vulnerable/fetch",
    } <= set(schema["paths"])
