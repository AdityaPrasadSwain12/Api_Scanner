import pytest

from app.security.scope import ScopeGuard, ScopeViolation, _host_matches


def test_exact_and_wildcard_host_matching():
    assert _host_matches("api.example.com", "api.example.com")
    assert _host_matches("v1.example.com", "*.example.com")
    assert not _host_matches("example.com", "*.example.com")
    assert not _host_matches("evil-example.com", "*.example.com")


@pytest.mark.asyncio
async def test_rejects_userinfo_scheme_and_out_of_scope():
    guard = ScopeGuard(["api.example.test"])
    with pytest.raises(ScopeViolation, match="only http"):
        await guard.validate("file:///etc/passwd")
    with pytest.raises(ScopeViolation, match="userinfo"):
        await guard.validate("https://user:pass@api.example.test/")
    with pytest.raises(ScopeViolation, match="outside"):
        await guard.validate("https://other.example.test/")


@pytest.mark.asyncio
async def test_rejects_private_resolution_by_default(monkeypatch):
    guard = ScopeGuard(["api.example.test"])

    async def private(*_):
        return {"127.0.0.1"}

    monkeypatch.setattr(guard, "_resolve", private)
    with pytest.raises(ScopeViolation, match="private"):
        await guard.validate("https://api.example.test")


@pytest.mark.asyncio
async def test_allows_private_only_when_explicit(monkeypatch):
    guard = ScopeGuard(["api.example.test"], allow_private=True)

    async def private(*_):
        return {"10.0.0.10"}

    monkeypatch.setattr(guard, "_resolve", private)
    value = await guard.validate("https://api.example.test")
    assert value.addresses == ("10.0.0.10",)
