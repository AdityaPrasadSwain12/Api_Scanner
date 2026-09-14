import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from app.core.logging import redact


class ScopeViolation(ValueError):
    pass


def _host_matches(host: str, rule: str) -> bool:
    host = host.lower().rstrip(".")
    rule = rule.lower().rstrip(".")
    if rule.startswith("*."):
        suffix = rule[1:]
        return host.endswith(suffix) and host != suffix[1:]
    return host == rule


def _is_forbidden_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    return not ip.is_global


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    host: str
    addresses: tuple[str, ...]


class ScopeGuard:
    def __init__(self, allowed_hosts: list[str], *, allow_private: bool = False):
        self.allowed_hosts = [item.lower().rstrip(".") for item in allowed_hosts]
        self.allow_private = allow_private

    async def validate(self, url: str) -> ValidatedTarget:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeViolation("only http and https targets are supported")
        if parsed.username or parsed.password:
            raise ScopeViolation("userinfo is not allowed in target URLs")
        if not parsed.hostname:
            raise ScopeViolation("target URL has no hostname")
        host = parsed.hostname.encode("idna").decode().lower().rstrip(".")
        if not self.allowed_hosts or not any(
            _host_matches(host, rule) for rule in self.allowed_hosts
        ):
            raise ScopeViolation(f"host {host!r} is outside the authorized allowlist")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise ScopeViolation("invalid target port") from exc
        addresses = await self._resolve(host, port)
        if not addresses:
            raise ScopeViolation("target hostname did not resolve")
        if not self.allow_private and any(_is_forbidden_ip(ip) for ip in addresses):
            raise ScopeViolation(
                "target resolves to a private, loopback, link-local, or reserved address"
            )
        clean_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        return ValidatedTarget(clean_url, host, tuple(sorted(addresses)))

    async def _resolve(self, host: str, port: int) -> set[str]:
        try:
            ipaddress.ip_address(host.split("%", 1)[0])
            return {host}
        except ValueError:
            pass
        loop = asyncio.get_running_loop()
        try:
            records = await loop.run_in_executor(
                None, lambda: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            )
        except socket.gaierror as exc:
            raise ScopeViolation("target hostname could not be resolved") from exc
        return {record[4][0] for record in records}


class ScopedHttpClient:
    """HTTP client which validates every request and redirect destination."""

    def __init__(
        self,
        guard: ScopeGuard,
        *,
        timeout: float,
        max_response_size: int,
        max_redirects: int = 3,
    ):
        self.guard = guard
        self.timeout = timeout
        self.max_response_size = max_response_size
        self.max_redirects = max_redirects

    async def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        follow_redirects = bool(kwargs.pop("follow_redirects", True))
        current = url
        original_host: str | None = None
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            for redirect_number in range(self.max_redirects + 1):
                validated = await self.guard.validate(current)
                original_host = original_host or validated.host
                # Resolving immediately before dispatch narrows DNS-rebinding exposure. Engine
                # containers additionally run with redirect following disabled.
                if validated.host != original_host:
                    raise ScopeViolation("redirect changed the authorized target host")
                async with client.stream(method, validated.url, **kwargs) as response:
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > self.max_response_size:
                            raise ValueError("response exceeded MAX_RESPONSE_SIZE")
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    result = httpx.Response(
                        response.status_code,
                        headers=response.headers,
                        content=body,
                        request=response.request,
                        extensions=response.extensions,
                    )
                if result.status_code not in {301, 302, 303, 307, 308}:
                    return result
                if not follow_redirects:
                    return result
                if redirect_number == self.max_redirects:
                    raise ScopeViolation("redirect limit exceeded")
                location = result.headers.get("location")
                if not location:
                    return result
                current = urljoin(validated.url, location)
        raise ScopeViolation("redirect validation failed")


def safe_evidence_response(response: httpx.Response, max_chars: int = 4096) -> dict:
    return {
        "status_code": response.status_code,
        "headers": redact(dict(response.headers)),
        "body": redact(response.text[:max_chars]),
    }
