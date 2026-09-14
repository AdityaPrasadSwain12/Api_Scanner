import base64
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


@dataclass
class AppliedAuthentication:
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ""


def apply_auth(url: str, auth: dict | None) -> AppliedAuthentication:
    if not auth or auth.get("type") in {None, "NONE"}:
        return AppliedAuthentication(url=url)
    auth_type = auth.get("type")
    if auth_type == "BEARER":
        return AppliedAuthentication(headers={"Authorization": f"Bearer {auth['token']}"}, url=url)
    if auth_type == "BASIC":
        value = base64.b64encode(f"{auth['username']}:{auth['password']}".encode()).decode()
        return AppliedAuthentication(headers={"Authorization": f"Basic {value}"}, url=url)
    if auth_type == "API_KEY":
        if auth.get("location", "header") == "query":
            parsed = urlsplit(url)
            query = [*parse_qsl(parsed.query, keep_blank_values=True), (auth["name"], auth["key"])]
            return AppliedAuthentication(
                url=urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))
            )
        return AppliedAuthentication(headers={str(auth["name"]): str(auth["key"])}, url=url)
    raise ValueError(f"unsupported authentication type: {auth_type}")
