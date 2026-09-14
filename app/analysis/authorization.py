import json
from difflib import SequenceMatcher
from typing import Any


def response_similarity(left: Any, right: Any) -> float:
    """Compare normalized JSON shape and content; returns a transparent 0..1 similarity."""
    try:
        left_obj = json.loads(left) if isinstance(left, str) else left
        right_obj = json.loads(right) if isinstance(right, str) else right
        left_text = json.dumps(left_obj, sort_keys=True, separators=(",", ":"))
        right_text = json.dumps(right_obj, sort_keys=True, separators=(",", ":"))
    except (json.JSONDecodeError, TypeError):
        left_text, right_text = str(left), str(right)
    return SequenceMatcher(None, left_text[:20_000], right_text[:20_000]).ratio()


def contains_identifier(body: str, identifier: str) -> bool:
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        return identifier in body

    def walk(item: Any) -> bool:
        if isinstance(item, dict):
            return any(walk(v) for v in item.values())
        if isinstance(item, list):
            return any(walk(v) for v in item)
        return str(item) == identifier

    return walk(value)


def authorization_confidence(
    *,
    owner_status: int,
    cross_status: int,
    owner_body: str,
    cross_body: str,
    foreign_identifier: str,
) -> tuple[bool, str, float]:
    """Require success, foreign-object evidence, and response similarity before BOLA."""
    similarity = response_similarity(owner_body, cross_body)
    exposed_identifier = contains_identifier(cross_body, foreign_identifier)
    vulnerable = (
        owner_status < 300 and cross_status < 300 and exposed_identifier and similarity >= 0.55
    )
    confidence = "HIGH" if vulnerable and similarity >= 0.85 else "MEDIUM"
    return vulnerable, confidence, similarity
