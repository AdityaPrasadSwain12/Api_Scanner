SEVERITY_BASE = {"INFO": 0.0, "LOW": 3.0, "MEDIUM": 5.5, "HIGH": 8.0, "CRITICAL": 10.0}
CONFIDENCE_MULTIPLIER = {"LOW": 0.55, "MEDIUM": 0.8, "HIGH": 1.0}


def calculate_risk(severity: str, confidence: str) -> float:
    """Transparent 0..10 risk: qualitative severity base × evidence confidence."""
    return round(SEVERITY_BASE[severity] * CONFIDENCE_MULTIPLIER[confidence], 1)
