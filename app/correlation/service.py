from collections import defaultdict
from dataclasses import dataclass

from app.domain import FindingDraft

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CONFIDENCE_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


@dataclass
class CorrelatedFinding:
    finding: FindingDraft
    sources: list[str]


def correlate_findings(findings: list[FindingDraft]) -> list[CorrelatedFinding]:
    groups: dict[str, list[FindingDraft]] = defaultdict(list)
    for finding in findings:
        groups[finding.fingerprint()].append(finding)
    output: list[CorrelatedFinding] = []
    for group in groups.values():
        representative = max(
            group,
            key=lambda value: (SEVERITY_RANK[value.severity], CONFIDENCE_RANK[value.confidence]),
        ).model_copy(deep=True)
        sources = sorted({item.source_engine for item in group})
        representative.evidence = [evidence for item in group for evidence in item.evidence]
        representative.references = sorted({ref for item in group for ref in item.references})
        if len(sources) >= 2 and representative.confidence != "HIGH":
            representative.confidence = "HIGH"
        output.append(CorrelatedFinding(representative, sources))
    return sorted(output, key=lambda item: SEVERITY_RANK[item.finding.severity], reverse=True)
