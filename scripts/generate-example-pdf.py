"""Generate the checked-in example reports from the technical example payload."""

import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))

from app.reporting.generator import ReportGenerator  # noqa: E402

payload = json.loads(
    (root / "examples" / "report.technical.example.json").read_text(encoding="utf-8")
)
generator = ReportGenerator(root / "examples")
(root / "examples" / "report.example.json").write_text(
    json.dumps(generator.pentest_payload(payload), indent=2), encoding="utf-8"
)
(root / "examples" / "report.example.html").write_text(
    generator._html(payload), encoding="utf-8"
)
(root / "examples" / "report.example.pdf").write_bytes(generator._pdf(payload))
print(root / "examples" / "report.example.json")
print(root / "examples" / "report.technical.example.json")
print(root / "examples" / "report.example.html")
print(root / "examples" / "report.example.pdf")
