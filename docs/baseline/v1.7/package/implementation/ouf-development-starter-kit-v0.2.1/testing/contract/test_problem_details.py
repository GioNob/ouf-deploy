from pathlib import Path
import json

ROOT=Path(__file__).resolve().parents[2]
C=ROOT/"contracts"/"ouf-contracts-v1.0.0-rc3-coherence"

def test_problem_details_canonical_fields():
    schema=json.loads((C/"common/problem-details-v1.json").read_text())
    assert "code" in schema["required"]
    assert "correlationId" in schema["required"]
