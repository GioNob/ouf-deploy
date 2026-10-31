from pathlib import Path
import yaml, json, re
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[1]
CAT=yaml.safe_load((ROOT/"spec/e2e-scenario-catalog.yaml").read_text())
OWN=yaml.safe_load((ROOT/"spec/scenario-ownership.yaml").read_text())
LEG=yaml.safe_load((ROOT/"spec/legacy-id-mapping.yaml").read_text())
TRACE=yaml.safe_load((ROOT/"spec/frozen-acceptance-traceability.yaml").read_text())

GENERIC=[
"Prepare versioned fixture and correlation identity.",
"Invoke through the governed path.",
"Inject the scenario-specific positive/negative condition.",
"Capture module decisions, immutable references and result."
]

def test_namespace_and_count():
    ids=[s["id"] for s in CAT["scenarios"]]
    assert ids==[f"OUF-E2E-{i:03d}" for i in range(1,26)]
    assert CAT["scenarioCount"]==25

def test_every_scenario_is_specific_and_executable_shape():
    for s in CAT["scenarios"]:
        assert len(s.get("actors",[]))>=1
        assert len(s.get("modules",[]))>=1
        assert len(s.get("preconditions",[]))>=1
        assert len(s.get("steps",[]))>=3
        assert len(s.get("assertions",[]))>=3
        assert len(s.get("evidence",[]))>=3
        assert s.get("sourceTrace")
        assert s["steps"] != GENERIC
        assert s["preconditions"] != ["Required module contracts are deployed or stubbed only at external platform boundaries."]
        assert s["evidence"] != ["correlation trace","decision/result record","contract/version/hash references"]

def test_xma_and_previous_mappings_complete():
    assert set(LEG["xmaMap"])=={f"E2E-X{i:02d}" for i in range(1,17)}
    assert set(LEG["xmaMap"].values())=={f"OUF-E2E-{i:03d}" for i in range(1,17)}
    assert len(LEG["previousV01Map"])==16

def test_ownership_complete_and_unique():
    rows=OWN["scenarios"]
    assert {r["id"] for r in rows}=={f"OUF-E2E-{i:03d}" for i in range(1,26)}
    assert all(r["leadTeam"] and r["evidenceOwner"] for r in rows)

def test_frozen_suites_remain_mandatory():
    suites={(x["source"],x["suite"]) for x in TRACE["mandatorySuites"]}
    assert any("MCP-A" in s for _,s in suites)
    assert any("THS-A" in s for _,s in suites)

def test_evidence_schema():
    schema=json.loads((ROOT/"evidence/e2e-evidence-record-v1.json").read_text())
    Draft202012Validator.check_schema(schema)
    assert schema["properties"]["contractFreezeVersion"]["const"]=="1.0.0-rc3-coherence"

def test_scope_control():
    text=" ".join(CAT["scopeControl"])
    assert "A/B/C remains unresolved" in text
    assert "not modified" in text
    assert "Supplier vertical API guidelines remain out of scope" in text
