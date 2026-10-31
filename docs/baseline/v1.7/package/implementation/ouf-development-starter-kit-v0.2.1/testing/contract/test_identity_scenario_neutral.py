from pathlib import Path
import json
from jsonschema import Draft202012Validator

ROOT=Path(__file__).resolve().parents[2]
C=ROOT/"contracts"/"ouf-contracts-v1.0.0-rc3-coherence"

def test_two_provider_profiles_validate_without_scenario_selection():
    schema=json.loads((C/"identity/m2m-identity-integration-profile-v1.json").read_text())
    validator=Draft202012Validator(schema)
    for name in ["alpha","beta"]:
        obj=json.loads((C/f"examples/identity/m2m-identity-profile.{name}.valid.json").read_text())
        assert list(validator.iter_errors(obj)) == []
        assert obj["scenarioDecision"]["selectedScenario"] is None
