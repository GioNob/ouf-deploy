"""Package only the pinned conditional-installation Onboarding owner; no target authority."""
import importlib.util,json
from pathlib import Path

def main():
    here=Path(__file__).resolve().parent
    spec=importlib.util.spec_from_file_location("qualified_candidate",here/"package-resolution-comparison-candidate.py")
    candidate=importlib.util.module_from_spec(spec);spec.loader.exec_module(candidate)
    candidate.LOCK_PATH=here.parent/"releases/installation-owner-candidate-20261019.json"
    candidate.LOCK=json.loads(candidate.LOCK_PATH.read_text())
    candidate.SOURCES={row["module"]:(row["repository"],row["commit"])for row in candidate.LOCK["modules"]}
    candidate.KINDS={row["module"]:row["kind"]for row in candidate.LOCK["modules"]}
    candidate.main()

if __name__=="__main__":main()
