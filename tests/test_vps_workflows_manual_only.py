"""R-032 / D-055: keep VPS operations and historical qualifications manual."""

import re
import unittest
from pathlib import Path

import yaml


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
INVENTORY = WORKFLOWS.parents[1] / "docs" / "OUF_HISTORICAL_WORKFLOWS_MANUAL_ONLY.md"
HISTORICAL_HEADER = re.compile(r"# Qualificazione storica \(\d{4}-\d{2}-\d{2}\): solo manuale, D-055")
# These four jobs receive the preceding job's artifact ID and digest via inputs.
COHORT_LABS = {
    f"storage-452-generation{generation}-runtime-labs.yml" for generation in (29, 31, 32, 33)
}
# Literal GitHub-hosted labels reviewed for this repository. An expression,
# private label or runner group must be treated as potentially self-hosted.
HOSTED_LABELS = {"ubuntu-latest", "ubuntu-24.04", "windows-2022"}


def needs_manual_dispatch(job, local_workflows):
    if "runs-on" not in job:
        # Local callees are scanned independently: workflow_call itself is
        # forbidden on a VPS workflow. A remote callee has unknown runners.
        return job.get("uses") not in local_workflows
    selector = job["runs-on"]
    if isinstance(selector, dict) and set(selector) == {"labels"}:
        selector = selector["labels"]
    labels = selector if isinstance(selector, list) else [selector]
    return not labels or any(
        not isinstance(label, str) or label not in HOSTED_LABELS for label in labels
    )


def event_names(workflow):
    # SafeLoader (YAML 1.1) decodes an unquoted 'on' key as True.
    events = workflow.get("on", workflow.get(True))
    if isinstance(events, str):
        return [events]
    if isinstance(events, (dict, list)):
        return list(events)
    return []


def calls_cohort_lab(job):
    target = job.get("uses", "").split("@", 1)[0].lower()
    directory, _, name = target.rpartition("/")
    return directory in {"./.github/workflows", "gionob/ouf-deploy/.github/workflows"} and name in COHORT_LABS


class ManualVpsWorkflows(unittest.TestCase):
    def test_repository_workflows(self):
        files = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
        self.assertTrue(files, f"No workflows under {WORKFLOWS}")
        local_workflows = {f"./.github/workflows/{path.name}" for path in files}
        # Cross-check the inventory so deleting only a header cannot unprotect a workflow.
        historical = set(re.findall(r"^\| \[([^\]]+)\]\([^)]+\) \| QUALIFICAZIONE STORICA \|",
                                    INVENTORY.read_text(encoding="utf-8"), re.MULTILINE))
        self.assertTrue(historical, "Missing historical workflow inventory")
        self.assertFalse(historical.difference(path.name for path in files), "Obsolete historical inventory entry")
        for path in files:
            with self.subTest(workflow=path.name):
                source = path.read_text(encoding="utf-8-sig")
                workflow = yaml.safe_load(source)
                marked = HISTORICAL_HEADER.fullmatch(source.splitlines()[0]) is not None
                self.assertEqual(marked, path.name in historical, f"{path.name}: check historical header and inventory")
                events = event_names(workflow)
                if marked:
                    expected = "workflow_call" if path.name in COHORT_LABS else "workflow_dispatch"
                    self.assertEqual(events, [expected], f"{path.name}: expected only {expected}")
                guarded = [
                    name for name, job in workflow["jobs"].items()
                    if needs_manual_dispatch(job, local_workflows) or calls_cohort_lab(job)
                ]
                if guarded:
                    self.assertEqual(events, ["workflow_dispatch"],
                                     f"{path.name}: jobs {guarded} require workflow_dispatch only")

    def test_cohort_lab_callers(self):
        lab = "storage-452-generation33-runtime-labs.yml"
        self.assertTrue(calls_cohort_lab({"uses": f"./.github/workflows/{lab}"}))
        self.assertTrue(calls_cohort_lab({"uses": f"GioNob/ouf-deploy/.github/workflows/{lab}@main"}))
        self.assertFalse(calls_cohort_lab({"uses": "./.github/workflows/other.yml"}))
        self.assertFalse(calls_cohort_lab({"runs-on": "ubuntu-latest"}))

    def test_event_syntax(self):
        for key in ["on", '"on"']:
            for value, expected in [
                ("workflow_dispatch", ["workflow_dispatch"]),
                ("[workflow_dispatch]", ["workflow_dispatch"]),
                ("{workflow_dispatch: {inputs: {ticket: {type: string}}}}", ["workflow_dispatch"]),
                ("push", ["push"]),
                ("[workflow_dispatch, pull_request]", ["workflow_dispatch", "pull_request"]),
                ("{workflow_dispatch: {}, schedule: []}", ["workflow_dispatch", "schedule"]),
            ]:
                with self.subTest(key=key, value=value):
                    self.assertEqual(event_names(yaml.safe_load(f"{key}: {value}")), expected)

    def test_runner_selectors(self):
        for selector in [
            "self-hosted", "ouf-vps-test", ["linux", "SELF-HOSTED"],
            "${{ matrix.runner }}", {"group": "private"}, {"labels": ["ouf-vps-test"]},
            ["ubuntu-24.04", "self-hosted"],
        ]:
            with self.subTest(selector=selector):
                self.assertTrue(needs_manual_dispatch({"runs-on": selector}, set()))
        for selector in ["ubuntu-24.04", ["ubuntu-latest"], {"labels": "windows-2022"}]:
            self.assertFalse(needs_manual_dispatch({"runs-on": selector}, set()))


if __name__ == "__main__":
    unittest.main()
