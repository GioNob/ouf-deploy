"""R-032: only a manual dispatch may assign work to the VPS runner."""

import unittest
from pathlib import Path

import yaml


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
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


class ManualVpsWorkflows(unittest.TestCase):
    def test_repository_workflows(self):
        files = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
        self.assertTrue(files, f"No workflows under {WORKFLOWS}")
        local_workflows = {f"./.github/workflows/{path.name}" for path in files}
        for path in files:
            with self.subTest(workflow=path.name):
                workflow = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
                guarded = [
                    name for name, job in workflow["jobs"].items()
                    if needs_manual_dispatch(job, local_workflows)
                ]
                if guarded:
                    self.assertEqual(event_names(workflow), ["workflow_dispatch"],
                                     f"{path.name}: jobs {guarded} require workflow_dispatch only")

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
