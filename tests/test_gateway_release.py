"""Offline publisher, journal and mandate fixtures for the Gateway workflow."""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools/privileged_executor"), str(ROOT / "tools")]
import gateway_bundle as bundle
from gateway_admin import Admin
import gateway_operation as operation
import mandate
import store


CI = dict(repository="fixture/ouf-api-gateway", workflow="publisher.yml", pullRequest=7,
          sourceCommit="a" * 40, runId=11, runAttempt=1, artifactId=12)
REQ = dict(operation="gateway-release", run="70", attempt="1", commit="b" * 40, phase="plan",
           sourcePr="7", sourceRun="11", artifact="12", sourceCommit=CI["sourceCommit"])
REQ["digest"] = mandate.intent(REQ)
SECRET = "private-synthetic-fixture-value"
MARKER = {"$installation": "binding"}
DECL = [{"name": "binding", "type": "secret"}]


def encoded(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def artifact(resources, *, declarations=None, change_bundle=None, change_manifest=None, change_files=None):
    declarations = DECL if declarations is None else declarations
    resources_sha = sha(encoded(resources))
    doc = dict(schema="ouf.gateway-release-bundle.v1", sourceRepository=CI["repository"],
               sourceCommit=CI["sourceCommit"], resources=resources, placeholders=declarations,
               resourcesSha256=resources_sha)
    doc.update(change_bundle or {})
    body = encoded(doc)
    manifest = dict(schema="ouf.gateway-release-manifest.v1", sourceRepository=CI["repository"],
                    sourceCommit=CI["sourceCommit"], workflowPath=".github/workflows/" + CI["workflow"],
                    runId="11", bundleSha256=sha(body), resourcesSha256=resources_sha,
                    placeholders=[item["name"] for item in declarations])
    manifest.update(change_manifest or {})
    files = {"bundle.json": body, "manifest.json": encoded(manifest)}
    files["SHA256SUMS"] = "".join(f"{sha(v)}  {k}\n" for k, v in files.items()).encode()
    files.update(change_files or {})
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for key, val in files.items():
            archive.writestr(key, val)
    raw = out.getvalue()
    return dict(CI, zipSha256=sha(raw)), raw


def row(kind, ident, body):
    return {"kind": kind, "id": ident, "body": body}


ROWS = [row("upstreams", "one", {"desc": MARKER}), row("plugin_configs", "cfg", {"plugins": {}}),
        row("routes", "one", {"uri": "/new", "upstream_id": "one", "plugin_config_id": "cfg"})]


def verify(pair):
    ci, raw = pair
    return bundle.verify(raw, ci, {"binding": SECRET})


class Contract(unittest.TestCase):
    def test_admin_uses_only_scoped_paths_and_errors_are_public_codes(self):
        admin = Admin("127.0.0.1", 9180, "/fixture", SECRET, Mock())
        with patch("gateway_admin.http.client.HTTPConnection") as factory:
            conn = factory.return_value
            response = conn.getresponse.return_value
            for kind in bundle.KINDS:
                target = row(kind, "item", {"desc": SECRET})
                response.status = 200
                response.read.return_value = encoded({"key": "/apisix/" + kind + "/item", "value":
                    {"id": "item", "create_time": 1, "update_time": 2, **target["body"]}})
                self.assertEqual(admin.get(target), target["body"])
                args = conn.request.call_args.args
                self.assertEqual(args[:3], ("GET", "/fixture/" + kind + "/item", None))
                self.assertEqual(args[3]["X-API-KEY"], SECRET)
            response.status = 404
            response.read.return_value = b'{"message":"Key not found"}'
            self.assertIsNone(admin.get(target))
            response.status = 400
            response.read.return_value = encoded({"error_msg": SECRET})
            with self.assertRaisesRegex(mandate.Held, "^GATEWAY_ADMIN_REQUEST$"):
                admin.write(target, target["body"])
            for ident in (".", "..", "x/y"):
                with self.assertRaisesRegex(mandate.Held, "^GATEWAY_RESOURCE_PATH$"):
                    admin.get(dict(target, id=ident))

    def test_workflow_challenge_and_deploy_mandate_agree(self):
        cfg = dict(repositoryId=5, branch="main", commit=REQ["commit"], environmentId=6,
                   environment="ouf-vps-privileged", reviewerIds=[7], gateway={})
        inputs = {k: REQ[k] for k in ("sourceRun", "sourcePr", "sourceCommit", "artifact")}
        with tempfile.TemporaryDirectory() as tmp:
            summary, output = Path(tmp)/"summary", Path(tmp)/"output"
            env = dict(GITHUB_RUN_ID=REQ["run"], GITHUB_RUN_ATTEMPT="1", GITHUB_SHA=REQ["commit"],
                       DISPATCH_INPUTS=json.dumps(dict(inputs, action="release")),
                       GITHUB_STEP_SUMMARY=str(summary), GITHUB_OUTPUT=str(output))
            with patch.dict(os.environ, env, clear=True), patch.object(sys, "argv", ["client", "intent"]):
                runpy.run_path(str(ROOT/".github/scripts/gateway-release.py"), run_name="__main__")
            self.assertIn(mandate.challenge(REQ), summary.read_text())
            self.assertIn("digest=" + REQ["digest"], output.read_text())
        workflow = ".github/workflows/gateway-release.yml"
        run = dict(id=70, run_attempt=1, status="in_progress", event="workflow_dispatch", path=workflow,
                   head_sha=REQ["commit"], head_branch="main", repository={"id":5}, head_repository={"id":5})
        branch = {"protected": True, "commit": {"sha": REQ["commit"]}}
        environment = dict(id=6, name=cfg["environment"], protection_rules=[dict(type="required_reviewers",
                           reviewers=[{"type": "User", "reviewer": {"id": 7}}])])
        review = dict(state="approved", comment=mandate.challenge(REQ), user={"id":7,"type":"User"},
                      environments=[{"id":6,"name":cfg["environment"]}])
        def authorize(request, source=run):
            return mandate.authorize(request, cfg, Mock(side_effect=[source, branch, environment, [review]]))
        self.assertTrue(mandate.hex64(authorize(REQ)))
        with self.assertRaisesRegex(mandate.Held, "RUN_NOT_AUTHORIZED"):
            authorize(REQ, dict(run, path=mandate.WORKFLOW))
        with self.assertRaisesRegex(mandate.Held, "EXACT_HUMAN_REVIEW_REQUIRED"):
            authorize(dict(REQ, phase="apply"))
        with self.assertRaisesRegex(mandate.Held, "PLAN_INTENT_DRIFT"):
            authorize(dict(REQ, sourcePr="8"))

    def test_contract_and_recursive_substitution(self):
        rows = deepcopy(ROWS)
        rows[0]["body"] = {"nested": [MARKER, {"unchanged": "$installation"}]}
        self.assertEqual(verify(artifact(rows))[0]["body"], {"nested": [SECRET, {"unchanged": "$installation"}]})
        ci, raw = artifact(ROWS)
        with self.assertRaisesRegex(mandate.Held, "ZIP_DIGEST"):
            verify((dict(ci, zipSha256="0" * 64), raw))

    def test_rejects_malformed_or_unbound_package(self):
        cases = [
            artifact(ROWS, change_manifest={"runId": 11}), artifact(ROWS, change_manifest={"extra": ""}),
            artifact(ROWS, change_manifest={"placeholders": []}), artifact(ROWS, change_manifest={"sourceCommit": "b"*40}),
            artifact(ROWS, change_bundle={"resourcesSha256": "0"*64}), artifact(ROWS, change_bundle={"extra": True}),
            artifact(ROWS, change_files={"subdir/other": ""}), artifact(ROWS, change_files={"SHA256SUMS": "invalid"}),
            artifact(ROWS[::-1]), artifact(ROWS + [ROWS[-1]]), artifact(ROWS, declarations=[]),
            artifact(ROWS, declarations=DECL + [{"name": "unused", "type": "string"}]),
            artifact([row("routes", "..", {})]), artifact([row("consumers", "a", {})]),
            artifact([row("routes", "a", {"id": "b"})]), artifact([row("routes", "a", {"desc": {**MARKER, "x": 1}})]),
        ]
        for index, pair in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(mandate.Held):
                verify(pair)

    def test_real_selector_runs_before_zip_download(self):
        ci, raw = artifact(ROWS)
        repo = {"full_name": CI["repository"]}
        run = dict(id=11, status="completed", conclusion="success", event="pull_request",
                   path=".github/workflows/publisher.yml", head_sha=CI["sourceCommit"], repository=repo,
                   head_repository=repo, pull_requests=[{"number": 7, "head": {"sha": CI["sourceCommit"]}}], run_attempt=1)
        item = dict(id=12, expired=False, workflow_run={"id": 11, "head_sha": CI["sourceCommit"]},
                    name="gateway-release-bundle-11", digest="sha256:" + ci["zipSha256"])
        source = dict(repository=CI["repository"], workflow=CI["workflow"])
        profile = dict(source=source, values={"binding": SECRET})
        for update, change in (({}, {}), ({"event": "push"}, {}), ({"pull_requests": []}, {}),
                               ({"head_sha": "f"*40}, {}), ({}, {"expired": True}), ({}, {"id": 99}),
                               ({}, {"name": "source-onboarding-governed-image-11"})):
            api = Mock(side_effect=[dict(run, **update), dict(item, **change)])
            with patch.object(bundle, "github_reader", return_value=api) as reader, \
                    patch.object(bundle, "download", return_value=raw) as download:
                if update or change:
                    with self.assertRaisesRegex(mandate.Held, "CI_PROVENANCE"):
                        bundle.package(profile, REQ, SECRET)
                    download.assert_not_called()
                else:
                    self.assertEqual(bundle.package(profile, REQ, SECRET), (ci, verify((ci, raw))))
                    download.assert_called_once_with(ci, SECRET)
                reader.assert_called_once_with(CI["repository"], SECRET)


class MemoryAdmin:
    def __init__(self):
        self.data = {("routes", "one"): {"uri": "/old"}, ("plugin_configs", "cfg"): {"plugins": {}},
                     ("services", "outside"): {"sensitive": SECRET}}
        self.reads, self.writes = [], []
        self.on_write = lambda *_: None

    def get(self, resource):
        key = resource["kind"], resource["id"]
        self.reads.append(key)
        return deepcopy(self.data.get(key))

    def write(self, resource, value):
        key = resource["kind"], resource["id"]
        self.writes.append(key)
        if value is None:
            del self.data[key]
        else:
            self.data[key] = deepcopy(value)
        self.on_write(key, value)
        return deepcopy(value)


class Phases(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.cfg = {"gateway": {"values": {"binding": SECRET}}, "commit": REQ["commit"]}
        self.admin = MemoryAdmin()
        self.before = deepcopy(self.admin.data)
        ci, raw = artifact(ROWS)
        self.package = self.enterContext(patch.object(operation, "package", return_value=(ci, verify((ci, raw)))))
        self.enterContext(patch.object(operation, "connect", side_effect=lambda _: nullcontext((self.admin, "generation"))))
        self.enterContext(patch.object(store, "trusted", side_effect=lambda path, **_: path))
        self.enterContext(patch.object(store, "sync_dir"))  # non-POSIX temporary directory

    def phase(self, req):
        mandate.validate(req, self.cfg)
        result = operation.GatewayRelease(self.cfg, self.root, req).execute("fixture-review", SECRET)
        self.assertNotIn(SECRET, json.dumps(result))
        return result

    def plan(self):
        result = self.phase(REQ)
        self.assertEqual(result["counts"], {"create": 1, "update": 1, "unchanged": 1})
        self.assertEqual(self.admin.writes, [])
        return dict(REQ, phase="apply", digest=result["digest"])

    def return_req(self, receipt):
        return dict(operation="gateway-release", phase="return", commit=REQ["commit"], run="71",
                    attempt="1", releaseRun=REQ["run"], digest=receipt["digest"])

    def test_dispatch_uses_ephemeral_token_for_plan_and_apply(self):
        models = [str(ROOT / "tools" / name) for name in ("semantic_provider_r3", "semantic_application_cutover")]
        with patch.object(sys, "path", models + sys.path):
            dispatch = runpy.run_path(str(ROOT / "scripts/ouf-a2-executor"))["dispatch"]
        token = "synthetic-workflow-token"
        with patch.dict(dispatch.__globals__, authorize=Mock(return_value="fixture-review")):
            plan = dispatch(REQ, self.cfg, self.root, Mock(), token=token)
            self.package.assert_called_once_with(self.cfg["gateway"], REQ, token)
            req = dict(REQ, phase="apply", digest=plan["digest"])
            receipt = dispatch(req, self.cfg, self.root, Mock(), token=token)
            self.package.assert_called_with(self.cfg["gateway"], req, token)
            result = dispatch(self.return_req(receipt), self.cfg, self.root, Mock(), token=token)
        self.assertEqual(result["status"], "RETURNED")
        self.assertEqual(self.package.call_count, 2)
        self.assertNotIn(token, json.dumps([plan, receipt, result]))
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(token.encode(), path.read_bytes())

    def test_apply_then_separately_reviewed_return(self):
        req = self.plan()
        def check_snapshot(*_):
            snap = store.read(self.root / "70/gateway.snapshot")
            self.assertEqual(snap["rows"][2]["before"], {"uri": "/old"})
        self.admin.on_write = check_snapshot
        receipt = self.phase(req)
        self.assertEqual(self.admin.writes, [("upstreams", "one"), ("routes", "one")])
        back = self.return_req(receipt)
        for bad in (dict(back, digest="c"*64), dict(back, releaseRun="99")):
            with self.assertRaisesRegex(mandate.Held, "RETURN_RECEIPT"):
                self.phase(bad)
        self.assertEqual(self.phase(back)["status"], "RETURNED")
        self.assertEqual(self.admin.data, self.before)
        self.assertNotIn(("services", "outside"), self.admin.reads + self.admin.writes)
        with self.assertRaisesRegex(mandate.Held, "RETURN_RECEIPT"):
            self.phase(back)

    def test_wrong_approval_or_drift_causes_zero_writes(self):
        req = self.plan()
        with patch.object(operation, "package") as fetch, self.assertRaisesRegex(mandate.Held, "PLAN_DRIFT"):
            self.phase(dict(req, digest="0"*64))
        fetch.assert_not_called()
        self.admin.data[("routes", "one")]["uri"] = "/foreign"
        with self.assertRaisesRegex(mandate.Held, "PLAN_DRIFT"):
            self.phase(req)
        self.assertFalse(self.admin.writes)
        self.assertFalse((self.root / "70/gateway.snapshot").exists())

    def test_failed_write_after_commit_restores_every_attempt_in_reverse(self):
        req = self.plan()
        def lose_ack(*_):
            if len(self.admin.writes) == 2:
                raise RuntimeError(SECRET)
        self.admin.on_write = lose_ack
        with self.assertRaisesRegex(mandate.Held, "^GATEWAY_WRITE_FAILED_RESTORED$"):
            self.phase(req)
        self.assertEqual(self.admin.data, self.before)
        self.assertEqual(self.admin.writes, [("upstreams", "one"), ("routes", "one"),
                                            ("routes", "one"), ("upstreams", "one")])
        self.assertEqual(store.read(self.root / "70/gateway.apply.failure"), {"status": "RESTORED"})

    def test_foreign_state_is_preserved_and_unresolved_write_blocks_new_run(self):
        req = self.plan()
        def foreign(key, value):
            self.admin.data[key] = {"desc": "foreign"}
            raise RuntimeError(SECRET)
        self.admin.on_write = foreign
        with self.assertRaisesRegex(mandate.Held, "^GATEWAY_RECONCILIATION_REQUIRED$"):
            self.phase(req)
        req = dict(REQ, run="78")
        req["digest"] = mandate.intent(req)
        with self.assertRaisesRegex(mandate.Held, "RECONCILIATION_REQUIRED"):
            self.phase(req)
        self.assertEqual(self.admin.data[("upstreams", "one")], {"desc": "foreign"})

    def test_return_rejects_changed_state_and_compensates_a_partial_return(self):
        req = self.plan()
        receipt = self.phase(req)
        back = self.return_req(receipt)
        applied = deepcopy(self.admin.data)
        self.admin.data[("routes", "one")]["status"] = 0
        with self.assertRaisesRegex(mandate.Held, "LIVE_DRIFT"):
            self.phase(back)
        self.admin.data = deepcopy(applied)
        def lose_delete_ack(key, value):
            if value is None:
                raise RuntimeError(SECRET)
        self.admin.on_write = lose_delete_ack
        with self.assertRaisesRegex(mandate.Held, "^GATEWAY_WRITE_FAILED_RESTORED$"):
            self.phase(back)
        self.assertEqual(self.admin.data, applied)
        self.assertEqual(store.read(self.root / "gateway-head")["digest"], receipt["digest"])


if __name__ == "__main__":
    unittest.main()
