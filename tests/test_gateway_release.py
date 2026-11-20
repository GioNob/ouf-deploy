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
    def test_only_declared_encrypted_path_accepts_opaque_readback(self):
        desired = {"plugins": {"openid-connect": {"client_secret": SECRET, "client_id": "id"},
                               "other": {"client_secret": SECRET}}}
        live = deepcopy(desired)
        oidc = live["plugins"]["openid-connect"]
        oidc["client_secret"] = "opaque-fixture"
        self.assertEqual(operation.field_differences(live, desired), [])
        self.assertEqual(operation.field_differences(live, desired, exact=True),
                         ["plugins.openid-connect.client_secret: changed"])
        for invalid in ("", None, False, [], {}):
            oidc["client_secret"] = invalid
            self.assertEqual(operation.field_differences(live, desired), ["plugins.openid-connect.client_secret: changed"])
        del oidc["client_secret"]
        oidc["client_id"] = SECRET
        live["plugins"]["other"]["client_secret"] = "different"
        self.assertEqual(operation.field_differences(live, desired), [
            "plugins.openid-connect.client_id: changed", "plugins.openid-connect.client_secret: missing",
            "plugins.other.client_secret: changed"])

    def test_differences_identify_array_indices_and_preserve_exact_limits(self):
        expected = {"items": [{"maximum": 2**53 - 1}, "sensitive"], "methods": ["GET"]}
        actual = {"items": [{"maximum": float(format(2**53 - 1, ".14g")), SECRET: True}],
                  "methods": ["GET", SECRET]}
        self.assertEqual(operation.field_differences(actual, expected), [
            "items[0].maximum: changed", "items[0]: unexpected field", "items[1]: missing", "methods[1]: unexpected"])

    def test_declared_fields_are_required_and_arrays_are_exact(self):
        conforms = operation.conforms
        self.assertTrue(conforms({"plugin": {"enabled": True, "extra": 1}}, {"plugin": {"enabled": True}}))
        for live, wanted in (({}, {"field": None}), ({"field": False}, {"field": 0}),
                             ([1, 2], [2, 1]), ([1, 2], [1]), ([True], [1]),
                             ([{"k": 0, "extra": 1}], [{"k": 0}]), ({}, None), (None, {})):
            with self.subTest(live=live, wanted=wanted):
                self.assertFalse(conforms(live, wanted))

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
            self.assertIsNone(admin.write(target, None))
            self.assertEqual(conn.request.call_args.args[:3], ("DELETE", "/fixture/" + kind + "/item", None))
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

    def test_workflow_summary_and_deploy_mandate_agree(self):
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
            self.assertNotIn("Approvare", summary.read_text())
            self.assertIn(REQ["digest"], summary.read_text())
            self.assertIn("digest=" + REQ["digest"], output.read_text())
            planned = {"status": "PLANNED", "digest": "c"*64, "recoveringRun": "69",
                       "counts": {"create": 0, "update": 6, "unchanged": 1}}
            with patch.dict(os.environ, dict(env, REVIEW_TOKEN=SECRET), clear=True), \
                    patch.object(sys, "argv", ["client", "invoke"]), \
                    patch("subprocess.run", return_value=Mock(stdout=encoded(planned))):
                runpy.run_path(str(ROOT/".github/scripts/gateway-release.py"), run_name="__main__")
            self.assertIn("pending run 69", summary.read_text())
            self.assertNotIn(SECRET, summary.read_text())
        workflow = ".github/workflows/gateway-release.yml"
        run = dict(id=70, run_attempt=1, status="in_progress", event="workflow_dispatch", path=workflow,
                   head_sha=REQ["commit"], head_branch="main", repository={"id":5}, head_repository={"id":5})
        branch = {"protected": True, "commit": {"sha": REQ["commit"]}}
        environment = dict(id=6, name=cfg["environment"], protection_rules=[dict(type="required_reviewers",
                           reviewers=[{"type": "User", "reviewer": {"id": 7}}])])
        review = dict(state="approved", user={"id":7,"type":"User"},
                      environments=[{"id":6,"name":cfg["environment"]}])
        state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(store, "trusted", side_effect=lambda path, **_: path))
        self.enterContext(patch.object(store, "sync_dir"))
        def authorize(request, source=run, reviews=()):
            return mandate.authorize(request, cfg, Mock(side_effect=[source, branch, environment, reviews]), state)
        self.assertTrue(mandate.hex64(authorize(REQ)))
        with self.assertRaisesRegex(mandate.Held, "RUN_NOT_AUTHORIZED"):
            authorize(REQ, dict(run, path=mandate.WORKFLOW))
        with self.assertRaisesRegex(mandate.Held, "EXACT_HUMAN_REVIEW_REQUIRED"):
            authorize(dict(REQ, phase="apply"))
        with self.assertRaisesRegex(mandate.Held, "PLAN_INTENT_DRIFT"):
            authorize(dict(REQ, sourcePr="8"))
        rollback = dict(operation="gateway-release", run="71", attempt="1", commit=REQ["commit"],
                        phase="return", digest="c" * 64, releaseRun=REQ["run"])
        with self.assertRaisesRegex(mandate.Held, "EXACT_HUMAN_REVIEW_REQUIRED"):
            authorize(rollback, dict(run, id=71))
        self.assertTrue(mandate.hex64(authorize(rollback, dict(run, id=71), [review])))

    def test_contract_and_recursive_substitution(self):
        rows = deepcopy(ROWS)
        rows[0]["body"] = {"nested": [MARKER, {"unchanged": "$installation"}]}
        self.assertEqual(verify(artifact(rows))[0]["body"], {"nested": [SECRET, {"unchanged": "$installation"}]})
        ci, raw = artifact(ROWS)
        with self.assertRaisesRegex(mandate.Held, "ZIP_DIGEST"):
            verify((dict(ci, zipSha256="0" * 64), raw))

    def test_integer_placeholders_for_upstream_ports(self):
        # Contract rev. 2: ports are JSON integers, mixed-case registry names are accepted.
        decl = [{"name": "binding", "type": "secret"}, {"name": "services.ports.Owner", "type": "integer"}]
        body = {"upstream": {"nodes": [{"host": MARKER, "port": {"$installation": "services.ports.Owner"}, "weight": 1}]}}
        ci, raw = artifact([row("routes", "r", body)], declarations=decl)
        out = bundle.verify(raw, ci, {"binding": SECRET, "services.ports.Owner": 8080})
        self.assertEqual(out[0]["body"]["upstream"]["nodes"][0]["port"], 8080)
        for wrong in ("8080", True, 8080.0):
            with self.assertRaisesRegex(mandate.Held, "GATEWAY_INSTALLATION_VALUE"):
                bundle.verify(raw, ci, {"binding": SECRET, "services.ports.Owner": wrong})
        with self.assertRaisesRegex(mandate.Held, "GATEWAY_INSTALLATION_VALUE"):
            ci2, raw2 = artifact([row("routes", "r", {"x": MARKER})])
            bundle.verify(raw2, ci2, {"binding": 7})
        import gateway_policy
        good = dict(source={"repository": "o/ouf-api-gateway", "workflow": "ci.yml"}, container="apisix",
                    dockerSocket="/var/run/docker.sock", keyFile="/opt/k", host="127.0.0.1", port=9180,
                    adminPath="/apisix/admin", values={"caddy.oidcDiscoveryUrl": "https://x.invalid/r",
                                                       "services.ports.ouf-onboarding": 8080})
        from pathlib import PurePosixPath
        from unittest.mock import patch as _patch
        with _patch.object(gateway_policy, "Path", PurePosixPath):  # host paths are POSIX on the VPS
            self.assertTrue(gateway_policy.valid_profile(good))
            self.assertFalse(gateway_policy.valid_profile(dict(good, values={"x": True})))

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

    def select(self, resources):
        pair = artifact(resources)
        self.package.return_value = pair[0], verify(pair)

    def new_plan_request(self, run):
        req = dict(REQ, run=run)
        return dict(req, digest=mandate.intent(req))

    def test_plugin_defaults_in_ack_and_get_and_replacement_of_old_fields(self):
        key = ("routes", "one")
        limit = {"count": 5, "time_window": 60}
        self.select([row(*key, {"uri": "/old", "desc": MARKER, "plugins": {"limit-count": limit}})])
        self.admin.data[key]["methods"] = ["GET"]
        def materialize(key, body):
            self.admin.data[key]["status"] = 1
            self.admin.data[key]["plugins"]["limit-count"]["policy"] = "local"
        self.admin.on_write = materialize
        write = self.admin.write
        with patch.object(self.admin, "write", side_effect=lambda r, b: dict(write(r, b), priority=0)):
            plan = self.phase(REQ)
            self.assertEqual(plan["counts"]["update"], 1)
            self.phase(dict(REQ, phase="apply", digest=plan["digest"]))
        self.assertNotIn("methods", self.admin.data[key])
        self.assertEqual(self.phase(self.new_plan_request("72"))["counts"]["unchanged"], 1)
        self.assertEqual(self.admin.writes, [key])

    def test_failed_update_removes_additions_and_deletes_new_route_after_different_ack(self):
        new, existing = ("routes", "created"), ("routes", "one")
        self.select([row(*new, {"uri": "/created", "desc": MARKER}),
                     row(*existing, {"uri": "/old", "methods": ["POST"]})])
        def fail_after_second_put(key, body):
            if key == new and body:
                self.admin.data[key]["status"] = 1
            if key == existing and "methods" in body:
                raise RuntimeError("lost response")
        self.admin.on_write = fail_after_second_put
        write = self.admin.write
        def write_with_ack(r, b):
            ack = write(r, b)
            return dict(ack, priority=0) if ack is not None else None
        with patch.object(self.admin, "write", side_effect=write_with_ack) as calls:
            plan = self.phase(REQ)
            with self.assertRaisesRegex(mandate.Held, "^GATEWAY_WRITE_FAILED_RESTORED$"):
                self.phase(dict(REQ, phase="apply", digest=plan["digest"]))
            self.assertIsNone(calls.call_args.args[1])
        self.assertEqual(self.admin.writes, [new, existing, existing, new])
        self.assertEqual(self.admin.data, self.before)

    def test_pending_legacy_snapshot_resumes_from_mixed_live_state(self):
        desired = [row("routes", str(i), {"uri": f"/new/{i}", "desc": MARKER}) for i in range(7)]
        self.select(desired)
        for i in range(1, 7):
            self.admin.data[("routes", str(i))] = {"uri": f"/old/{i}", "methods": ["GET"]}
        # The old executor added priority/status to the snapshot and PUT body.
        for resource in self.package.return_value[1]:
            resource["body"].update(priority=0, status=1)
        plan = self.phase(REQ)
        def crash(key, body):
            self.admin.data[key]["plugins"] = {}
            raise KeyboardInterrupt()
        self.admin.on_write = crash
        with self.assertRaises(KeyboardInterrupt):
            self.phase(dict(REQ, phase="apply", digest=plan["digest"]))
        mixed = deepcopy(self.admin.data)
        pending = store.read(self.root / "gateway-head")
        self.assertEqual(pending, {"status": "PENDING", "phase": "apply", "run": REQ["run"]})
        for other in (desired[:-1], [*desired[:-1], row("routes", "6", {"uri": "/other"})]):
            self.select(other)
            with self.assertRaisesRegex(mandate.Held, "^GATEWAY_PENDING_PACKAGE_DRIFT$"):
                self.phase(self.new_plan_request("74"))
        self.select(desired)
        self.admin.on_write = lambda *_: None
        new = self.new_plan_request("72")
        recovered = self.phase(new)
        self.assertEqual(recovered["recoveringRun"], REQ["run"])
        self.assertEqual(recovered["counts"], {"unchanged": 1, "update": 6, "create": 0})
        self.assertEqual(self.admin.data, mixed)
        self.assertEqual(store.read(self.root / "gateway-head"), pending)
        apply = dict(new, phase="apply", digest=recovered["digest"])
        key = ("routes", "1")
        self.admin.data[key]["uri"] = "/unrelated"
        with self.assertRaisesRegex(mandate.Held, "^GATEWAY_PENDING_LIVE_DRIFT$"):
            self.phase(apply)
        self.assertEqual(self.admin.writes, [("routes", "0")])
        self.admin.data[key] = mixed[key].copy()
        receipt = self.phase(apply)
        self.assertEqual(self.admin.writes, [("routes", str(i)) for i in range(7)])
        self.assertEqual(store.read(self.root / "gateway-head")["digest"], receipt["digest"])
        for resource in desired:
            self.assertEqual(self.admin.data[("routes", resource["id"])]["uri"], resource["body"]["uri"])
        self.phase(dict(self.return_req(receipt), releaseRun=new["run"]))
        self.assertEqual(self.admin.data, mixed)
        self.assertEqual(store.read(self.root / "gateway-head"), pending)

    def test_delete_ack_does_not_prove_compensation_without_absence(self):
        key = ("routes", "created")
        self.select([row(*key, {"uri": "/created", "desc": MARKER})])
        write = self.admin.write
        def lost_put_ignored_delete(resource, body):
            if body is not None:
                write(resource, body)
                raise OSError("lost response")
            return None
        with patch.object(self.admin, "write", side_effect=lost_put_ignored_delete) as calls:
            plan = self.phase(REQ)
            with self.assertRaisesRegex(mandate.Held, "^GATEWAY_RECONCILIATION_REQUIRED$"):
                self.phase(dict(REQ, phase="apply", digest=plan["digest"]))
            self.assertIsNone(calls.call_args.args[1])
        self.assertIn(key, self.admin.data)
        self.assertEqual(store.read(self.root / "gateway-head")["status"], "PENDING")

    def test_creation_with_nonconforming_put_response(self):
        key = ("routes", "created")
        self.select([row(*key, {"uri": "/created", "desc": MARKER})])
        write = self.admin.write
        def wrong_ack(resource, body):
            if body is None:
                return write(resource, None)
            write(resource, {"uri": "/unexpected"})
            return ack
        for run, ack, expected in (("73", {"uri": "/unexpected"}, "GATEWAY_WRITE_FAILED_RESTORED"),
                                   ("74", {}, "GATEWAY_RECONCILIATION_REQUIRED")):
            req = self.new_plan_request(run)
            plan = self.phase(req)
            with self.subTest(run=run), patch.object(self.admin, "write", side_effect=wrong_ack), \
                    self.assertRaisesRegex(mandate.Held, "^" + expected + "$"):
                self.phase(dict(req, phase="apply", digest=plan["digest"]))
            self.assertEqual(key in self.admin.data, expected == "GATEWAY_RECONCILIATION_REQUIRED")
            diagnostics = store.read(self.root / run / "gateway.apply.diagnostics")
            self.assertEqual(diagnostics[0]["stage"], "write-ack")
            self.assertEqual(diagnostics[0]["paths"],
                             ["desc: missing", "uri: changed" if ack else "uri: missing"])

    def test_get_and_compensation_failures_retain_only_field_paths(self):
        key = ("routes", "created")
        self.select([row(*key, {"uri": "/new", "plugins": {"openid-connect": {"client_secret": MARKER}}})])
        def alter_readback(key, body):
            self.admin.data[key]["plugins"]["openid-connect"].clear()
            self.admin.data[key]["uri"] = SECRET
        self.admin.on_write = alter_readback
        plan = self.phase(REQ)
        with self.assertRaisesRegex(mandate.Held, "^GATEWAY_RECONCILIATION_REQUIRED$"):
            self.phase(dict(REQ, phase="apply", digest=plan["digest"]))
        diagnostic = self.root / REQ["run"] / "gateway.apply.diagnostics"
        self.assertEqual(store.read(diagnostic), [
            dict(stage="write-get", kind="routes", id="created",
                 paths=["plugins.openid-connect.client_secret: missing", "uri: changed"]),
            dict(stage="compensation-drift", kind="routes", id="created", paths=["$: changed"])])

    def test_unreadable_get_records_no_response_or_exception_text(self):
        with patch.object(self.admin, "get", side_effect=OSError(SECRET)), \
                self.assertRaisesRegex(mandate.Held, "^GATEWAY_ADMIN_REQUEST$"):
            self.phase(REQ)
        self.assertEqual(store.read(self.root / REQ["run"] / "gateway.plan.diagnostics"), [
            dict(stage="plan-get", kind="upstreams", id="one", paths=["$: unavailable"])])

    def test_pending_return_uses_release_snapshot(self):
        receipt = self.phase(self.plan())
        applied = deepcopy(self.admin.data)
        def interrupt_return(*_):
            raise KeyboardInterrupt()
        self.admin.on_write = interrupt_return
        with self.assertRaises(KeyboardInterrupt):
            self.phase(self.return_req(receipt))
        self.admin.on_write = lambda *_: None
        req = self.new_plan_request("72")
        result = self.phase(req)
        self.assertEqual(result["recoveringRun"], "71")
        self.assertEqual(result["counts"], {"create": 0, "update": 1, "unchanged": 2})
        self.phase(dict(req, phase="apply", digest=result["digest"]))
        self.assertEqual(self.admin.data, applied)

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
        with self.assertRaisesRegex(mandate.Held, "^GATEWAY_PENDING_LIVE_DRIFT$"):
            self.phase(req)
        self.assertEqual(self.admin.data[("upstreams", "one")], {"desc": "foreign"})

    def test_return_rejects_changed_state_and_compensates_a_partial_return(self):
        req = self.plan()
        receipt = self.phase(req)
        back = self.return_req(receipt)
        applied = deepcopy(self.admin.data)
        self.admin.data[("routes", "one")]["uri"] = "/drift"
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
