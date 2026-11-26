"""Offline governed publisher, transport inbox and ordinary vertical-mock replacement."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from test_module_release import Engine, NEW, OLD, ROOT, TESTED, artifact, sha
from tools.module_release import operation, transport
from tools.module_release.contract import Held


class VerticalMockRelease(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.inbox = self.root / "inbox"
        self.inbox.mkdir()
        (self.root / "journal").mkdir()
        profile = json.loads((ROOT / "config/module-release/vertical-mock.example.json").read_bytes())
        executor = json.loads((ROOT / "docs/privileged-executor.example.json").read_bytes())
        installed = executor["modules"]["vertical-mock"]
        self.assertEqual(profile, {key: installed[key] for key in profile})
        self.assertEqual(profile["migration"], {"mode": "none", "rollbackCompatible": False})
        self.assertEqual(profile["gate"]["command"], ["/usr/local/bin/ouf-vertical-mock", "serve"])
        self.assertEqual(profile["gate"]["executable"], profile["gate"]["command"][0])
        ready = profile["readiness"]
        self.assertEqual((ready["path"], ready["port"], ready["acceptStatus"]), ("/health/ready", 8080, [204]))
        self.assertNotIn("jsonStatus", ready)
        self.p = profile
        self.ci = profile["ci"]
        self.ci.update(repository="fixture/reviewed-mock", sourceCommit="b"*40, sourceTree="c"*40,
                       pullRequest=2, runId=15, runAttempt=1, artifactId=17)
        profile.update(inbox=str(self.root), journal=str(self.root / "journal"), container="vertical-mock",
                       dockerSocket=str(self.root / "socket"), nsenter=str(self.root / "nsenter"),
                       oldImage="sha256:" + "a"*64, networks={"fixture": {"ipv4": "192.0.2.7", "aliases": ["mock"]}})
        profile["migration"]["rollbackCompatible"] = True
        self.contract_fields = dict(qualifiedInCiOnly=True, targetApplyAuthorized=False, humanBudgetGranted=False,
                                    releaseAcceptance=False, contract="ouf.vertical-mock.v1",
                                    journalFormat="ouf.vertical-mock-journal.v1")
        image = artifact(profile, self.root, **self.contract_fields)
        self.rt = Engine(profile, image)
        old = self.rt.docs[OLD]
        bindings = [("OUF_MOCK_DATA_DIR", "data", True), ("OUF_MOCK_DOMAIN_FILE", "domain", False),
                    ("OUF_MOCK_READ_TOKEN_FILE", "read", False), ("OUF_MOCK_ADMIN_TOKEN_FILE", "admin", False)]
        old["Config"].update(User="10008:10008", Env=[f"{key}=/fixture/{name}" for key, name, _ in bindings])
        old["Mounts"] = [dict(Type="bind", Source=f"/source/{name}", Destination=f"/fixture/{name}", RW=rw)
                         for _, name, rw in bindings]
        old["HostConfig"]["Binds"] = [f"/source/{name}:/fixture/{name}:{'rw' if rw else 'ro'}"
                                      for _, name, rw in bindings]
        self.original = (self.root / (self.ci["zipSha256"] + ".zip")).read_bytes()
        with zipfile.ZipFile(io.BytesIO(self.original)) as archive:
            self.payload = {name: archive.read(name) for name in archive.namelist()}
        self.manifest = json.loads(self.payload["manifest.json"])
        repo = {"full_name": self.ci["repository"]}
        self.run = dict(id=15, status="completed", conclusion="success", event="pull_request",
                        path=".github/workflows/module-ci.yml", run_attempt=1, repository=repo, head_repository=repo,
                        head_sha=TESTED, pull_requests=[{"number": 2, "head": {"sha": self.ci["sourceCommit"]}}])
        self.item = dict(id=17, expired=False, workflow_run={"id": 15, "head_sha": TESTED},
                         name="vertical-mock-governed-image-15", digest="sha256:" + self.ci["zipSha256"])
        self.merge = dict(sha=TESTED, tree={"sha": self.ci["sourceTree"]}, parents=[{"sha": self.ci["sourceCommit"]}])
        self.source = dict(sha=self.ci["sourceCommit"], tree={"sha": self.ci["sourceTree"]})
        self.github = self.enterContext(patch.object(transport, "github", side_effect=self.api))

    def api(self, path, output=None):
        prefix = "repos/" + self.ci["repository"]
        if output is not None:
            self.assertEqual(path, prefix + "/actions/artifacts/17/zip")
            output.write((self.root / (self.ci["zipSha256"] + ".zip")).read_bytes())
            return
        return {prefix + "/actions/runs/15": self.run, prefix + "/actions/artifacts/17": self.item,
                prefix + "/git/commits/" + TESTED: self.merge,
                prefix + "/git/commits/" + self.ci["sourceCommit"]: self.source}[path]

    def deliver(self):
        return transport.transport(self.p, 15, 17, self.inbox)

    def repack(self, **changes):
        packed = io.BytesIO()
        with zipfile.ZipFile(packed, "w") as archive:
            for name, data in (self.payload | changes).items():
                archive.writestr(name, data)
        key = sha(packed.getvalue())
        (self.root / (key + ".zip")).write_bytes(packed.getvalue())
        self.item["digest"] = "sha256:" + key
        self.ci["zipSha256"] = key

    def assert_held(self, reason):
        with self.assertRaises(Held) as denied:
            self.deliver()
        self.assertEqual(str(denied.exception), reason)
        self.assertEqual(list(self.inbox.iterdir()), [])
        plan = operation.plan(self.p, self.rt)
        self.assertEqual((plan["status"], plan["reason"]), ("HELD", reason))
        self.assertEqual(self.rt.events, [])

    def test_transport_to_ready_inherits_data_bind(self):
        receipt = self.deliver()
        self.assertEqual(receipt, self.deliver())
        self.assertEqual((self.inbox / (receipt["zipSha256"] + ".zip")).read_bytes(), self.original)
        self.assertIn(self.ci["imageId"], receipt["verifiedImageIds"])
        self.assertEqual(receipt["publisherImageId"], self.manifest["imageId"])
        self.assertEqual(receipt["testedCommit"], TESTED)
        self.assertNotIn("migrations", receipt)
        self.p["inbox"] = str(self.inbox)
        plan = operation.plan(self.p, self.rt)
        self.assertEqual(plan["status"], "PLANNED", plan)
        final = operation.apply(self.p, plan["planSha256"], self.rt, defer_migration=True)
        self.assertEqual(final["status"], "READY", final)
        self.assertEqual((final["predecessorCid"], final["successorCid"], final["readyHttp"]), (OLD, NEW, 204))
        successor = self.rt.inspect(self.p["container"])
        self.assertEqual(successor["Image"], self.ci["imageId"])
        self.assertEqual(successor["Config"]["User"], "10008:10008")
        self.assertEqual(successor["Config"]["Env"], self.rt.docs[OLD]["Config"]["Env"])
        self.assertEqual(successor["HostConfig"]["Binds"], self.rt.docs[OLD]["HostConfig"]["Binds"])
        self.assertEqual(successor["Mounts"], self.rt.docs[OLD]["Mounts"])
        self.assertFalse(self.rt.inspect(self.p["retainedName"])["State"]["Running"])

    def assert_plan_held(self, reason):
        before = self.rt.events.copy()
        plan = operation.plan(self.p, self.rt)
        self.assertEqual((plan["status"], plan["reason"]), ("HELD", reason))
        self.assertTrue(self.rt.docs[OLD]["State"]["Running"])
        self.assertEqual(self.rt.events, before)

    def test_no_mounts_held_before_stop(self):
        old = self.rt.docs[OLD]
        old["Mounts"] = []
        old["HostConfig"]["Binds"] = []
        self.assert_plan_held("PERSISTENT_MOUNTS_REQUIRED")

    def test_domain_bind_alone_held_before_stop(self):
        old = self.rt.docs[OLD]
        old["Mounts"] = old["Mounts"][1:2]
        old["HostConfig"]["Binds"] = old["HostConfig"]["Binds"][1:2]
        self.assert_plan_held("PERSISTENT_PATH_UNCOVERED")

    def test_readonly_data_bind_held_at_plan_and_apply_recheck(self):
        plan = operation.plan(self.p, self.rt)
        self.assertEqual(plan["status"], "PLANNED", plan)
        old = self.rt.docs[OLD]
        old["Mounts"][0]["RW"] = False
        old["HostConfig"]["Binds"][0] = "/source/data:/fixture/data:ro"
        self.assert_plan_held("PERSISTENT_BIND_RW_REQUIRED")
        before = self.rt.events.copy()
        result = operation.apply(self.p, plan["planSha256"], self.rt)
        self.assertEqual((result["status"], result["reason"]), ("HELD", "PERSISTENT_BIND_RW_REQUIRED"))
        self.assertTrue(old["State"]["Running"])
        self.assertEqual(self.rt.events, before)

    def test_named_volume_held_before_stop(self):
        old = self.rt.docs[OLD]
        old["Mounts"][0].update(Type="volume", Name="mock-data", Source="/fixture/volume-data")
        old["HostConfig"]["Binds"][0] = "mock-data:/fixture/data:rw"
        self.assert_plan_held("EXPLICIT_BIND_MOUNTS_REQUIRED")

    def test_nearest_mount_covers_observed_env_path(self):
        old = self.rt.docs[OLD]
        # Review 61d-b (Astra): a subdirectory of the RW bind can be a symlink to volatile storage
        # that the inspect cannot see, so only the bind destination itself is a persistent path.
        old["Config"]["Env"][0] = "OUF_MOCK_DATA_DIR=/fixture/data/store/journal"
        self.assert_plan_held("PERSISTENT_PATH_NOT_BIND_ROOT")
        old["Config"]["Env"][0] = "OUF_MOCK_DATA_DIR=/fixture/data"
        self.assertEqual(operation.plan(self.p, self.rt)["status"], "PLANNED")
        old["Config"]["Env"].append("OTHER_PATH=/fixture/data/store")
        self.p["persistentPathEnv"].append("OTHER_PATH")
        old["HostConfig"]["Tmpfs"] = {"/fixture/data/store": "nosuid"}
        self.assert_plan_held("EXPLICIT_BIND_MOUNTS_REQUIRED")
        old["Config"]["Env"][0] = "OUF_MOCK_DATA_DIR=/fixture/database"
        self.assert_plan_held("PERSISTENT_PATH_UNCOVERED")

    def test_observed_env_required_and_unambiguous(self):
        env = self.rt.docs[OLD]["Config"]["Env"]
        entry = env.pop(0)
        self.assert_plan_held("PERSISTENT_PATH_ENV_REQUIRED")
        env.append("OUF_MOCK_DATA_DIR=/fixture/data/../domain")
        self.assert_plan_held("PERSISTENT_PATH_INVALID")
        env.append(entry)
        self.assert_plan_held("PERSISTENT_PATH_ENV_REQUIRED")

    def test_mock_profile_must_declare_data_path(self):
        del self.p["persistentPathEnv"]
        self.assert_plan_held("PERSISTENT_PATH_PROFILE_REQUIRED")

    def test_manifest_closed_at_transport_and_release(self):
        for key in self.manifest:
            with self.subTest(missing=key):
                manifest = self.manifest.copy()
                del manifest[key]
                self.repack(**{"manifest.json": json.dumps(manifest)})
                self.assert_held("VERTICAL_MOCK_MANIFEST_FIELDS")
        for extra in ({"unexpected": None}, {"flywayMigrations": []}):
            with self.subTest(extra=extra):
                self.repack(**{"manifest.json": json.dumps(self.manifest | extra)})
                self.assert_held("VERTICAL_MOCK_MANIFEST_FIELDS")
        duplicate = '{"releaseAcceptance":false,' + json.dumps(self.manifest)[1:]
        self.repack(**{"manifest.json": duplicate})
        self.assert_held("VERTICAL_MOCK_MANIFEST_FIELDS")

    def test_manifest_flags_and_contract_values(self):
        for key in ("targetApplyAuthorized", "humanBudgetGranted", "releaseAcceptance"):
            for value in (True, 0, "false", None):
                with self.subTest(key=key, value=value):
                    self.repack(**{"manifest.json": json.dumps(self.manifest | {key: value})})
                    self.assert_held("VERTICAL_MOCK_MANIFEST_CONTRACT")
        for key, value in (("qualifiedInCiOnly", 1), ("schema", "other"), ("contract", "other"),
                           ("journalFormat", "other")):
            with self.subTest(key=key):
                self.repack(**{"manifest.json": json.dumps(self.manifest | {key: value})})
                self.assert_held("VERTICAL_MOCK_MANIFEST_CONTRACT")

    def test_publisher_profile_is_fixed(self):
        for key in ("workflow", "imageName", "manifestSchema", "artifactPrefix", "pullRequest"):
            with self.subTest(key=key), patch.dict(self.ci, {key: "other"}):
                self.assert_held("VERTICAL_MOCK_PUBLISHER_PINS_REQUIRED")
        with self.assertRaisesRegex(Held, "MODULE_PROFILE_MISMATCH"):
            transport.transport({"ci": self.ci}, 15, 17, self.inbox)
        with patch.dict(self.p, migrationsField="flywayMigrations"), self.assertRaisesRegex(
                Held, "VERTICAL_MOCK_MIGRATION_PROFILE"):
            self.deliver()
        with patch.dict(self.p["migration"], mode="spring-flyway"):
            self.assertEqual(operation.plan(self.p, self.rt)["reason"], "VERTICAL_MOCK_MIGRATION_PROFILE")

    def test_malformed_repository_rejected_without_api_call(self):
        for value in ("other", "owner/", "../repo", "a/b/c", None):
            with self.subTest(value=value), patch.dict(self.ci, repository=value):
                self.assert_held("VERTICAL_MOCK_PUBLISHER_PINS_REQUIRED")
                with self.assertRaisesRegex(Held, "CI_PINS_REQUIRED"):
                    transport.select(self.ci, 15, 17, self.github)
                self.github.assert_not_called()

    def test_valid_repository_differs_from_run(self):
        with patch.dict(self.ci, repository="another/approved-name"):
            with self.assertRaisesRegex(Held, "SUCCESSFUL_APPROVED_PR_RUN_REQUIRED"):
                self.deliver()
        self.github.assert_called_once_with("repos/another/approved-name/actions/runs/15")
        self.assertEqual(list(self.inbox.iterdir()), [])

    def test_run_artifact_and_trees_before_publication(self):
        for record, change, code in (
                (self.run, {"conclusion": "failure"}, "SUCCESSFUL_APPROVED_PR_RUN_REQUIRED"),
                (self.run, {"event": "push"}, "SUCCESSFUL_APPROVED_PR_RUN_REQUIRED"),
                (self.run, {"pull_requests": []}, "SUCCESSFUL_APPROVED_PR_RUN_REQUIRED"),
                (self.item, {"name": "vertical-mock-governed-image-16"}, "CI_ARTIFACT_CHANGED"),
                (self.item, {"digest": "sha256:" + "0"*64}, "TRANSPORT_PIN_CHANGED"),
                (self.ci, {"runAttempt": 2}, "TRANSPORT_PIN_CHANGED"),
                (self.merge, {"parents": []}, "TESTED_TREE_CHANGED"),
                (self.merge, {"tree": {"sha": "0"*40}}, "TESTED_TREE_CHANGED"),
                (self.source, {"tree": {"sha": "0"*40}}, "SOURCE_TREE_CHANGED")):
            with self.subTest(change=change), patch.dict(record, change), self.assertRaisesRegex(Held, code):
                self.deliver()
            self.assertEqual(list(self.inbox.iterdir()), [])

    def test_archived_revision_label_is_verified_even_with_valid_digests(self):
        artifact(self.p, self.root, revision_label=self.ci["sourceCommit"], **self.contract_fields)
        self.item["digest"] = "sha256:" + self.ci["zipSha256"]
        self.assert_held("IMAGE_LABELS_CHANGED")

    def test_image_id_and_checksums_bound_to_bytes(self):
        with patch.dict(self.ci, imageId="sha256:" + "0"*64):
            self.assert_held("IMAGE_ID_CHANGED")
        self.repack(SHA256SUMS=b"wrong\n")
        self.assert_held("IMAGE_ARCHIVE_DIGEST_CHANGED")
        (self.root / (self.ci["zipSha256"] + ".zip")).write_bytes(self.original)
        self.assert_held("ARTIFACT_DIGEST_CHANGED")
