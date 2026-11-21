"""Offline admission of a Semantic CI ZIP into a simulated local image store."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_module_release import PROFILE, TESTED, artifact
from mandate import Held
from module_release.docker import Docker
from store import Journal
from successor_image import admit, live_manifest
from module_release.contract import SEMANTIC_SCHEMA


class SemanticArtifact(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch("store.sync_dir"))
        self.journal = Journal(self.root / "run")
        ci = json.loads(PROFILE.read_bytes())["ci"]
        ci.update(repository="owner/ouf-semantic-registry", workflow="module-ci.yml", imageName="registry",
                  runId=42, runAttempt=2, artifactId=19)
        self.spec = dict(inbox=str(self.root), ci=ci, migrationsField="migrations",
                         predecessorMigrations=["V12__previous.sql"])
        self.cfg = dict(successorImage=self.spec, socket="unused")
        self.blob = artifact(self.spec, self.root, migrations=["V12__previous.sql", "V13__adoption.sql"])
        repo = {"full_name": ci["repository"]}
        self.run = dict(id=42, run_attempt=2, event="pull_request", status="completed", conclusion="success",
                        path=".github/workflows/module-ci.yml", repository=repo, head_repository=repo,
                        head_sha=ci["sourceCommit"], pull_requests=[{"number": ci["pullRequest"],
                                                                    "head": {"sha": ci["sourceCommit"]}}])
        self.obj = dict(id=19, name="semantic-registry-governed-image-42", expired=False,
                        workflow_run={"id": 42, "head_sha": ci["sourceCommit"]}, digest="sha256:" + ci["zipSha256"])
        self.tree = dict(sha=TESTED, tree={"sha": ci["sourceTree"]}, parents=[{"sha": ci["sourceCommit"]}])
        self.get = {"/actions/runs/42": self.run, "/actions/artifacts/19": self.obj,
                    "/git/commits/" + TESTED: self.tree}.__getitem__
        def engine(method, path, **kw):
            if method == "POST":
                self.assertEqual(path, "/images/load?quiet=1")
                self.assertEqual(kw["archive"].read(), self.blob)
                return None
            return {"Id": ci["imageId"], "Config": {"Labels": {"org.opencontainers.image.revision": TESTED,
                    "org.opencontainers.image.source": "https://github.com/" + ci["repository"]}}}
        self.engine = self.enterContext(patch.object(Docker, "api", side_effect=engine))

    def run_plan(self):
        return admit(self.cfg, self.journal, self.get)

    def test_live_inventory_selects_exact_profile_image_without_load(self):
        self.spec.update(migrationsField="flywayMigrations")
        ci = self.spec["ci"]
        ci["manifestSchema"] = SEMANTIC_SCHEMA
        rows = [{"name": "V12__previous.sql", "sha256": "a"*64}]
        artifact(self.spec, self.root, flywayMigrations=rows, qualifiedInCiOnly=True,
                 targetApplyAuthorized=False, humanBudgetGranted=False, releaseAcceptance=False)
        for key in ("successorImage", "nextSuccessorImage"):
            with self.subTest(key=key):
                self.assertEqual(live_manifest({key: self.spec}, ci["imageId"]), rows)
        with self.assertRaisesRegex(Held, "LIVE_SEMANTIC_MANIFEST_REQUIRED"):
            live_manifest(self.cfg, "sha256:" + "9"*64)
        self.engine.assert_not_called()

    def test_load_exact_publisher_bytes_into_approved_store_identity(self):
        result = self.run_plan()
        self.assertEqual(result["ci"], self.spec["ci"])
        self.assertIn(result["ci"]["imageId"], result["verifiedImageIds"])
        self.assertEqual(result["newMigrations"], ["V13__adoption.sql"])
        self.assertEqual(result["migrations"], ["V12__previous.sql", "V13__adoption.sql"])
        self.assertEqual(self.engine.call_count, 2)
        self.assertTrue((self.journal.path / "load-image.receipt").exists())

    def test_ci_membership_and_tested_tree_before_load(self):
        for obj, key, bad in ((self.obj, "name", "different"), (self.obj, "workflow_run", {"id": 41}),
                              (self.run, "path", ".github/workflows/other.yml"), (self.run, "run_attempt", 1),
                              (self.run, "repository", {"full_name": "other/module"}), (self.run, "pull_requests", []),
                              (self.run, "head_sha", "a"*40), (self.tree, "parents", []),
                              (self.obj, "digest", "sha256:" + "a"*64)):
            with self.subTest(key=key), patch.dict(obj, {key: bad}), self.assertRaises(Held):
                self.run_plan()
        self.engine.assert_not_called()

    def test_tampered_local_zip(self):
        next(self.root.glob("*.zip")).write_bytes(b"other bytes")
        with self.assertRaisesRegex(Held, "ARTIFACT_DIGEST_CHANGED"):
            self.run_plan()
        self.engine.assert_not_called()

    def test_image_id_outside_published_archive(self):
        self.spec["ci"]["imageId"] = "sha256:" + "9"*64
        with self.assertRaisesRegex(Held, "IMAGE_ID_CHANGED"):
            self.run_plan()
        self.engine.assert_not_called()

    def test_publisher_manifest_drift(self):
        for changes, code in (({"imageId": "sha256:" + "9"*64}, "IMAGE_ID_CHANGED"),
                              ({"reviewedSourceCommit": "9"*40}, "CI_PROVENANCE_CHANGED")):
            with self.subTest(code=code):
                self.blob = artifact(self.spec, self.root, migrations=self.spec["predecessorMigrations"], **changes)
                self.obj["digest"] = "sha256:" + self.spec["ci"]["zipSha256"]
                with self.assertRaisesRegex(Held, code):
                    self.run_plan()
        self.engine.assert_not_called()

    def test_loaded_image_drift(self):
        self.engine.side_effect = [None, {"Id": "sha256:" + "9"*64, "Config": {"Labels": {}}}]
        with self.assertRaisesRegex(Held, "LOADED_IMAGE_CHANGED"):
            self.run_plan()
        self.assertFalse((self.journal.path / "load-image.receipt").exists())

    def test_unverifiable_migrations_before_load(self):
        for fields in ({"migrationsField": "absent"}, {"predecessorMigrations": ["V12__other.sql"]}):
            with self.subTest(fields=fields), patch.dict(self.spec, fields), self.assertRaises(Held):
                self.run_plan()
        self.engine.assert_not_called()
