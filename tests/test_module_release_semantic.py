"""Original Semantic publisher ZIP through transport and A2 admission, without a network."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_module_release import ROOT, TESTED, artifact, sha
from module_release import transport
from module_release.contract import Held
from store import Journal
from successor_image import admit


RUN = 44796175289
ARTIFACT = 73  # Synthetic numeric artifact ID.
REPO = "GioNob/ouf-semantic-registry"
HEAD = "8a79db9201c6285749669a58b169ccf9e0da7cb2"
TREE = "e293bbe42b3229087027d015a2002b0775939bd4"
MIGRATIONS = [{"name": "V13__adoption.sql", "sha256": sha(b"fixture SQL")}]


class SemanticTransport(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads((ROOT / "tests/fixtures/module-release/semantic-successor.example.json").read_bytes())
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.inbox = self.root / "inbox"
        self.inbox.mkdir()
        repo = {"full_name": REPO}
        self.run = dict(id=RUN, status="completed", conclusion="success", event="pull_request",
                        path=".github/workflows/module-ci.yml", run_attempt=2, run_started_at="2026-11-20T10:00:00Z",
                        repository=repo, head_repository=repo, head_sha=HEAD,
                        pull_requests=[{"number": 49, "head": {"sha": HEAD}}])
        self.item = dict(id=ARTIFACT, expired=False, workflow_run=dict(id=RUN, head_sha=HEAD),
                         created_at="2026-11-20T10:01:00Z", name=f"semantic-registry-governed-image-{RUN}")
        self.merge = dict(sha=TESTED, tree={"sha": TREE}, parents=[{"sha": "c"*40}, {"sha": HEAD}])
        self.source = dict(sha=HEAD, tree={"sha": TREE})
        self.api = {f"/actions/runs/{RUN}": self.run, f"/actions/artifacts/{ARTIFACT}": self.item,
                    "/git/commits/" + TESTED: self.merge, "/git/commits/" + HEAD: self.source}
        self.make_zip()
        self.enterContext(patch.object(transport, "github", side_effect=self.github))

    def make_zip(self, **overrides):
        ci = dict(imageName="ouf-semantic-registry", manifestSchema="ouf.semantic-tested-image.v1",
                  repository=REPO, sourceCommit=HEAD, sourceTree=TREE, runId=RUN, runAttempt=2)
        fields = dict(qualifiedInCiOnly=True, targetApplyAuthorized=False, humanBudgetGranted=False,
                      releaseAcceptance=False, flywayMigrations=MIGRATIONS)
        self.image = artifact({"ci": ci}, self.root, **(fields | overrides))
        self.target_id = ci["imageId"]
        self.zip = self.root / (ci["zipSha256"] + ".zip")
        self.item["digest"] = "sha256:" + ci["zipSha256"]

    def github(self, path, out=None):
        prefix = "repos/" + REPO
        if out is not None:
            self.assertEqual(path, prefix + f"/actions/artifacts/{ARTIFACT}/zip")
            out.write(self.zip.read_bytes())
        else:
            self.assertTrue(path.startswith(prefix + "/"))
            return self.api[path[len(prefix):]]

    def deliver(self):
        return transport.transport(self.profile, RUN, ARTIFACT, self.inbox)

    def test_original_zip_and_reviewed_merge_reach_a2(self):
        receipt = self.deliver()
        self.assertEqual(receipt["testedCommit"], TESTED)
        self.assertEqual(receipt["sourceCommit"], HEAD)
        self.assertEqual(receipt["migrations"], MIGRATIONS)
        self.assertEqual(receipt["zipSha256"] + ".zip", self.zip.name)
        self.assertEqual((self.inbox / self.zip.name).read_bytes(), self.zip.read_bytes())
        # GitHub can report the tested merge as the run head. Redelivery is idempotent.
        self.run["head_sha"] = self.item["workflow_run"]["head_sha"] = TESTED
        self.assertEqual(self.deliver(), receipt)
        self.assertEqual(list(self.inbox.iterdir()), [self.inbox / self.zip.name])
        ci = self.profile["ci"].copy()
        del ci["artifactPrefix"]
        ci.update({k: receipt[k] for k in ("runId", "runAttempt", "artifactId", "zipSha256")}, imageId=self.target_id)
        spec = dict(ci=ci, inbox=str(self.inbox), migrationsField="flywayMigrations", predecessorMigrations=[])
        with patch("store.sync_dir"), patch("successor_image.Docker") as engine:
            def load(archive, facts):
                self.assertEqual(archive.read(), self.image)
                self.assertEqual(facts["testedCommit"], TESTED)
                return self.target_id
            engine.return_value.load.side_effect = load
            result = admit(dict(successorImage=spec, socket="fixture"), Journal(self.root / "run"), self.api.__getitem__)
            engine.return_value.load.assert_called_once()
        self.assertEqual(result["newMigrations"], MIGRATIONS)

    def test_refuses_unrelated_heads_trees_and_old_attempt_before_publication(self):
        for obj, changes, error in (
                (self.merge, {"parents": []}, "TESTED_TREE_CHANGED"),
                (self.merge, {"tree": {"sha": "f"*40}}, "TESTED_TREE_CHANGED"),
                (self.source, {"tree": {"sha": "f"*40}}, "SOURCE_TREE_CHANGED"),
                (self.item, {"created_at": "2026-11-20T09:59:00Z"}, "ARTIFACT_ATTEMPT_CHANGED"),
                (self.item, {"name": f"source-onboarding-governed-image-{RUN}"}, "CI_ARTIFACT_CHANGED"),
                (self.item, {"digest": "sha256:" + "0"*64}, "ARTIFACT_DIGEST_CHANGED")):
            with self.subTest(error=error), patch.dict(obj, changes), self.assertRaisesRegex(Held, error):
                self.deliver()
            self.assertEqual(list(self.inbox.iterdir()), [])
        self.run["head_sha"] = self.item["workflow_run"]["head_sha"] = "e"*40
        with self.assertRaisesRegex(Held, "TESTED_RUN_CHANGED"):
            self.deliver()
        self.assertEqual(list(self.inbox.iterdir()), [])

    def test_refuses_manifest_drift_before_publication(self):
        for changes, reason in (({"reviewedSourceCommit": TESTED}, "CI_PROVENANCE_CHANGED"),
                                ({"workflowRunAttempt": "1"}, "CI_PROVENANCE_CHANGED"),
                                ({"targetApplyAuthorized": True}, "CI_PROVENANCE_CHANGED"),
                                ({"flywayMigrations": [{"name": "V13.sql"}]}, "MIGRATION_INVENTORY_REQUIRED")):
            with self.subTest(changes=changes):
                self.make_zip(**changes)
                with self.assertRaisesRegex(Held, reason):
                    self.deliver()
                self.assertEqual(list(self.inbox.iterdir()), [])
