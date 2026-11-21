"""Portable CI ZIP + Engine/HTTP doubles for the governed module release."""
import copy
import hashlib
import io
import json
import os
import runpy
import stat
import sys
from unittest.mock import Mock, patch
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tools"), *(str(ROOT / "tools" / folder) for folder in
                ("privileged_executor", "semantic_provider_r3", "semantic_application_cutover"))]

from tools.module_release.contract import ENTRY, Held
from tools.module_release import docker
from tools.module_release.frame import merge_image
from tools.module_release.operation import apply, migrate, plan
from tools.module_release.transport import select


PROFILE = Path(__file__).resolve().parents[1] / "tests/fixtures/module-release/onboarding.example.json"
OLD, NEW = "1" * 64, "2" * 64
TESTED = "d" * 40


def sha(data):
    return hashlib.sha256(data).hexdigest()


class GateProcessTest(unittest.TestCase):
    def test_ingestion_gate_and_java_match_only_the_command_of_their_image(self):
        proc = Path(self.enterContext(tempfile.TemporaryDirectory()))
        profile = json.loads(PROFILE.with_name("ingestion.example.json").read_bytes())
        profile["gate"]["executable"] = "/opt/java/bin/java"
        old = profile["gate"]["command"]
        new = old[:3]
        doc = {"State": {"Pid": 42, "Running": True}}
        (proc / "status").write_text("SigCgt:\t00000200\n")
        self.enterContext(patch.object(docker, "Path", return_value=proc))
        self.enterContext(patch.object(docker.signal, "SIGUSR1", 10, create=True))
        self.enterContext(patch.object(docker, "gate_shell_matches", return_value=True))
        self.enterContext(patch.object(docker.os, "readlink", return_value="/opt/java/bin/java"))
        rt = docker.Docker(profile)
        for image, expected in ((profile["oldImage"], old), (profile["ci"]["imageId"], new)):
            doc["Image"] = image
            for gated in (True, False):
                for actual in (new, old):
                    argv = ENTRY + actual if gated else actual
                    (proc / "cmdline").write_bytes(b"\0".join(arg.encode() for arg in argv) + b"\0")
                    self.assertEqual(rt.process(doc, gated), actual == expected)

    def test_shell_links_argv_and_signal_mask(self):
        proc = Path(self.enterContext(tempfile.TemporaryDirectory()))
        command = ["/usr/local/bin/ouf-mcp", "server"]
        rt = docker.Docker({"gate": {"command": command}})
        doc = {"State": {"Pid": 42, "Running": True}}
        (proc / "exe").touch()
        (proc / "other").touch()
        (proc / "status").write_text("SigCgt:\t00000200\n")
        cmdline = b"\0".join(arg.encode() for arg in ENTRY + command) + b"\0"
        (proc / "cmdline").write_bytes(cmdline)

        # Simulated directory descriptors allow POSIX links even on Windows.
        root, bin_dir, shell, applet = range(4)
        files = {(None, proc / "root"): root, (root, "bin"): bin_dir,
                 (bin_dir, "sh"): shell, (bin_dir, "busybox"): applet}
        metadata = {bin_dir: Mock(st_mode=stat.S_IFDIR), shell: Mock(st_mode=stat.S_IFLNK),
                    applet: (proc / "exe").stat()}
        kernel = Mock(wraps=os, O_PATH=1, O_DIRECTORY=2, O_NOFOLLOW=4, path=os.path)
        kernel.open.side_effect = lambda path, flags, dir_fd=None: files[dir_fd, path]
        kernel.fstat.side_effect = metadata.__getitem__
        kernel.close = Mock()
        self.enterContext(patch.object(docker, "os", kernel))
        self.enterContext(patch.object(docker, "Path", return_value=proc))
        self.enterContext(patch.object(docker.signal, "SIGUSR1", 10, create=True))
        for link in ("/bin/busybox", "busybox", "../../bin/busybox"):
            with self.subTest(link=link):
                kernel.readlink.return_value = link
                self.assertTrue(rt.process(doc, gated=True))
                kernel.readlink.assert_called_with("", dir_fd=shell)
        kernel.readlink.return_value = "/bin/sh"
        self.assertFalse(rt.process(doc, gated=True))
        kernel.readlink.return_value = "/bin/busybox"
        metadata[applet] = (proc / "other").stat()
        self.assertFalse(rt.process(doc, gated=True))
        metadata[applet] = (proc / "exe").stat()
        (proc / "cmdline").write_bytes(cmdline + b"\0")
        self.assertFalse(rt.process(doc, gated=True))
        (proc / "cmdline").write_bytes(cmdline)
        (proc / "status").write_text("SigCgt:\t00000000\n")
        self.assertFalse(rt.process(doc, gated=True))


def artifact(p, root, *, image_env=None, **manifest_changes):
    ci = p["ci"]
    tag = ci["imageName"] + ":" + TESTED
    defaults = {"Labels": {"org.opencontainers.image.revision": TESTED,
                           "org.opencontainers.image.source": "https://github.com/" + ci["repository"]}}
    if image_env is not None:
        defaults["Env"] = image_env
    raw = json.dumps({"config": defaults}).encode()
    config = sha(raw)
    publisher = json.dumps({"config": {"digest": "sha256:" + config}}).encode()
    manifest_id = "sha256:" + sha(publisher)
    members = {"blobs/sha256/" + config: raw, "blobs/sha256/" + sha(publisher): publisher,
               "index.json": json.dumps({"manifests": [{"digest": manifest_id, "size": len(publisher)}]}).encode(),
               "manifest.json": json.dumps([{"Config": "blobs/sha256/" + config, "RepoTags": [tag]}]).encode()}
    image = io.BytesIO()
    with tarfile.open(fileobj=image, mode="w:gz") as tar:
        for name, data in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    blob = image.getvalue()
    manifest = dict(schema=ci["manifestSchema"], repository=ci["repository"], reviewedSourceCommit=ci["sourceCommit"],
                    testedCommit=TESTED, testedTree=ci["sourceTree"], workflowRunId=str(ci["runId"]),
                    workflowRunAttempt=str(ci["runAttempt"]), imageTag=tag, imageRevisionLabel=TESTED,
                    archiveName="image.tar.gz", archiveSha256=sha(blob), archiveBytes=len(blob), imageId=manifest_id)
    manifest.update(manifest_changes)
    packed = io.BytesIO()
    with zipfile.ZipFile(packed, "w") as z:
        z.writestr("manifest.json", json.dumps(manifest))
        z.writestr("image.tar.gz", blob)
        z.writestr("SHA256SUMS", sha(blob) + "  image.tar.gz\n")
    ci.update(zipSha256=sha(packed.getvalue()), imageId="sha256:" + config)
    (root / (ci["zipSha256"] + ".zip")).write_bytes(packed.getvalue())
    return blob


class Engine:
    def __init__(self, p, blob):
        self.p = p
        self.blob = blob
        self.events = []
        self.fault = None
        self.gates = set()
        self.nets = {}
        for i, (net, binding) in enumerate(p["networks"].items(), start=1):
            self.nets[net] = {"NetworkID": str(i) * 64, "IPAMConfig": None, "IPAddress": binding["ipv4"],
                              "Aliases": binding["aliases"] + [OLD[:12]], "MacAddress": "allocated-at-first-start"}
        self.docs = {OLD: {"Id": OLD, "Image": p["oldImage"], "Name": "/" + p["container"],
                           "Config": {"Image": "previous:ci", "Entrypoint": ENTRY, "Cmd": p["gate"]["command"],
                                      "MacAddress": "legacy", "Env": ["KEEP=fixture"], "Labels": {"retain": "value"}},
                           "Path": ENTRY[0], "Args": ENTRY[1:] + p["gate"]["command"],
                           "HostConfig": {"AutoRemove": False, "RestartPolicy": {"Name": "no"}, "OomKillDisable": None},
                           "Mounts": [{"Type": "bind", "Destination": "/fixture"}],
                           "NetworkSettings": {"Networks": copy.deepcopy(self.nets), "Ports": {}},
                           "State": {"Running": True, "Status": "running", "Pid": 12, "StartedAt": "first"},
                           "RestartCount": 0}}

    def inspect(self, ident, missing=False):
        for cid, doc in self.docs.items():
            if ident in (cid, doc["Name"][1:]):
                return copy.deepcopy(doc)
        if not missing:
            raise Held("MISSING")

    def load(self, archive, package):
        assert archive.read() == self.blob
        self.events.append("load")

    def image_defaults(self, image_id):
        return {}

    def stop(self, cid):
        self.events.append("stop:" + cid[0])
        self.docs[cid]["State"].update(Running=False, Status="exited", Pid=0)

    def start(self, cid):
        self.events.append("gate:" + cid[0])
        self.docs[cid]["HostConfig"]["OomKillDisable"] = None
        self.docs[cid]["State"].update(Running=True, Status="running", Pid=55, StartedAt="next")
        self.gates.add(cid)

    def rename(self, cid, name):
        self.docs[cid]["Name"] = "/" + name

    def disconnect(self, cid, network):
        nets = self.docs[cid]["NetworkSettings"]["Networks"]
        net = next(n for n, e in self.nets.items() if e["NetworkID"] == network)
        del nets[net]
        if self.fault == "lost_disconnect":
            self.fault = None
            raise OSError()

    def connect(self, cid, network, settings):
        net = next(n for n, e in self.nets.items() if e["NetworkID"] == network)
        ep = copy.deepcopy(self.nets[net])
        ep.update(settings)
        ep["Aliases"] = settings["Aliases"] + [cid[:12]]
        ep["MacAddress"] = "allocated-on-attach"
        self.docs[cid]["NetworkSettings"]["Networks"][net] = ep

    def create(self, name, request):
        self.events.append("create")
        doc = copy.deepcopy(self.docs[OLD])
        self.docs[NEW] = doc
        cfg = copy.deepcopy(request)
        nets = cfg.pop("NetworkingConfig")["EndpointsConfig"]
        doc["HostConfig"] = cfg.pop("HostConfig")
        merge_image(cfg, self.image_defaults(cfg["Image"]))
        doc.update(Id=NEW, Name="/" + name, Image=cfg["Image"], Config=cfg)
        doc["Path"], *doc["Args"] = cfg["Entrypoint"] + cfg["Cmd"]
        doc["State"].update(Status="created", StartedAt="0001-01-01T00:00:00Z", FinishedAt="0001-01-01T00:00:00Z")
        for net, settings in nets.items():
            assert "MacAddress" not in settings
            self.connect(NEW, self.nets[net]["NetworkID"], settings)
        if self.fault == "config":
            cfg["Env"] = ["CHANGED=fixture"]
        if self.fault == "network":
            doc["NetworkSettings"]["Networks"][next(iter(nets))]["Aliases"].append("unexpected")
        if self.fault == "lost_create":
            raise OSError()
        return NEW

    def process(self, doc, gated):
        if self.fault == "handler" and doc["Id"] == NEW:
            return False
        return (doc["Id"] in self.gates) == gated

    def signal(self, cid):
        assert cid in self.gates
        self.gates.remove(cid)
        self.events.append("signal:" + cid[0])
        if cid == NEW and self.p["migration"]["mode"] == "spring-flyway":
            self.events.append("spring-flyway")
        if cid == NEW and self.fault == "lost_signal":
            raise OSError()

    def probe(self, doc):
        self.events.append("probe:" + doc["Id"][0])
        if self.fault == "readiness" and doc["Id"] == NEW:
            return 200, b'{"nested":{"status":"UP"},"status":"DOWN"}'
        if "jsonStatus" not in self.p["readiness"]:
            return 204, b""
        return 200, b'{"status":"UP"}'

    def migrate(self, cid, command):
        assert cid in self.gates
        self.events.append("migrate")

    def pause(self):
        pass


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        p = self.p = json.loads(PROFILE.read_text(encoding="utf-8"))
        p.update(inbox=tmp.name, journal=tmp.name, dockerSocket=str(self.root / "sock"),
                 nsenter=str(self.root / "nsenter"), oldImage="sha256:" + "a" * 64)
        for i, net in enumerate(p["networks"].values(), start=1):
            net["ipv4"] = "192.0.2." + str(i)
        p["migration"]["rollbackCompatible"] = True
        p["readiness"]["attempts"] = 2
        p["ci"].update(runId=15, runAttempt=1, artifactId=17)
        self.rt = Engine(p, artifact(p, self.root))

    def planned(self):
        report = plan(self.p, self.rt)
        self.assertEqual(report["status"], "PLANNED", report)
        return report["planSha256"]

    def execute(self):
        approved = self.planned()
        result = apply(self.p, approved, self.rt)
        saved = json.loads((self.root / approved / "receipt.json").read_text())
        self.assertEqual(result, saved)
        return result

    def test_executor_enforces_each_review_through_onboarding_readiness(self):
        import mandate
        import module_operation
        import store
        dispatch = runpy.run_path(str(ROOT / "scripts/ouf-a2-executor"))["dispatch"]
        command = self.p["gate"]["command"] + ["--fixture.option=private-marker"]
        self.p["gate"]["command"] = command
        self.p["candidate"] = {"removeArgs": command[-1:]}
        self.rt.docs[OLD]["Config"]["Cmd"] = command
        self.rt.docs[OLD]["Args"] = ENTRY[1:] + command
        cfg = dict(repositoryId=10, environmentId=20, branch="protected", environment="test",
                   reviewerIds=[30], commit="a"*40, runner="fixture", modules={"onboarding":self.p})
        req = dict(run="1", attempt="1", commit=cfg["commit"], operation="module-release",
                   module="onboarding", phase="plan")
        req["digest"] = mandate.intent(req)
        def call(approval_count, workflow=mandate.module_workflow("onboarding")):
            run = dict(id=1, run_attempt=1, event="workflow_dispatch", status="in_progress",
                       path=workflow, head_branch="protected", head_sha=cfg["commit"],
                       repository={"id":10}, head_repository={"id":10})
            user = {"type":"User", "id":30}
            env = dict(id=20, name="test", protection_rules=[dict(type="required_reviewers",
                       reviewers=[{"type":"User", "reviewer":user}])])
            approval = dict(state="approved", comment="",
                            user=user, environments=[env])
            jobs = {"jobs": [dict(status="in_progress", runner_name="fixture", name=req["phase"] + " " + req["digest"])]}
            return dispatch(req, cfg, self.root, Mock(side_effect=[run, jobs, dict(protected=True,
                            commit={"sha":cfg["commit"]}), env, [approval] * approval_count]))
        with patch.object(store, "sync_dir"), patch.object(store, "trusted", side_effect=lambda p, **_: Path(p)), \
             patch.object(module_operation.operation, "Docker", return_value=self.rt):
            with self.assertRaisesRegex(mandate.Held, "RUN_NOT_AUTHORIZED"):
                call(0, workflow=mandate.WORKFLOW)
            plan_result = call(0)
            self.assertEqual(plan_result["candidateReview"]["removedArgs"], ["--fixture.option=<redacted>"])
            self.assertFalse("private-marker" in json.dumps(plan_result))
            req.update(phase="apply", digest=plan_result["digest"])
            with self.assertRaisesRegex(mandate.Held, "EXACT_HUMAN_REVIEW_REQUIRED"):
                call(0)
            self.assertNotIn("load", self.rt.events)
            stage = call(1)
            self.assertEqual(stage["status"], "GATED")
            self.assertNotIn("signal:2", self.rt.events)
            req.update(phase="migrate", digest=stage["digest"])
            with self.assertRaisesRegex(mandate.Held, "EXACT_HUMAN_REVIEW_REQUIRED"):
                call(1)
            self.assertNotIn("signal:2", self.rt.events)
            self.assertEqual(call(2)["status"], "READY")
            with self.assertRaisesRegex(mandate.Held, "PHASE_ALREADY_AUTHORIZED"):
                call(2)
            self.assertEqual(self.rt.events.count("signal:2"), 1)

    def test_archive_tampered(self):
        next(self.root.glob("*.zip")).write_bytes(b"different")
        self.assertEqual(plan(self.p, self.rt)["reason"], "ARTIFACT_DIGEST_CHANGED")
        self.assertEqual(self.rt.events, [])

    def test_inner_digest(self):
        artifact(self.p, self.root, archiveSha256="f" * 64)
        self.assertEqual(plan(self.p, self.rt)["reason"], "IMAGE_ARCHIVE_DIGEST_CHANGED")

    def test_oci_image_id(self):
        self.p["ci"]["imageId"] = "sha256:" + "f" * 64
        self.assertEqual(plan(self.p, self.rt)["reason"], "IMAGE_ID_CHANGED")

    def test_wrong_tested_tree(self):
        artifact(self.p, self.root, testedTree="c" * 40)
        self.assertEqual(plan(self.p, self.rt)["reason"], "CI_PROVENANCE_CHANGED")

    def test_plan_read_only_and_drift(self):
        before = list(self.root.iterdir())
        approved = self.planned()
        self.assertEqual(list(self.root.iterdir()), before)
        self.rt.docs[OLD]["Config"]["Env"].append("DRIFT=1")
        self.assertEqual(apply(self.p, approved, self.rt)["reason"], "PLAN_CHANGED")
        self.assertNotIn("load", self.rt.events)

    def test_success_flyway_and_retention(self):
        self.assertEqual(self.execute()["status"], "READY")
        self.assertEqual([e for e in self.rt.events if e != "probe:1"],
                         ["load", "stop:1", "create", "gate:2", "signal:2", "spring-flyway", "probe:2"])
        self.assertEqual(self.rt.inspect(self.p["retainedName"])["Id"], OLD)
        self.assertFalse(self.rt.docs[OLD]["State"]["Running"])

    def test_no_migration_finishes_in_approved_apply(self):
        self.p["migration"]["mode"] = "none"
        result = apply(self.p, self.planned(), self.rt, defer_migration=True)
        self.assertEqual(result["status"], "READY")
        self.assertNotIn("migrationSha256", result)

    def test_reviewed_migration_rejects_new_gate_generation(self):
        approved = self.planned()
        staged = apply(self.p, approved, self.rt, defer_migration=True)
        self.rt.docs[NEW]["State"]["StartedAt"] = "unexpected-generation"
        with self.assertRaisesRegex(Held, "MIGRATION_GENERATION_CHANGED"):
            migrate(self.p, approved, staged["migrationSha256"], self.rt)
        self.assertNotIn("signal:2", self.rt.events)
        self.assertFalse((self.root / approved / "migration-review-consumed.json").exists())

    def test_dedicated_migration_before_signal(self):
        self.p["migration"].update(mode="dedicated", command=["app", "migrate"])
        self.assertEqual(self.execute()["readiness"], "UP")
        self.assertLess(self.rt.events.index("migrate"), self.rt.events.index("signal:2"))

    def test_original_onboarding_profile_still_requires_http_200_with_up(self):
        with patch.object(self.rt, "probe", return_value=(204, b"")):
            self.assertEqual(plan(self.p, self.rt)["reason"], "PREDECESSOR_NOT_READY")
        with patch.object(self.rt, "probe", return_value=(200, b'{"status":"DOWN"}')):
            self.assertEqual(plan(self.p, self.rt)["reason"], "PREDECESSOR_NOT_READY")
        self.assertEqual(self.execute()["status"], "READY")
        self.assertEqual(self.rt.docs[NEW]["Config"]["Cmd"], ["java", "-jar", "/app/application.jar"])

    def test_non_json_readiness(self):
        self.p["readiness"].pop("jsonStatus")
        self.p["readiness"]["acceptStatus"] = [204]
        self.assertEqual(self.execute()["status"], "READY")

    def test_extra_env_held(self):
        self.rt.fault = "config"
        r = self.execute()
        self.assertEqual((r["status"], r["reason"], r["rollback"]), ("HELD", "CONFIGURATION_DELTA", "ROLLED_BACK"))
        self.assertNotIn("signal:2", self.rt.events)

    def test_extra_alias_held(self):
        self.rt.fault = "network"
        self.assertEqual(self.execute()["reason"], "ENDPOINT_DELTA")
        self.assertNotIn("gate:2", self.rt.events)
        self.assertNotIn("signal:2", self.rt.events)

    def test_missing_handler_held(self):
        self.rt.fault = "handler"
        self.assertEqual(self.execute()["reason"], "GATE_NOT_PROVEN")
        self.assertNotIn("signal:2", self.rt.events)

    def test_readiness_rolls_back(self):
        self.rt.fault = "readiness"
        result = self.execute()
        self.assertEqual((result["reason"], result["rollback"], result["restoredCid"], result["predecessorReadiness"]),
                         ("READINESS_NOT_UP", "ROLLED_BACK", OLD, "UP"))
        self.assertEqual(self.rt.events.count("signal:2"), 1)
        self.assertEqual(self.rt.events.count("signal:1"), 1)
        self.assertEqual(self.rt.inspect(self.p["container"])["Id"], OLD)
        self.assertFalse(self.rt.docs[NEW]["State"]["Running"])
        self.assertFalse(self.rt.docs[NEW]["NetworkSettings"]["Networks"])

    def test_uncertain_signal_never_replayed(self):
        self.p["migration"]["mode"] = "none"
        self.rt.fault = "lost_signal"
        self.assertEqual(self.execute()["status"], "READY")
        self.assertEqual(self.rt.events.count("signal:2"), 1)

    def test_missing_flyway_receipt_requires_reviewed_checksums_and_same_generation(self):
        from tools.module_release import flyway, recovery
        rt = self.rt
        rt.flyway_peer = {"postgresCid": "3"*64}
        expected = [dict(version=str(n), script=f"V{n}__fixture.sql", type="SQL", checksum=n, success=True)
                    for n in (1, 2)]
        history = {"peer": "3"*64, "db": "42", "history": expected[:1]}
        with patch.object(flyway, "inventory", return_value=expected), patch.object(flyway, "observe", return_value=history):
            stamp = self.planned()
            stage = apply(self.p, stamp, rt, defer_migration=True)
            signal = rt.signal
            def interrupted(cid):
                signal(cid)
                history["history"].append(dict(expected[1], checksum=-1))
                raise KeyboardInterrupt
            with patch.object(rt, "signal", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
                migrate(self.p, stamp, stage["migrationSha256"], rt)
            with self.assertRaisesRegex(Held, "FLYWAY_OUTCOME_UNCONFIRMED"):
                recovery.resume(self.p, rt, recovery.proposal(self.p, rt))
            self.assertEqual(rt.events.count("signal:2"), 1)
            self.assertNotIn("signal:1", rt.events)
            history["history"][-1] = expected[1]
            final = recovery.resume(self.p, rt, recovery.proposal(self.p, rt))
            self.assertEqual((final["status"], final["readyHttp"]), ("READY", 200))
            self.assertEqual(rt.events.count("signal:2"), 1)

    def test_lost_create_response_preserves_both_containers_and_exclusion(self):
        self.rt.fault = "lost_create"
        result = self.execute()
        self.assertEqual((result["rollback"], result["rollbackReason"]), ("HELD", "UNKNOWN_SERVICE_OWNER"))
        self.assertTrue((self.root / (self.p["module"] + ".lock")).is_dir())
        self.assertFalse(any(doc["State"]["Running"] for doc in self.rt.docs.values()))
        self.assertEqual(self.rt.events.count("create"), 1)

    def test_http_up_from_a_different_generation_is_rejected(self):
        probe = self.rt.probe
        def changed(doc):
            if doc["Id"] == NEW:
                self.rt.docs[NEW]["State"]["StartedAt"] = "unexpected-restart"
            return probe(doc)
        self.rt.probe = changed
        result = self.execute()
        self.assertEqual((result["reason"], result["rollback"]), ("GENERATION_CHANGED", "ROLLED_BACK"))

    def test_partial_detach(self):
        self.rt.fault = "lost_disconnect"
        self.assertEqual(self.execute()["rollback"], "ROLLED_BACK")
        self.assertNotIn("create", self.rt.events)

    def test_irreversible_migration_blocks_before_apply(self):
        approved = self.planned()
        self.p["migration"]["rollbackCompatible"] = False
        self.assertEqual(plan(self.p, self.rt)["rollback"], "BLOCKED")
        self.assertEqual(apply(self.p, approved, self.rt)["rollback"], "BLOCKED")
        self.assertEqual(self.rt.events, ["probe:1"])

    def test_interrupted_or_consumed_attempt_held(self):
        approved = self.planned()
        lock = self.root / (self.p["module"] + ".lock")
        lock.mkdir()
        self.assertEqual(apply(self.p, approved, self.rt)["reason"], "OPERATION_IN_PROGRESS_OR_INTERRUPTED")
        lock.rmdir()
        (self.root / approved).mkdir()
        self.assertEqual(apply(self.p, approved, self.rt)["reason"], "PLAN_ALREADY_CONSUMED")
        self.assertNotIn("load", self.rt.events)

    def test_transport_binds_successful_run_artifact_and_head(self):
        ci = self.p["ci"]
        repo = {"full_name": ci["repository"]}
        run = dict(id=15, event="pull_request", status="completed", conclusion="success", run_attempt=1,
                   repository=repo, head_repository=repo, head_sha=ci["sourceCommit"], path=".github/workflows/module-ci.yml",
                   pull_requests=[{"number": ci["pullRequest"], "head": {"sha": ci["sourceCommit"]}}])
        obj = dict(id=17, expired=False, workflow_run={"id": 15, "head_sha": ci["sourceCommit"]},
                   name="source-onboarding-governed-image-15", digest="sha256:" + ci["zipSha256"])
        api = lambda path: run if path.endswith("/runs/15") else obj
        self.assertEqual(select(ci, 15, 17, api)["zipSha256"], ci["zipSha256"])
        obj["workflow_run"]["id"] = 14
        with self.assertRaisesRegex(Held, "CI_ARTIFACT_CHANGED"):
            select(ci, 15, 17, api)
