"""Exercise first install through the shared ZIP reader, Engine fixture and A2 mandate."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_module_release as fixture
from tools.module_release import contract, frame_spec, install_operation as install, operation
from tools.module_release.frame import baseline, merge_image


ZERO_TIME = "0001-01-01T00:00:00Z"


class Interruption(BaseException):
    """Simulated process loss outside ordinary failure compensation."""


def setup_profile(directory):
    p = json.loads(fixture.PROFILE.read_bytes())
    p.update(module="fixture", journal=directory, inbox=directory, dockerSocket=str(Path(directory) / "socket"),
             nsenter=str(Path(directory) / "nsenter"), migration={"mode": "none", "rollbackCompatible": True})
    del p["oldImage"]
    p["networks"] = {"example-net": {"ipv4": "192.0.2.2", "aliases": ["example-service"]}}
    p["readiness"]["attempts"] = 2
    p["ci"].update(runId=1, runAttempt=1, artifactId=2)
    p["install"] = {"user": "1101:1101", "groupAdd": ["1102"], "failedName": "fixture-isolated",
                    "readonlyRootfs": True, "bindRoots": ["/srv/fixture"],
                    "binds": [{"source": "/srv/fixture/data", "target": "/data", "mode": "rw"}],
                    "tmpfs": [{"target": "/tmp", "options": "nosuid,nodev,size=8m"}],
                    "env": [{"name": "DATA_DIR", "value": "/data"}]}
    return p


class Engine(fixture.Engine):
    def __init__(self, p, blob):
        super().__init__({**p, "oldImage": "unused"}, blob)
        self.docs.clear()
        self.p = p
        self.labels = {"org.opencontainers.image.revision": fixture.TESTED,
                       "org.opencontainers.image.source": "https://github.com/" + p["ci"]["repository"]}
        self.cut = None

    def api(self, method, endpoint, **kwargs):
        assert method == "GET"
        if endpoint == "/containers/json?all=1":
            return [{"Id": cid} for cid in self.docs]
        if endpoint == "/networks/example-net":
            return {"Name": "example-net", "Id": "1"*64, "Driver": "bridge", "Containers": {},
                    "IPAM": {"Config": [{"Subnet": "192.0.2.0/24", "Gateway": "192.0.2.1"}]}}
        raise AssertionError(endpoint)

    def image_defaults(self, image_id):
        return {"Labels": self.labels}

    def load(self, archive, package):
        super().load(archive, package)
        if self.cut == "load":
            raise Interruption

    def create(self, name, request):
        if fixture.OLD in self.docs:
            return super().create(name, request)
        self.events.append("create")
        if self.cut == "uncertain":
            raise OSError()
        cid = fixture.OLD
        cfg = copy.deepcopy(request)
        host = cfg.pop("HostConfig")
        host.update(AutoRemove=False, OomKillDisable=None)
        nets = cfg.pop("NetworkingConfig")["EndpointsConfig"]
        merge_image(cfg, self.image_defaults(cfg["Image"]))
        self.docs[cid] = {"Id": cid, "Config": cfg, "Image": cfg["Image"], "HostConfig": host, "Name": "/" + name,
                          "Path": cfg["Entrypoint"][0], "Args": cfg["Entrypoint"][1:] + cfg["Cmd"],
                          "NetworkSettings": {"Networks": {}, "Ports": {}}, "RestartCount": 0,
                          "State": {"Status": "created", "Running": False, "Pid": 0,
                                    "StartedAt": ZERO_TIME, "FinishedAt": ZERO_TIME},
                          "Mounts": [{"Type": m["Type"], "Source": m["Source"], "Destination": m["Target"],
                                      "RW": not m["ReadOnly"]} for m in host["Mounts"]]}
        for network, settings in nets.items():
            self.connect(cid, self.nets[network]["NetworkID"], settings)
        if self.cut == "lost-create":
            raise OSError()
        return cid

    def start(self, cid):
        if self.cut == "before-start":
            raise Interruption
        super().start(cid)
        if self.cut == "at-gate":
            raise Interruption

    def signal(self, cid):
        super().signal(cid)
        if self.cut == "after-signal":
            raise Interruption

    def probe(self, doc):
        if self.fault == "install-readiness":
            return 503, b""
        return super().probe(doc)


class InstallTest(unittest.TestCase):
    def setUp(self):
        self.directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.directory)
        self.p = setup_profile(self.directory)
        self.rt = Engine(self.p, fixture.artifact(self.p, self.root))
        self.enterContext(patch.object(frame_spec, "bind_facts", return_value=({}, {"ino": 42})))

    def plan(self):
        row = install.plan(self.p, self.rt)
        self.assertEqual(row["status"], "PLANNED", row)
        return row["planSha256"]

    def apply(self, stamp):
        return install.apply(self.p, stamp, self.rt)

    def test_plan_before_create_is_read_only_and_restartable(self):
        before = list(self.root.iterdir())
        stamp = self.plan()
        self.assertEqual(before, list(self.root.iterdir()))
        self.rt.cut = "load"
        with self.assertRaises(Interruption):
            self.apply(stamp)
        self.assertEqual(before, list(self.root.iterdir()))
        self.assertEqual(install.rollback(self.p, stamp, self.rt)["reason"], "NO_INSTALL_TO_RETURN")
        self.assertEqual(self.rt.events, ["load"])
        self.assertEqual(self.plan(), stamp)
        self.rt.cut = None
        self.assertEqual(self.apply(stamp)["status"], "READY")

    def test_intent_without_identifiable_cid_is_read_only(self):
        stamp = self.plan()
        self.rt.cut = "uncertain"
        self.assertEqual(self.apply(stamp)["reason"], "CREATE_UNCERTAIN")
        self.assertEqual(install.plan(self.p, self.rt)["reason"], "INSTALL_CREATION_PENDING")
        events = list(self.rt.events)
        self.assertEqual(self.apply(stamp)["reason"], "CREATE_UNCERTAIN")
        self.assertEqual(install.rollback(self.p, stamp, self.rt)["reason"], "CREATE_UNCERTAIN")
        self.assertEqual(self.rt.events, events)

    def test_matching_label_adopts_once(self):
        stamp = self.plan()
        self.rt.cut = "lost-create"
        self.assertEqual(self.apply(stamp)["reason"], "CREATE_UNCERTAIN")
        cfg = self.rt.docs[fixture.OLD]["Config"]
        cfg["Labels"][install.LABEL] = "unrelated"
        self.assertEqual(self.apply(stamp)["reason"], "CREATE_UNCERTAIN")
        cfg["Labels"][install.LABEL] = stamp
        self.assertEqual(install.plan(self.p, self.rt, resume=stamp)["planSha256"], stamp)
        self.assertEqual(self.apply(stamp)["status"], "READY")
        self.assertEqual(self.rt.events.count("create"), 1)

    def interrupt(self, point):
        stamp = self.plan()
        self.rt.cut = point
        with self.assertRaises(Interruption):
            self.apply(stamp)
        self.rt.cut = None
        return stamp

    def test_never_started_resumes(self):
        stamp = self.interrupt("before-start")
        self.assertTrue(operation.never_started(self.rt.inspect(fixture.OLD)))
        self.assertEqual(self.apply(stamp)["status"], "READY")
        self.assertEqual(self.rt.events.count("create"), 1)

    def test_gate_resumes_once(self):
        stamp = self.interrupt("at-gate")
        self.assertEqual(self.apply(stamp)["status"], "READY")
        self.assertEqual(self.rt.events.count("gate:1"), 1)
        self.assertEqual(self.rt.events.count("signal:1"), 1)

    def assert_parked(self, stamp):
        self.assertEqual(install.rollback(self.p, stamp, self.rt)["status"], "ROLLED_BACK")
        doc = self.rt.inspect(self.p["install"]["failedName"])
        self.assertFalse(doc["State"]["Running"])
        self.assertEqual(doc["NetworkSettings"]["Networks"], {})
        self.assertEqual(doc["Mounts"][0]["Source"], "/srv/fixture/data")

    def test_never_started_returns(self):
        self.assert_parked(self.interrupt("before-start"))
        self.assertNotIn("signal:1", self.rt.events)

    def test_gated_returns(self):
        self.assert_parked(self.interrupt("at-gate"))
        self.assertNotIn("signal:1", self.rt.events)

    def test_failed_readiness_after_signal_parks(self):
        stamp = self.interrupt("after-signal")
        self.rt.fault = "install-readiness"
        self.assertEqual(self.apply(stamp)["reason"], "READINESS_NOT_UP")
        self.assert_parked(stamp)
        self.assertEqual(self.rt.events.count("signal:1"), 1)

    def test_exit_after_usr1_allows_only_same_run_to_be_parked(self):
        stamp = self.plan()
        signal = self.rt.signal
        def signal_and_exit(cid):
            signal(cid)
            doc = self.rt.docs[cid]
            doc["State"].update(Status="exited", Running=False, Pid=0)
            endpoint = doc["NetworkSettings"]["Networks"]["example-net"]
            endpoint.update(IPAddress="", EndpointID="", NetworkID="")

        with patch.object(self.rt, "signal", side_effect=signal_and_exit):
            self.assertEqual(self.apply(stamp)["status"], "HELD")
        doc = self.rt.docs[fixture.OLD]
        claim = self.root / stamp / "signal.json"
        signal_bytes = claim.read_bytes()
        mounts = copy.deepcopy(doc["Mounts"])
        with patch.object(self.rt, "stop", wraps=self.rt.stop) as stop, \
             patch.object(self.rt, "disconnect", wraps=self.rt.disconnect) as disconnect, \
             patch.object(self.rt, "rename", wraps=self.rt.rename) as rename:
            for field, delta in ((doc, {"RestartCount": 1}), (doc["State"], {"StartedAt": "another-run"}),
                                 (doc["HostConfig"], {"Runtime": "runc"})):
                with self.subTest(delta=delta), patch.dict(field, delta):
                    self.assertEqual(install.rollback(self.p, stamp, self.rt)["status"], "HELD")
                    self.assertFalse((self.root / stamp / "park-intent.json").exists())
                    stop.assert_not_called()
                    disconnect.assert_not_called()
                    rename.assert_not_called()
            self.assert_parked(stamp)
            stop.assert_not_called()
            disconnect.assert_called_once_with(fixture.OLD, self.rt.nets["example-net"]["NetworkID"])
            rename.assert_called_once_with(fixture.OLD, self.p["install"]["failedName"])
        self.assertEqual(doc["Mounts"], mounts)
        self.assertEqual(claim.read_bytes(), signal_bytes)
        self.assertEqual(self.rt.events.count("signal:1"), 1)

    def test_mount_permutation_after_usr1_exit_is_the_same_generation(self):
        # Review 61e-c (Astra), blocker 1: Docker can list the same mounts in another order.
        self.p["install"]["binds"].append({"source": "/srv/fixture/settings", "target": "/settings", "mode": "ro"})
        self.rt = Engine(self.p, fixture.artifact(self.p, self.root))
        stamp = self.plan()
        signal = self.rt.signal
        def signal_and_exit(cid):
            signal(cid)
            doc = self.rt.docs[cid]
            doc["State"].update(Status="exited", Running=False, Pid=0)
            endpoint = doc["NetworkSettings"]["Networks"]["example-net"]
            endpoint.update(IPAddress="", EndpointID="", NetworkID="")

        with patch.object(self.rt, "signal", side_effect=signal_and_exit):
            self.assertEqual(self.apply(stamp)["status"], "HELD")
        doc = self.rt.docs[fixture.OLD]
        self.assertEqual([m["Destination"] for m in doc["Mounts"]], ["/data", "/settings"])
        for changed in ({"Source": "/srv/fixture/other"}, {"Destination": "/other"}, {"RW": True}):
            with self.subTest(changed=changed), patch.dict(doc["Mounts"][1], changed):
                doc["Mounts"].reverse()
                try:
                    self.assertEqual(install.rollback(self.p, stamp, self.rt)["status"], "HELD")
                    self.assertFalse((self.root / stamp / "park-intent.json").exists())
                finally:
                    doc["Mounts"].reverse()
        doc["Mounts"].reverse()
        self.assertEqual(install.rollback(self.p, stamp, self.rt)["status"], "ROLLED_BACK")
        parked = self.rt.inspect(self.p["install"]["failedName"])
        self.assertFalse(parked["State"]["Running"])
        self.assertEqual(sorted(m["Destination"] for m in parked["Mounts"]), ["/data", "/settings"])
        self.assertEqual(self.rt.events.count("signal:1"), 1)

    def test_signal_claim_without_delivery_does_not_signal_again(self):
        stamp = self.plan()
        with patch.object(self.rt, "signal", side_effect=Interruption), self.assertRaises(Interruption):
            self.apply(stamp)
        self.assertTrue((self.root / stamp / "signal.json").is_file())
        self.assertEqual(self.apply(stamp)["reason"], "READINESS_NOT_UP")
        self.assertNotIn("signal:1", self.rt.events)
        self.assert_parked(stamp)

    def assert_untouched(self, stamp, doc, events):
        self.assertEqual(self.rt.inspect(fixture.OLD), doc)
        self.assertEqual(self.rt.events, events)
        self.assertFalse((self.root / stamp / "park-intent.json").exists())

    def test_resumed_apply_rejects_changed_generation_without_effects(self):
        stamp = self.interrupt("after-signal")
        state = self.rt.docs[fixture.OLD]["State"]
        state.update(Pid=state["Pid"] + 1, StartedAt="different-generation")
        before, events = self.rt.inspect(fixture.OLD), list(self.rt.events)
        self.assertEqual(self.apply(stamp)["status"], "HELD")
        self.assert_untouched(stamp, before, events)
        self.assertEqual(install.rollback(self.p, stamp, self.rt)["status"], "HELD")
        self.assert_untouched(stamp, before, events)

    def test_generation_changes_on_last_probe_before_park(self):
        stamp = self.interrupt("after-signal")
        observed = []
        def failed_probe(doc):
            observed.append(doc["State"]["Pid"])
            if len(observed) == self.p["readiness"]["attempts"]:
                self.rt.docs[fixture.OLD]["State"]["Pid"] += 1
            return 503, b""
        events = list(self.rt.events)
        with patch.object(self.rt, "probe", side_effect=failed_probe):
            result = self.apply(stamp)
        self.assertEqual(result.get("reason"), "GENERATION_CHANGED", result)
        self.assertEqual(len(observed), self.p["readiness"]["attempts"])
        self.assertTrue(self.rt.inspect(fixture.OLD)["State"]["Running"])
        self.assertEqual(self.rt.events, events)
        self.assertFalse((self.root / stamp / "park-intent.json").exists())

    def assert_race_at_park_holds(self, stamp, phase):
        original_park = install.park
        def race(runtime, cid, name, networks):
            self.assertTrue((self.root / stamp / "park-intent.json").is_file())
            # The change first becomes visible to the inspect used by park itself.
            state = self.rt.docs[cid]["State"]
            state.update(Pid=state["Pid"] + 1, StartedAt="later-run")
            return original_park(runtime, cid, name, networks)

        with patch.object(install, "park", side_effect=race) as park, \
             patch.object(self.rt, "stop", wraps=self.rt.stop) as stop, \
             patch.object(self.rt, "disconnect", wraps=self.rt.disconnect) as disconnect, \
             patch.object(self.rt, "rename", wraps=self.rt.rename) as rename:
            result = phase(self.p, stamp, self.rt)
            self.assertEqual(result, {"status": "HELD", "reason": "PARK_GENERATION_CHANGED"})
            self.assertFalse((self.root / stamp / "parked.json").exists())
            park.assert_called_once()
            stop.assert_not_called()
            disconnect.assert_not_called()
            rename.assert_not_called()

    def test_generation_changes_at_first_inspect_inside_park(self):
        stamp = self.interrupt("after-signal")
        self.rt.fault = "install-readiness"
        self.assert_race_at_park_holds(stamp, install.apply)

    def test_generation_changes_at_first_inspect_inside_resumed_park(self):
        stamp = self.plan()
        self.assertEqual(self.apply(stamp)["status"], "READY")
        with patch.object(install, "park", side_effect=Interruption), self.assertRaises(Interruption):
            install.rollback(self.p, stamp, self.rt)
        self.assert_race_at_park_holds(stamp, install.rollback)

    def test_create_memory_drift_holds_before_adoption_or_start(self):
        stamp = self.plan()
        create = self.rt.create
        def changed(name, request):
            cid = create(name, request)
            self.rt.docs[cid]["HostConfig"]["Memory"] = 64 << 20
            return cid
        with patch.object(self.rt, "create", side_effect=changed):
            result = self.apply(stamp)
        self.assertEqual(result.get("reason"), "INSTALL_HOST_CONFIG_CHANGED", result)
        before = self.rt.inspect(fixture.OLD)
        self.assert_untouched(stamp, before, ["load", "create"])
        self.assertFalse((self.root / stamp / "created.json").exists())
        # Only the intent and matching label survive. Adoption must attest the same request.
        self.assertEqual(self.apply(stamp).get("reason"), "INSTALL_HOST_CONFIG_CHANGED")
        self.assertFalse((self.root / stamp / "created.json").exists())
        self.assert_untouched(stamp, before, ["load", "create"])

    def test_readiness_tls_uses_common_profile_and_authorized_address(self):
        ready = self.p["readiness"]
        ready["tls"] = {"address": "192.0.2.2", "serverName": "service.example",
                        "caFile": str(self.root / "fixture-ca")}
        base = contract.validate
        def common_58k(profile):
            base(profile)
            tls = profile["readiness"]["tls"]
            contract.require(tls["address"] in [n["ipv4"] for n in profile["networks"].values()],
                             "INVALID_READINESS_TLS")
        with patch.object(contract, "validate", side_effect=common_58k) as common:
            self.plan()
            common.assert_called_once()
            ready["tls"]["address"] = "192.0.2.99"
            self.assertEqual(install.plan(self.p, self.rt).get("reason"), "INVALID_READINESS_TLS")

    def test_unrecognized_readiness_option_is_held(self):
        self.p["readiness"]["unsupported"] = {}
        self.assertEqual(install.plan(self.p, self.rt).get("reason"), "INVALID_READINESS")

    def test_inspect_defaults_mounts_networks_and_mac(self):
        stamp = self.plan()
        self.rt.cut = "lost-create"
        self.assertEqual(self.apply(stamp)["reason"], "CREATE_UNCERTAIN")
        doc = self.rt.docs[fixture.OLD]
        host = doc["HostConfig"]
        host.update(Memory=0, Privileged=False, ShmSize=64 << 20, Runtime="runc", IpcMode="private")
        host["RestartPolicy"]["MaximumRetryCount"] = 0
        doc["Config"].update(Hostname=fixture.OLD[:12], MacAddress="allocated")
        mount = doc["Mounts"][0]
        mount.update(Mode="rw", Propagation="rprivate")
        ep = doc["NetworkSettings"]["Networks"]["example-net"]
        ep["MacAddress"] = "allocated-at-inspect"
        for field, change in ((host, {"Unknown": 0}), (host, {"Privileged": True}), (host, {"MaskedPaths": []}),
                              (doc["Config"], {"Hostname": "different"}), (mount, {"Propagation": "shared"}),
                              (ep, {"DriverOpts": {"override": "value"}})):
            with self.subTest(change=change), patch.dict(field, change):
                self.assertEqual(install.plan(self.p, self.rt, resume=stamp)["status"], "HELD")
                self.assertEqual(self.apply(stamp)["status"], "HELD")
                self.assertFalse((self.root / stamp / "created.json").exists())
                self.assertEqual(self.rt.events, ["load", "create"])
        self.assertEqual(self.apply(stamp)["status"], "READY")

    def test_created_frame_drift_holds_before_start(self):
        stamp = self.interrupt("before-start")
        self.rt.docs[fixture.OLD]["HostConfig"]["PortBindings"] = {"80/tcp": [{"HostIp": "192.0.2.3"}]}
        before, events = self.rt.inspect(fixture.OLD), list(self.rt.events)
        self.assertEqual(self.apply(stamp)["reason"], "INSTALL_HOST_CONFIG_CHANGED")
        self.assert_untouched(stamp, before, events)
        self.assertEqual(install.rollback(self.p, stamp, self.rt)["status"], "HELD")
        self.assert_untouched(stamp, before, events)

    def test_ready_rollback_rejects_another_generation_and_resumes_partial_park(self):
        stamp = self.plan()
        self.assertEqual(self.apply(stamp)["status"], "READY")
        doc = self.rt.docs[fixture.OLD]
        doc["State"]["Pid"] += 1
        self.assertEqual(install.rollback(self.p, stamp, self.rt)["reason"], "GENERATION_CHANGED")
        doc["State"]["Pid"] -= 1
        self.rt.fault = "lost_disconnect"
        self.assertEqual(install.rollback(self.p, stamp, self.rt)["status"], "HELD")
        self.assert_parked(stamp)

    def test_published_receipt_before_pointer_allows_read_only_reconciliation(self):
        stamp = self.plan()
        receipt = self.apply(stamp)
        events = list(self.rt.events)
        self.assertEqual(install.plan(self.p, self.rt, resume=stamp)["planSha256"], stamp)
        self.assertEqual(self.apply(stamp), receipt)
        self.assertEqual(self.rt.events, events)

    def test_ready_replay_rollback_and_occupied_names(self):
        stamp = self.plan()
        result = self.apply(stamp)
        self.assertEqual(result["status"], "READY", result)
        events = list(self.rt.events)
        self.assertEqual(self.apply(stamp), result)
        self.assertEqual(self.rt.events, events)
        self.assertEqual(install.plan(self.p, self.rt)["reason"], "SERVICE_EXISTS")
        self.assert_parked(stamp)
        self.assertEqual(install.plan(self.p, self.rt)["reason"], "CUSTODY_NAME_OCCUPIED")

    def test_install_then_release_inherits_frame(self):
        result = self.apply(self.plan())
        self.assertEqual(result["status"], "READY", result)
        p = self.p
        p["oldImage"] = result["imageId"]
        self.rt.blob = fixture.artifact(p, self.root, image_env=["REVISION=second"])
        before = self.rt.inspect(result["cid"])
        baseline(p, before)
        self.assertEqual([m["Destination"] for m in before["Mounts"]], ["/data"])
        self.assertIn("/tmp", before["HostConfig"]["Tmpfs"])
        proposal = operation.plan(p, self.rt)
        self.assertEqual(proposal["status"], "PLANNED", proposal)
        released = operation.apply(p, proposal["planSha256"], self.rt)
        self.assertEqual(released["status"], "READY", released)
        after = self.rt.inspect(released["successorCid"])
        self.assertEqual(after["Mounts"], before["Mounts"])
        self.assertEqual(after["HostConfig"]["Tmpfs"], before["HostConfig"]["Tmpfs"])

    def test_changed_inputs_hold_before_effect(self):
        stamp = self.plan()
        self.p["install"]["readonlyRootfs"] = False
        self.assertEqual(self.apply(stamp)["reason"], "PLAN_CHANGED")
        self.p["install"]["readonlyRootfs"] = True
        archive = self.root / (self.p["ci"]["zipSha256"] + ".zip")
        archive.write_bytes(archive.read_bytes() + b"changed")
        self.assertEqual(self.apply(stamp)["reason"], "ARTIFACT_DIGEST_CHANGED")
        fixture.artifact(self.p, self.root, testedTree="wrong")
        self.assertEqual(install.plan(self.p, self.rt)["reason"], "CI_PROVENANCE_CHANGED")
        self.assertEqual(self.rt.events, [])

    def test_mandate_entrypoint_replay_review_and_pointer(self):
        import mandate
        from module_release import frame_spec as installed_spec
        self.enterContext(patch.object(installed_spec, "bind_facts", return_value=({}, {"ino": 42})))
        self.p["module"] = "onboarding"
        call, req = fixture.ReleaseTest.governed_dispatch(self)
        req.update(operation="module-install", schema="ouf.module-install.v1")
        req["digest"] = mandate.intent(req)
        workflow = ".github/workflows/module-install.yml"
        with self.assertRaisesRegex(mandate.Held, "RUN_NOT_AUTHORIZED"):
            call(0)
        proposal = call(0, workflow)
        self.assertEqual(proposal["installReview"]["env"], ["DATA_DIR"])
        req.update(phase="apply", digest=proposal["digest"])
        with self.assertRaisesRegex(mandate.Held, "EXACT_HUMAN_REVIEW_REQUIRED"):
            call(0, workflow)
        ready = call(1, workflow)
        self.assertEqual(ready["status"], "READY")
        self.assertEqual(call(1, workflow), ready)
        pointer = json.loads((self.root / "module-onboarding.installed").read_bytes())
        self.assertEqual(pointer, {"run": "1", "phase": "apply", "planSha256": proposal["digest"]})
        req.update(run="2", phase="rollback")
        with self.assertRaisesRegex(mandate.Held, "EXACT_HUMAN_REVIEW_REQUIRED"):
            call(0, workflow)
        self.assertEqual(call(1, workflow)["status"], "ROLLED_BACK")
        self.assertEqual(self.rt.events.count("create"), 1)
