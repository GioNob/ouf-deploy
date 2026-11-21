"""Opt-in isolated Engine round trip. Requires a disposable, labelled local daemon."""
import ipaddress
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path[:0] = [str(ROOT / "tools" / n) for n in
                ("privileged_executor", "semantic_provider_r3", "semantic_application_cutover")]
from privileged_postgres_fixture import postgres_fixture
from pipeline import Cutover, until
from queue_inventory import Queue, permit, review_rows
from mandate import Held
from semantic import ENTRY, Engine, allocated_profile, prepare, profile_template, signal_once
from semantic_identity_v25 import semantic_configuration
from store import Journal


@unittest.skipUnless(sys.platform == "linux" and os.getenv("OUF_A2_NATIVE_ENGINE") == "1", "isolated Engine opt-in")
class NativeRoundTrip(unittest.TestCase):
    def test_engine_gate_and_return(self):
        self.round_trip()

    def test_distinct_successor_and_original_image_on_return(self):
        self.round_trip("ouf-ci-gate:a2-successor")

    def test_worker_enabled_next_image_and_interrupted_create(self):
        self.round_trip("ouf-ci-gate:a2-successor", worker_enabled=True)

    def round_trip(self, successor_tag=None, worker_enabled=False):
        self.assertEqual(os.geteuid(), 0)
        engine = Engine(os.environ["OUF_A2_FIXTURE_SOCKET"])
        self.assertIn("ouf.a2.fixture=true", engine.call("GET", "info")["Labels"])
        image = os.environ["OUF_A2_FIXTURE_IMAGE"]
        self.assertRegex(image, "^sha256:[a-f0-9]{64}$")
        image_cfg = engine.call("GET", f"images/{image}/json")
        self.assertEqual(image_cfg["Id"], image)
        # The local fixture image provides the ordinary Semantic Java command
        # and a long-lived test JAR that needs no credentials or external traffic.
        name = "a2-fixture-" + uuid.uuid4().hex
        net = engine.call("POST", "networks/create", {"Name":name, "Driver":"bridge", "Internal":True,
                      "IPAM":{"Config":[{"Subnet":"192.0.2.0/27"}]}})["Id"]
        self.addCleanup(engine.call, "DELETE", f"networks/{net}")
        network = engine.call("GET", f"networks/{net}")
        subnet = ipaddress.ip_network(network["IPAM"]["Config"][0]["Subnet"])
        ip = str(subnet.network_address + 3)
        request = dict(Image=image, User="10001:10001", Entrypoint=ENTRY,
                       Cmd=["java","-XX:MaxRAMPercentage=75","-jar","/app/application.jar"],
                       Env=["OUF_SCHEMA_GOV_ENABLED=true", "OUF_DISCOVERY_WORKER_ENABLED=" + str(worker_enabled).lower()],
                       HostConfig=dict(NetworkMode=name, CapDrop=["ALL"], SecurityOpt=["no-new-privileges:true"],
                                       RestartPolicy={"Name":"no","MaximumRetryCount":0}),
                       NetworkingConfig={"EndpointsConfig":{name:{"Aliases":[name],"IPAMConfig":{"IPv4Address":ip}}}})
        old = engine.create(name, request, image)
        self.addCleanup(engine.call, "DELETE", f"containers/{old}?force=1")
        engine.call("POST", f"containers/{old}/start")
        row = engine.inspect(old)
        original = dict(containerName=name, image=image, configurationSha256=semantic_configuration(row))
        until(lambda: engine.process(old, original, "GATE_WAITING"), 8, "BASELINE_GATE")
        candidate = candidate_config = None
        if successor_tag:
            inspected = engine.call("GET", f"images/{successor_tag}/json")
            candidate, candidate_config = inspected["Id"], inspected["Config"]
            self.assertNotEqual(candidate, image)
            self.assertNotIn("fixture.a2.successor", row["Config"]["Labels"] or {})
            self.assertNotIn("A2_IMAGE_DEFAULT=yes", row["Config"]["Env"])
        create, proposed = prepare(row, original, candidate, candidate_config, worker_enabled=worker_enabled)
        nets = {name:net}
        engine.detach(old, name+"-saved", nets)
        if candidate:
            # main copied the predecessor Config, then replaced only Image and the worker.
            legacy, _ = prepare(row, original, worker_enabled=worker_enabled)
            legacy["Image"] = candidate
            legacy_cid = engine.create(name, legacy, candidate)
            try:
                with self.assertRaisesRegex(Held, "STOPPED_GATE_FRAME_DRIFT"):
                    engine.start_gate(legacy_cid, name, legacy, candidate)
                self.assertEqual(engine.inspect(legacy_cid)["State"]["Status"], "created")
            finally:
                engine.remove_stopped(legacy_cid, name)
        cid = engine.create(name, create, proposed["image"])
        self.addCleanup(engine.call, "DELETE", f"containers/{cid}?force=1")
        target = allocated_profile(dict(old=old,template=profile_template(row),request=create,target=proposed),cid)
        if worker_enabled:
            # A fresh executor sees the same never-started CID and frozen create request.
            recovered = Engine(os.environ["OUF_A2_FIXTURE_SOCKET"])
            stopped = recovered.stopped_gate(cid, name, create, candidate)
            self.assertEqual(stopped["State"]["Status"], "created")
            self.assertIn("OUF_DISCOVERY_WORKER_ENABLED=true", stopped["Config"]["Env"])
            self.assertEqual(recovered.inspect(name+"-saved")["Id"], old)
        engine.start_gate(cid,name,create,proposed["image"])
        with tempfile.TemporaryDirectory() as d:
            def release(container, profile):
                gen = until(lambda: engine.process(container, profile, "GATE_WAITING"), 8, "GATE")
                signal_once(engine, Journal(Path(d)/container), container, profile, gen)
                java = until(lambda: engine.process(container, profile, "APPLICATION_RUNNING"), 12, "JAVA")
                self.assertEqual(gen,java)
            release(cid,target)
            if worker_enabled:
                # A second image change retains line C while the older CID is still parked.
                current = engine.inspect(cid)
                third = engine.call("GET", "images/ouf-ci-gate:" + "d"*40 + "/json")
                self.assertNotIn(third["Id"], (image, candidate))
                next_request, next_target = prepare(current, target, third["Id"], third["Config"], worker_enabled=True)
                engine.detach(cid, name+"-saved-v28", nets)
                next_cid = engine.create(name, next_request, third["Id"])
                self.addCleanup(engine.call, "DELETE", f"containers/{next_cid}?force=1")
                observed = allocated_profile(dict(old=cid, template=profile_template(current),
                                                 request=next_request, target=next_target), next_cid)
                engine.start_gate(next_cid, name, next_request, third["Id"])
                release(next_cid, observed)
                self.assertEqual(engine.inspect(name+"-saved-v28")["Id"], cid)
                self.assertEqual(engine.inspect(name+"-saved")["Id"], old)
                return
            engine.detach(cid, name+"-return", nets)
            engine.reconnect(old,name,create["NetworkingConfig"]["EndpointsConfig"],nets)
            launch = Cutover.return_request({"request": create, "template": profile_template(row)})
            engine.start_gate(old,name,launch,image)
            release(old,original)


    def test_readonly_postgres_inventory(self):
        self.assertEqual(os.geteuid(), 0)
        socket = os.environ["OUF_A2_FIXTURE_SOCKET"]
        self.assertIn("ouf.a2.fixture=true", Engine(socket).call("GET", "info")["Labels"])
        cli = ["/usr/bin/docker", "--host", "unix://" + socket]
        name = "queue-fixture-" + uuid.uuid4().hex
        with postgres_fixture(cli, name) as setup:
            subprocess.run(setup, input=b"""
                CREATE ROLE reader LOGIN;
                CREATE SCHEMA ouf_sem;
                CREATE TABLE ouf_sem.discovery_request (
                    created_by_subject text, request_id uuid, state text, recovery_state text,
                    attempt_count int, worker_generation bigint, lease_until timestamptz, next_attempt_at timestamptz,
                    budget_started_at timestamptz, budget_deadline timestamptz, private_payload text);
                GRANT USAGE ON SCHEMA ouf_sem TO reader;
                GRANT SELECT (created_by_subject, request_id, state, recovery_state, attempt_count,
                    worker_generation, lease_until, next_attempt_at, budget_started_at, budget_deadline)
                    ON ouf_sem.discovery_request TO reader;
                """, check=True)
            reader = Queue(dict(container=name, socket="/tmp", role="reader", database="postgres",
                                subjectTenants={"subject":"tenant"}), socket)
            self.assertEqual(reader.query("SELECT to_json(current_setting('transaction_read_only'))"), ["on"])
            self.assertEqual(reader.snapshot(), [])
            subprocess.run(setup, input=b"""
                INSERT INTO ouf_sem.discovery_request (created_by_subject, request_id, state, private_payload)
                VALUES ('subject', '00000000-0000-4000-8000-000000000001', 'PENDING', 'fixture payload');
                """, check=True)
            rows = reader.snapshot()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["state"], "PENDING")
            self.assertNotIn("fixture payload", str(rows))
            self.assertNotIn("subject", str(review_rows(rows)))
            with self.assertRaisesRegex(Held, "QUEUE_APPROVAL_DRIFT"):
                permit(rows, "empty", [])


if __name__ == "__main__":
    unittest.main()
