"""Opt-in isolated Engine round trip. Requires a disposable, labelled local daemon."""
import ipaddress
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path[:0] = [str(ROOT / "tools" / n) for n in
                ("privileged_executor", "semantic_provider_r3", "semantic_application_cutover")]
from pipeline import until
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
        self.round_trip("ouf-ci-gate:" + "d"*40)

    def round_trip(self, successor_tag=None):
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
                       Env=["OUF_SCHEMA_GOV_ENABLED=true","OUF_DISCOVERY_WORKER_ENABLED=false"],
                       HostConfig=dict(NetworkMode=name, CapDrop=["ALL"], SecurityOpt=["no-new-privileges:true"],
                                       RestartPolicy={"Name":"no","MaximumRetryCount":0}),
                       NetworkingConfig={"EndpointsConfig":{name:{"Aliases":[name],"IPAMConfig":{"IPv4Address":ip}}}})
        old = engine.create(name, request, image)
        self.addCleanup(engine.call, "DELETE", f"containers/{old}?force=1")
        engine.call("POST", f"containers/{old}/start")
        row = engine.inspect(old)
        original = dict(containerName=name, image=image, configurationSha256=semantic_configuration(row))
        until(lambda: engine.process(old, original, "GATE_WAITING"), 8, "BASELINE_GATE")
        candidate = None
        if successor_tag:
            candidate = engine.call("GET", f"images/{successor_tag}/json")["Id"]
            self.assertNotEqual(candidate, image)
        create, proposed = prepare(row, original, candidate)
        nets = {name:net}
        engine.detach(old, name+"-saved", nets)
        cid = engine.create(name, create, proposed["image"])
        self.addCleanup(engine.call, "DELETE", f"containers/{cid}?force=1")
        target = allocated_profile(dict(old=old,template=profile_template(row),request=create,target=proposed),cid)
        engine.start_gate(cid,name,create,proposed["image"])
        with tempfile.TemporaryDirectory() as d:
            def release(container, profile):
                gen = until(lambda: engine.process(container, profile, "GATE_WAITING"), 8, "GATE")
                signal_once(engine, Journal(Path(d)/container), container, profile, gen)
                java = until(lambda: engine.process(container, profile, "APPLICATION_RUNNING"), 12, "JAVA")
                self.assertEqual(gen,java)
            release(cid,target)
            engine.detach(cid, name+"-return", nets)
            engine.reconnect(old,name,create["NetworkingConfig"]["EndpointsConfig"],nets)
            create["Env"] = row["Config"]["Env"]
            create["Image"] = row["Config"]["Image"]
            engine.start_gate(old,name,create,image)
            release(old,original)


    def test_readonly_postgres_inventory(self):
        self.assertEqual(os.geteuid(), 0)
        socket = os.environ["OUF_A2_FIXTURE_SOCKET"]
        self.assertIn("ouf.a2.fixture=true", Engine(socket).call("GET", "info")["Labels"])
        cli = ["/usr/bin/docker", "--host", "unix://" + socket]
        name = "queue-fixture-" + uuid.uuid4().hex
        postgres_bin = Path(subprocess.check_output(["pg_config", "--bindir"], text=True).strip())
        self.assertTrue((postgres_bin / "initdb").is_file())
        with tempfile.TemporaryDirectory() as directory:
            passwd = Path(directory) / "passwd"
            passwd.write_text("fixture:x:10001:10001:fixture:/tmp:/bin/sh\n")
            passwd.chmod(0o644)
            # Use only the hosted VM's installed PostgreSQL distribution, on a private Unix socket.
            subprocess.run([*cli, "run", "-d", "--network", "none", "--name", name, "--user", "10001:10001",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "-e", "HOME=/tmp",
                "-e", f"PATH={postgres_bin}:/usr/bin:/bin", "-v", "/usr:/usr:ro", "-v", "/usr/lib:/lib:ro",
                "-v", f"{passwd}:/etc/passwd:ro", os.environ["OUF_A2_FIXTURE_IMAGE"], "/bin/sh", "-ec",
                "initdb -D /tmp/data --no-locale -E UTF8 --auth-local=trust --auth-host=reject && "
                "exec postgres -D /tmp/data -k /tmp -c listen_addresses=''"],
                check=True, stdout=subprocess.DEVNULL)
            self.addCleanup(subprocess.run, [*cli, "rm", "-f", name], check=False)
            setup = [*cli, "exec", "-i", name, "psql", "-X", "-w", "-q", "-v", "ON_ERROR_STOP=1",
                     "-h", "/tmp", "-U", "fixture", "-d", "postgres"]
            for _ in range(60):
                if subprocess.run(setup, input=b"SELECT 1;", stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL).returncode == 0:
                    break
                time.sleep(.5)
            else:
                self.fail("Local PostgreSQL socket did not become ready")
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
