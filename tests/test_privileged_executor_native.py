"""Opt-in isolated Engine round trip. Requires a disposable, labelled local daemon."""
import ipaddress
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools" / n) for n in
                ("privileged_executor", "semantic_provider_r3", "semantic_application_cutover")]
from pipeline import until
from semantic import ENTRY, Engine, allocated_profile, prepare, profile_template, signal_once
from semantic_identity_v25 import semantic_configuration
from store import Journal


@unittest.skipUnless(sys.platform == "linux" and os.getenv("OUF_A2_NATIVE_ENGINE") == "1", "isolated Engine opt-in")
class NativeRoundTrip(unittest.TestCase):
    def test_engine_gate_and_return(self):
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
        net = engine.call("POST", "networks/create", {"Name":name, "Driver":"bridge", "Internal":True})["Id"]
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
        create, proposed = prepare(row, original)
        nets = {name:net}
        engine.detach(old, name+"-saved", nets)
        cid = engine.create(name, create, image)
        self.addCleanup(engine.call, "DELETE", f"containers/{cid}?force=1")
        target = allocated_profile(dict(old=old,template=profile_template(row),request=create,target=proposed),cid)
        engine.start_gate(cid,name,create,image)
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
            engine.start_gate(old,name,create,image)
            release(old,original)


if __name__ == "__main__":
    unittest.main()
