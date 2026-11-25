"""Daemon-specific VOLUME/tmpfs semantics on the existing disposable Engine fixture."""
import ipaddress
import os
import subprocess
import sys
import tempfile
import unittest
import uuid

from test_module_install import setup_profile
from tools.module_release.docker import Docker
from tools.module_release.frame import baseline
from tools.module_release.frame_spec import build_create
from tools.module_release.install_operation import network_inventory, verify_frame


@unittest.skipUnless(sys.platform == "linux" and os.getenv("OUF_MODULE_RELEASE_NATIVE") == "1",
                     "requires the labelled native Engine fixture")
class NativeVolume(unittest.TestCase):
    def test_image_volume_covered_by_tmpfs_passes_live_baseline(self):
        name = "install-fixture-" + uuid.uuid4().hex
        p = setup_profile("/fixture")
        p.update(container=name, dockerSocket=os.environ["OUF_A2_FIXTURE_SOCKET"])
        store = self.enterContext(tempfile.TemporaryDirectory(dir="/var/lib"))
        os.chown(store, 1101, 1101)
        p["install"].update(binds=[{"source": store, "target": "/data", "mode": "rw"}],
                            bindRoots=[store], env=[], groupAdd=[])
        p["gate"] = {"command": ["/bin/sleep", "60"]}
        rt = Docker(p)
        self.assertIn("ouf.a2.fixture=true", rt.api("GET", "/info")["Labels"])
        cli = ["/usr/bin/docker", "--host", "unix://" + p["dockerSocket"]]
        subprocess.run([*cli, "build", "--pull=false", "--network=none", "-t", name, "-"], check=True,
                       input=b'FROM ouf-ci-busybox:old\nVOLUME ["/tmp"]\n')
        self.addCleanup(subprocess.run, [*cli, "image", "rm", name], check=False)
        network = name + "-net"
        subprocess.run([*cli, "network", "create", "--internal", "--subnet", "192.0.2.0/28", network], check=True)
        self.addCleanup(subprocess.run, [*cli, "network", "rm", network], check=False)
        net = rt.api("GET", "/networks/" + network)
        subnet = ipaddress.ip_network(net["IPAM"]["Config"][0]["Subnet"])
        p["networks"] = {network: {"ipv4": str(subnet[2]), "aliases": [name]}}
        image = rt.api("GET", "/images/" + name + "/json")
        self.assertIn("/tmp", image["Config"]["Volumes"])
        facts = {"imageId": image["Id"], "Config": image["Config"], "networks": network_inventory(p, rt)}
        request = build_create(p, facts, "c"*64)
        cid = rt.create(name, request)
        self.addCleanup(subprocess.run, [*cli, "rm", "-f", cid], check=False)
        verify_frame(p, rt.inspect(cid), request, image["Config"], facts["networks"], cid)
        rt.start(cid)
        doc = rt.inspect(cid)
        verify_frame(p, doc, request, image["Config"], facts["networks"], cid)
        self.assertIn("/tmp", doc["HostConfig"]["Tmpfs"])
        self.assertEqual([(m["Type"], m["Destination"]) for m in doc["Mounts"]], [("bind", "/data")])
        baseline(p, doc, predecessor_image=image["Id"])
