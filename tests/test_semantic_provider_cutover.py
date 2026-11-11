"""Run D restoration against disposable Docker containers on the hosted runner."""
from pathlib import Path
import re
import runpy
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
D = runpy.run_path(str(SCRIPTS / "cutover-semantic-provider-20261111.py"))
NAMESPACE = D["restore"].__globals__


def cli(*args):
    return subprocess.check_output(("docker", *args), timeout=30, text=True).strip()


class CutoverTests(unittest.TestCase):
    def test_merge_loadable_by_java_with_default_and_provider_anchors(self):
        _, _, trust = D["load_helpers"]()
        stock = subprocess.check_output(("keytool", "-J-XX:-UsePerfData", "-list", "-rfc", "-cacerts",
                                        "-storepass", "changeit"), stderr=subprocess.DEVNULL, timeout=20)
        certificates = {D["ssl"].PEM_cert_to_DER_cert(value.decode()) for value in trust.PEM.findall(stock)}
        self.assertGreater(len(certificates), 50)
        with tempfile.TemporaryDirectory() as temp:
            cert = Path(temp) / "fixture.crt"
            subprocess.run(("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=ouf-public-fixture", "-keyout", str(Path(temp) / "fixture.key"),
                            "-out", str(cert)), check=True, capture_output=True, timeout=10)
            added = D["ssl"].PEM_cert_to_DER_cert(cert.read_text())
            self.assertNotIn(added, certificates)
            path = Path(temp) / "merged.p12"
            path.write_bytes(trust._pkcs12(sorted(certificates | {added}, key=D["sha"])))
            result = subprocess.check_output(("keytool", "-list", "-keystore", str(path), "-storetype",
                                              "PKCS12", "-storepass", "changeit"), timeout=20)
        self.assertEqual(result.count(b"trustedCertEntry"), len(certificates) + 1)

    def test_bounded_failure_dispatches_restore_and_preserves_receipt(self):
        old = {"Id": D["OLD"]}
        manifest = {"retainedName": "retained-fixture", "newContainer": {"name": "fixture"}}
        request = {"Labels": {}}
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp) / "journal"
            stopped = {"State": {"Running": True, "Pid": 50}}
            with patch.dict(NAMESPACE, WORK=work):
                with patch.dict(NAMESPACE, inspect=lambda *args, **kwargs: old,
                                save=lambda *args, **kwargs: None,
                                action=lambda *args: None,
                                restore=lambda *args: None):
                    # Inject a failure at the first post-stop readback.
                    reads = iter((old, stopped))
                    with patch.dict(NAMESPACE, inspect=lambda *args, **kwargs: next(reads)):
                        report = {}
                        D["apply"](None, None, (manifest, "a" * 64, old, request, b"", b"", "b" * 64), report)
        self.assertEqual(report["status"], "SEMANTIC_PREVIOUS_CONTAINER_RESTORED")
        self.assertEqual(report["reason"], "OLD_STOP_FRAME_CHANGED")

    def test_restore_existing_cid_after_never_started_replacement(self):
        prefix = "ouf-d-ci-" + uuid.uuid4().hex[:10]
        name = prefix + "-semantic"
        retained = name + "-before"
        failed = name + "-failed"
        ip, mac = "172.29.218.6", "02:42:ac:1d:da:06"
        network = cli("network", "create", "--subnet", "172.29.218.0/24", prefix)
        cids = []
        def cleanup():
            if cids:
                subprocess.run(("docker", "rm", "-f", *cids), capture_output=True, timeout=30, check=True)
            cli("network", "rm", network)
        self.addCleanup(cleanup)
        image = cli("image", "inspect", "busybox:1.37.0", "--format", "{{.Id}}")
        base = {"Image": image, "Cmd": ["/bin/sh", "-c",
                "trap ':' USR1; touch /tmp/fixture-ready; while :; do sleep 1; done"],
                "HostConfig": {"NetworkMode": prefix, "RestartPolicy": {"Name": "no"}},
                "NetworkingConfig": {"EndpointsConfig": {prefix: {
                    "IPAMConfig": {"IPv4Address": ip}, "MacAddress": mac, "Aliases": [name],
                }}}}
        deadline = time.monotonic() + 60
        def create(labels):
            result = D["engine"](deadline, "POST", "/containers/create?name=" + name, base | {"Labels": labels})
            cids.append(result["Id"])
            return result["Id"]
        cid = create({})
        D["action"](deadline, cid, "start")
        old = D["inspect"](deadline, cid)
        self.assertEqual(old["NetworkSettings"]["Networks"][prefix]["MacAddress"], mac)
        D["action"](deadline, cid, "stop?t=2")
        D["engine"](deadline, "POST", f"/networks/{network}/disconnect", {"Container": cid, "Force": False})
        D["action"](deadline, cid, "rename?name=" + retained)
        digest = "c" * 64
        candidate = create({D["LABEL"]: digest})
        def ready(doc):
            for _ in range(30):
                status = subprocess.run(("docker", "exec", doc["Id"], "cat", "/proc/1/status"),
                                        capture_output=True, timeout=4)
                caught = re.search(rb"^SigCgt:\s*([0-9a-f]+)$", status.stdout, re.MULTILINE)
                if status.returncode == 0 and caught and int(caught[1], 16) & (1 << 9):
                    return
                time.sleep(0.1)
            self.fail("Fixture gate did not start")
        rollout = SimpleNamespace(mounts=lambda doc: doc["Mounts"], gate_running=ready)
        manifest = {"newContainer": {"name": name}, "retainedName": retained, "failureName": failed,
                    "observedGateway": "fixture"}
        with patch.dict(NAMESPACE, OLD=cid, NETWORK=prefix, NETWORK_ID=network, IMAGE=image, ADDRESS=ip, MAC=mac,
                        await_health=lambda *_: ready(D["inspect"](time.monotonic() + 5, cid))):
            D["restore"](rollout, old, manifest, digest, candidate)
        actual = D["inspect"](time.monotonic() + 5, cid)
        self.assertTrue(actual["State"]["Running"])
        self.assertEqual(actual["Name"], "/" + name)
        replacement = D["inspect"](time.monotonic() + 5, candidate)
        self.assertEqual(replacement["Name"], "/" + failed)
        self.assertFalse(replacement["State"]["Running"])
        self.assertEqual(replacement["NetworkSettings"]["Networks"], {})


if __name__ == "__main__":
    unittest.main()
