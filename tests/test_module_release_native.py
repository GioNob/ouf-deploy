"""Opt-in module release with an actual Docker archive, gated Java and HTTP probe."""
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import zipfile

from test_module_release import PROFILE, TESTED
from tools.module_release.contract import ENTRY, checksum
from tools.module_release.docker import Docker
from tools.module_release.operation import apply, migrate, plan, ready


@unittest.skipUnless(sys.platform == "linux" and os.getenv("OUF_MODULE_RELEASE_NATIVE") == "1",
                     "labelled disposable Engine opt-in")
class NativeRelease(unittest.TestCase):
    def test_gate_migration_and_http_readiness(self):
        self.assertEqual(os.geteuid(), 0)
        socket = os.environ["OUF_A2_FIXTURE_SOCKET"]
        cli = ["/usr/bin/docker", "--host", "unix://" + socket]
        p = json.loads(PROFILE.read_bytes())
        rt = Docker(p)
        p["dockerSocket"] = socket
        self.assertIn("ouf.a2.fixture=true", rt.api("GET", "/info")["Labels"])
        name = "module-fixture-" + uuid.uuid4().hex
        net = name + "-net"
        command = ["java", "-jar", "/app/application.jar"]
        old_image = os.environ["OUF_A2_FIXTURE_IMAGE"]
        tag = "ouf-ci-gate:" + TESTED
        candidate = rt.api("GET", "/images/" + tag + "/json")["Id"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p.update(container=name, retainedName=name+"-saved", failedName=name+"-failed", oldImage=old_image,
                     inbox=directory, journal=directory, nsenter="/usr/bin/nsenter",
                     networks={net: {"ipv4":"192.0.2.35", "aliases":[name]}}, gate={"command":command})
            p["readiness"].update(path="/ready", attempts=20)
            p["migration"].update(mode="dedicated", command=["/bin/sh", "-c", "exit 0"], rollbackCompatible=True)
            ci = p["ci"]
            ci.update(repository="fixture/module", imageName="ouf-ci-gate", imageId=candidate,
                      runId=1, runAttempt=1, artifactId=1)
            payload = root / "image.tar.gz"
            with tempfile.TemporaryFile() as raw, gzip.open(payload, "wb", compresslevel=1) as out:
                subprocess.run([*cli, "save", tag], stdout=raw, check=True)
                raw.seek(0)
                shutil.copyfileobj(raw, out)
            with payload.open("rb") as f:
                archive_hash = checksum(f)
            manifest = dict(schema=ci["manifestSchema"], repository=ci["repository"],
                            reviewedSourceCommit=ci["sourceCommit"], testedCommit=TESTED, testedTree=ci["sourceTree"],
                            workflowRunId="1", workflowRunAttempt="1", imageTag=tag, imageRevisionLabel=TESTED,
                            archiveName=payload.name, archiveSha256=archive_hash,
                            archiveBytes=payload.stat().st_size, imageId=candidate)
            archive = root / "fixture.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.write(payload, payload.name)
                z.writestr("manifest.json", json.dumps(manifest))
                z.writestr("SHA256SUMS", archive_hash + "  image.tar.gz\n")
            with archive.open("rb") as f:
                ci["zipSha256"] = checksum(f)
            archive.rename(root / (ci["zipSha256"] + ".zip"))
            network = rt.api("POST", "/networks/create", {"Name":net, "Internal":True, "Driver":"bridge",
                             "IPAM":{"Config":[{"Subnet":"192.0.2.32/27"}]}})["Id"]
            self.addCleanup(subprocess.run, [*cli, "network", "rm", network], check=False)
            for container in (name, p["retainedName"], p["failedName"]):
                self.addCleanup(subprocess.run, [*cli, "rm", "-f", container], stderr=subprocess.DEVNULL)
            old = rt.create(name, dict(Image=old_image, Entrypoint=ENTRY, Cmd=command,
                HostConfig={"NetworkMode":net, "RestartPolicy":{"Name":"no"}},
                NetworkingConfig={"EndpointsConfig":{net:{"Aliases":[name], "IPAMConfig":{"IPv4Address":"192.0.2.35"}}}}))
            rt.start(old)
            for _ in range(100):
                if rt.process(rt.inspect(old), gated=True):
                    break
                time.sleep(.1)
            else:
                self.fail("Predecessor gate")
            rt.signal(old)
            for _ in range(100):
                if ready(rt, rt.inspect(old), p["readiness"]):
                    break
                time.sleep(.1)
            else:
                self.fail("Predecessor HTTP readiness")
            proposal = plan(p)
            self.assertEqual(proposal["status"], "PLANNED", proposal)
            staged = apply(p, proposal["planSha256"], defer_migration=True)
            self.assertEqual(staged["status"], "GATED", staged)
            self.assertTrue(rt.process(rt.inspect(staged["successorCid"]), gated=True))
            final = migrate(p, proposal["planSha256"], staged["migrationSha256"])
            self.assertEqual((final["status"], final.get("readiness")), ("READY", "UP"), final)
            self.assertEqual(rt.inspect(p["retainedName"])["Id"], old)
