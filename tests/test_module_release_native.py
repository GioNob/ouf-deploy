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
from unittest.mock import patch
import zipfile

from test_module_release import PROFILE, TESTED
from privileged_postgres_fixture import postgres_fixture
from tools.module_release import flyway, postgres, recovery, return_operation
from tools.module_release.contract import ENTRY, checksum, digest
from tools.module_release.docker import Docker
from tools.module_release.operation import apply, migrate, plan, ready


@unittest.skipUnless(sys.platform == "linux" and os.getenv("OUF_MODULE_RELEASE_NATIVE") == "1",
                     "labelled disposable Engine opt-in")
class NativeRelease(unittest.TestCase):
    def test_gate_migration_and_http_readiness(self):
        self.exercise_release(busybox=False)

    def test_busybox_gate_and_forced_return_to_ready_predecessor(self):
        self.exercise_release(busybox=True)

    def test_crash_after_detach_returns_to_http_readiness(self):
        self.exercise_release(busybox=True, interruption="detach")

    def test_created_busybox_and_lost_signal_resume_same_cid(self):
        self.exercise_release(busybox=True, interruption="create")

    def test_committed_dedicated_migration_with_missing_receipt(self):
        self.exercise_release(busybox=True, interruption="database")

    def test_flyway_commit_and_lost_signal_are_reconciled(self):
        self.exercise_release(busybox=False, interruption="flyway")

    def test_udp_real_flyway_release_reconciliation_and_return(self):
        self.exercise_release(busybox=False, interruption="jdbc")

    def exercise_release(self, busybox, interruption=None):
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
        image_name = "ouf-ci-busybox" if busybox else "ouf-ci-gate"
        if interruption == "jdbc":
            image_name = "ouf-ci-flyway"
            old_image = rt.api("GET", "/images/" + image_name + ":old/json")["Id"]
            command = ["java", "-jar", "/app/flyway.jar"]
            p["module"] = "udp"
            p["ci"]["artifactPrefix"] = "fixture-udp"
        if busybox:
            old_image = rt.api("GET", "/images/" + image_name + ":old/json")["Id"]
            command = ["/usr/local/bin/ouf-mcp", "server"]
        tag = image_name + ":" + TESTED
        candidate = rt.api("GET", "/images/" + tag + "/json")["Id"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p.update(container=name, retainedName=name+"-saved", failedName=name+"-failed", oldImage=old_image,
                     inbox=directory, journal=directory, nsenter="/usr/bin/nsenter",
                     networks={net: {"ipv4":"192.0.2.35", "aliases":[name]}}, gate={"command":command})
            p["readiness"].update(path="/ready", attempts=20)
            p["migration"].update(mode="dedicated", command=["/bin/sh", "-c", "exit 0"], rollbackCompatible=True)
            if busybox:
                p["readiness"] = dict(path="/health/ready", port=8080, acceptStatus=[204], attempts=20)
                p["migration"]["command"] = ["/bin/sh", "-c", "exit 1"]
            ci = p["ci"]
            ci.update(repository="fixture/module", imageName=image_name, imageId=candidate,
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
            env = []
            if interruption in ("flyway", "database", "jdbc"):
                pg = name + "-pg"
                setup = self.enterContext(postgres_fixture(cli, pg, net, jdbc=interruption == "jdbc"))
                def sql(command):
                    subprocess.run(setup, input=command.encode(), check=True, stdout=subprocess.DEVNULL)
                if interruption == "jdbc":
                    p["migration"] = dict(mode="spring-flyway", rollbackCompatible=True, flyway=dict(
                        postgresCid=rt.inspect(pg)["Id"], socket="/tmp", urlEnv="FIXTURE_URL",
                        userEnv="FIXTURE_USER", database="postgres", schema="release_fixture"))
                    env = [f"FIXTURE_URL=jdbc:postgresql://{pg}/postgres", "FIXTURE_USER=fixture"]
                elif interruption == "database":
                    sql("""CREATE SCHEMA ouf_mcp;
                        CREATE TABLE ouf_mcp.profile_analysis(id int);
                        CREATE TABLE ouf_mcp.profile_analysis_task(id int);
                        CREATE TABLE ouf_mcp.schema_migration(version int, checksum text, applied_at timestamptz);
                        INSERT INTO ouf_mcp.schema_migration VALUES (1,repeat('a',64),now());""")
                    env = [f"MCP_DATABASE_URL=postgresql://fixture@{pg}/postgres"]
                    p["migration"].update(command=["/bin/sh", "-c", "exit 0"],
                        database=dict(postgresCid=rt.inspect(pg)["Id"], version=1, socket="/tmp", urlEnv="MCP_DATABASE_URL"),
                        migrations=[dict(version=2, checksum="b"*64)])
                else:
                    sql("""CREATE SCHEMA ouf_onboarding;
                        CREATE TABLE ouf_onboarding.flyway_schema_history(installed_rank int, version text,
                        script text, type text, checksum int, success boolean);
                        INSERT INTO ouf_onboarding.flyway_schema_history VALUES
                        (1,'1','V1__base.sql','SQL',%d,true);""" % flyway.flyway_checksum(b"SELECT 1;"))
                    rt.flyway_peer = dict(postgresCid=rt.inspect(pg)["Id"], socket="/tmp")
                    p["migration"].pop("command")
                    p["migration"]["mode"] = "spring-flyway"
                    env = [f"OUF_ONB_DB_URL=jdbc:postgresql://{pg}/postgres", "OUF_ONB_DB_USER=fixture"]
            elif interruption == "create":
                p["migration"].pop("command")
                p["migration"]["mode"] = "none"
            old = rt.create(name, dict(Image=old_image, Entrypoint=ENTRY, Cmd=command, Env=env, User="10005:10005" if busybox else "",
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
            if interruption == "database":
                # A data-only migration preserves the qualified schema signature.
                p["migration"]["targetSchemaSha256"] = digest(postgres.observe(rt, rt.inspect(old))["schema"])
            proposal = plan(p)
            self.assertEqual(proposal["status"], "PLANNED", proposal)
            stamp = proposal["planSha256"]
            if interruption == "jdbc":
                stage = apply(p, stamp, rt, defer_migration=True)
                self.assertEqual(stage["status"], "GATED", stage)
                config = rt.inspect(stage["successorCid"])["Config"]
                self.assertEqual(config["Entrypoint"], ENTRY)
                self.assertIn("FIXTURE_JAVA_IMAGE=successor", config["Env"])
                self.assertEqual(config["Labels"]["fixture.java.successor"], "yes")
                review = json.loads((root / stamp / "migration-plan.json").read_bytes())["flywayReview"]
                self.assertEqual([r["script"] for r in review["pending"]], ["V2__added.sql"])
                send = rt.signal
                def interrupt_after_delivery(cid):
                    send(cid)
                    raise KeyboardInterrupt
                with patch.object(rt, "signal", side_effect=interrupt_after_delivery), self.assertRaises(KeyboardInterrupt):
                    migrate(p, stamp, stage["migrationSha256"], rt)
                runtime = Docker(p)
                with patch.object(runtime, "signal", side_effect=AssertionError("duplicate signal")):
                    final = recovery.resume(p, runtime, recovery.proposal(p, runtime))
                self.assertEqual((final["status"], final["readyHttp"]), ("READY", 200))
                table = subprocess.check_output(setup + ["-Atc", "SELECT to_regclass('release_fixture.added_row')"])
                self.assertIn(b"added_row", table)
                restored = return_operation.run(p, stamp, rt)
                self.assertEqual((restored.get("restoredCid"), restored.get("predecessorReadyHttp")), (old, 200), restored)
                return
            if interruption == "database":
                stage = apply(p, stamp, rt, defer_migration=True)
                self.assertEqual(stage["status"], "GATED", stage)
                execute_migration = rt.migrate
                def committed(cid, argv):
                    execute_migration(cid, argv)
                    sql("INSERT INTO ouf_mcp.schema_migration VALUES (2,repeat('b',64),now())")
                    raise KeyboardInterrupt
                with patch.object(rt, "migrate", side_effect=committed), self.assertRaises(KeyboardInterrupt):
                    migrate(p, stamp, stage["migrationSha256"], rt)
                self.assertFalse((root / stamp / "migration-complete.json").exists())
                runtime = Docker(p)
                stage = recovery.resume(p, runtime, recovery.proposal(p, runtime))
                with patch.object(runtime, "migrate", side_effect=AssertionError("duplicate migration")):
                    final = migrate(p, stamp, stage["migrationSha256"], runtime, recover=True)
                self.assertEqual((final["status"], final["readyHttp"]), ("READY", 204))
                return
            if interruption == "detach":
                disconnect = rt.disconnect
                def crash_detach(cid, netid):
                    disconnect(cid, netid)
                    raise KeyboardInterrupt
                with patch.object(rt, "disconnect", side_effect=crash_detach), self.assertRaises(KeyboardInterrupt):
                    apply(p, stamp, rt)
                runtime = Docker(p)
                recovered = recovery.resume(p, runtime, recovery.proposal(p, runtime))
                self.assertEqual((recovered["restoredCid"], recovered["predecessorReadyHttp"]), (old, 204))
                self.assertTrue(ready(rt, rt.inspect(old), p["readiness"]))
                return
            if interruption == "create":
                with patch.object(rt, "start", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                    apply(p, stamp, rt)
                doc = rt.inspect(name)
                self.assertEqual(doc["State"]["Status"], "created")
                self.assertEqual(doc["Config"]["Entrypoint"], ENTRY)
                self.assertIn("MODULE_SUCCESSOR=yes", doc["Config"]["Env"])
                self.assertEqual(doc["Config"]["Labels"]["fixture.module.successor"], "yes")
            if interruption in ("create", "flyway"):
                if interruption == "flyway":
                    stage = apply(p, stamp, rt, defer_migration=True)
                    self.assertEqual(stage["status"], "GATED", stage)
                    doc = rt.inspect(name)
                if interruption == "create":
                    rt = Docker(p)
                send = rt.signal
                def delivered(cid):
                    send(cid)
                    if interruption == "flyway":
                        sql("INSERT INTO ouf_onboarding.flyway_schema_history VALUES "
                            "(2,'2','V2__added.sql','SQL',%d,true)" % flyway.flyway_checksum(b"SELECT 2;"))
                    raise KeyboardInterrupt
                with patch.object(rt, "signal", side_effect=delivered) as sent, self.assertRaises(KeyboardInterrupt):
                    if interruption == "create":
                        recovery.resume(p, rt, recovery.proposal(p, rt))
                    else:
                        migrate(p, stamp, stage["migrationSha256"], rt)
                sent.assert_called_once_with(doc["Id"])
                runtime = Docker(p)
                runtime.flyway_peer = rt.flyway_peer
                with patch.object(runtime, "signal", side_effect=AssertionError("duplicate USR1")):
                    final = recovery.resume(p, runtime, recovery.proposal(p, runtime))
                self.assertEqual((final["successorCid"], final["readyHttp"]),
                                 (doc["Id"], 204 if busybox else 200), final)
                self.assertTrue(ready(rt, rt.inspect(doc["Id"]), p["readiness"]))
                return
            if busybox:
                stamp = proposal["planSha256"]
                result = apply(p, stamp)
                self.assertEqual((result["status"], result.get("reason"), result.get("rollback")),
                                 ("HELD", "MIGRATION_FAILED", "ROLLED_BACK"), result)
                log = root / stamp
                # The failed exec runs only after the candidate's real gate proof.
                self.assertEqual(json.loads((log / "migration-intent.json").read_bytes())["cid"], result["successorCid"])
                self.assertEqual(json.loads((log / "restore-signal.json").read_bytes())["cid"], old)
                restored = rt.inspect(name)
                self.assertEqual(restored["Id"], old)
                self.assertTrue(ready(rt, restored, p["readiness"]))
                self.assertFalse(rt.inspect(result["successorCid"])["State"]["Running"])
                return
            staged = apply(p, proposal["planSha256"], defer_migration=True)
            self.assertEqual(staged["status"], "GATED", staged)
            self.assertTrue(rt.process(rt.inspect(staged["successorCid"]), gated=True))
            final = migrate(p, proposal["planSha256"], staged["migrationSha256"])
            self.assertEqual((final["status"], final.get("readiness")), ("READY", "UP"), final)
            self.assertEqual(rt.inspect(p["retainedName"])["Id"], old)
