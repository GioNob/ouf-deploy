"""Opt-in: observe the Go executable/argv and empty HTTP 204 in its network namespace."""
import json
import os
import subprocess
import sys
import time
import unittest
import uuid

from privileged_postgres_fixture import postgres_fixture
from test_module_release import ROOT
from tools.module_release import postgres
from tools.module_release.contract import ENTRY, Held, digest
from tools.module_release.docker import Docker
from tools.module_release.operation import ready


@unittest.skipUnless(sys.platform == "linux" and os.getenv("OUF_MODULE_RELEASE_NATIVE") == "1",
                     "labelled disposable Engine opt-in")
class NativeMCP(unittest.TestCase):
    def test_gated_go_server_returns_204(self):
        profile = json.loads((ROOT / "tests/fixtures/module-release/mcp.example.json").read_bytes())
        profile.update(nsenter="/usr/bin/nsenter", dockerSocket=os.environ["OUF_A2_FIXTURE_SOCKET"])
        rt = Docker(profile)
        self.assertIn("ouf.a2.fixture=true", rt.api("GET", "/info")["Labels"])
        cid = rt.create("mcp-probe-" + uuid.uuid4().hex, {
            "Image": os.environ["OUF_A2_FIXTURE_IMAGE"],
            "Entrypoint": ENTRY, "Cmd": profile["gate"]["command"], "HostConfig": {"NetworkMode": "none"}})
        self.addCleanup(rt.api, "DELETE", "/containers/" + cid + "?force=true")
        rt.start(cid)
        for _ in range(100):
            doc = rt.inspect(cid)
            if rt.process(doc, gated=True):
                break
            time.sleep(.1)
        else:
            self.fail("USR1 gate")
        self.assertFalse(ready(rt, doc, profile["readiness"]))
        rt.signal(cid)
        for _ in range(100):
            doc = rt.inspect(cid)
            if ready(rt, doc, profile["readiness"]):
                break
            time.sleep(.1)
        else:
            self.fail("Go readiness")
        self.assertEqual(rt.probe(doc), (204, b""))
        self.assertFalse(ready(rt, doc, dict(profile["readiness"], acceptStatus=[200])))
        profile["gate"]["executable"] = "/app/unexpected"
        self.assertFalse(rt.process(doc, gated=False))

    def test_postgres_snapshot_history_and_schema(self):
        profile = json.loads((ROOT / "tests/fixtures/module-release/mcp.example.json").read_bytes())
        profile["dockerSocket"] = os.environ["OUF_A2_FIXTURE_SOCKET"]
        rt = Docker(profile)
        self.assertIn("ouf.a2.fixture=true", rt.api("GET", "/info")["Labels"])
        cli = ["/usr/bin/docker", "--host", "unix://" + profile["dockerSocket"]]
        name = "mcp-pg-" + uuid.uuid4().hex
        net = name + "-net"
        network_id = rt.api("POST", "/networks/create", {"Name": net, "Internal": True})["Id"]
        self.addCleanup(rt.api, "DELETE", "/networks/" + network_id)
        with postgres_fixture(cli, name, net) as setup:
            def sql(command):
                subprocess.run(setup, input=command.encode(), check=True, stdout=subprocess.DEVNULL)
            sql("""CREATE SCHEMA ouf_mcp;
                CREATE TABLE ouf_mcp.profile_analysis(id integer primary key);
                CREATE TABLE ouf_mcp.profile_analysis_task(id integer);
                CREATE TABLE ouf_mcp.schema_migration(version integer, checksum text, applied_at timestamptz);
                INSERT INTO ouf_mcp.schema_migration SELECT i, repeat('a',64),now() FROM generate_series(1,14) i;
                CREATE ROLE reader LOGIN;
                GRANT USAGE ON SCHEMA ouf_mcp TO reader;
                GRANT SELECT ON ouf_mcp.schema_migration TO reader;""")
            migration = profile["migration"]
            migration["database"].update(postgresCid=rt.inspect(name)["Id"], socket="/tmp")
            old = {"Config": {"Env": ["MCP_DATABASE_URL=postgres://reader@" + name + "/postgres"]},
                   "NetworkSettings": {"Networks": {net: {"NetworkID": network_id}}}}
            baseline = postgres.observe(rt, old)
            self.assertEqual(len(baseline["history"]), 14)
            postgres.verify(rt, old, baseline, migration)
            sql("ALTER TABLE ouf_mcp.profile_analysis ADD COLUMN reviewed text")
            with self.assertRaisesRegex(Held, "DATABASE_CHANGED"):
                postgres.verify(rt, old, baseline, migration)
            migration.update(migrations=[{"version": 15, "checksum": "b"*64}],
                             targetSchemaSha256=digest(postgres.observe(rt, old)["schema"]))
            sql("INSERT INTO ouf_mcp.schema_migration VALUES (15,repeat('b',64),now())")
            postgres.verify(rt, old, baseline, migration, migrated=True)
            sql("UPDATE ouf_mcp.schema_migration SET checksum=repeat('c',64) WHERE version=2")
            with self.assertRaisesRegex(Held, "DATABASE_CHANGED"):
                postgres.verify(rt, old, baseline, migration, migrated=True)
