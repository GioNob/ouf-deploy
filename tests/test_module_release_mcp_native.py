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
from tools.module_release import postgres, retention
from tools.module_release.contract import ENTRY, Held, digest
from tools.module_release.docker import Docker
from tools.module_release.operation import ready


@unittest.skipUnless(sys.platform == "linux" and os.getenv("OUF_MODULE_RELEASE_NATIVE") == "1",
                     "labelled disposable Engine opt-in")
class NativeMCP(unittest.TestCase):
    def test_retention_permissions_and_batch_session(self):
        """DEP-55J-01/02. Exercise the production catalog query and the batch DSN on PostgreSQL."""
        profile = json.loads((ROOT / "tests/fixtures/module-release/mcp.example.json").read_bytes())
        profile["dockerSocket"] = os.environ["OUF_A2_FIXTURE_SOCKET"]
        rt = Docker(profile)
        self.assertIn("ouf.a2.fixture=true", rt.api("GET", "/info")["Labels"])
        cli = ["/usr/bin/docker", "--host", "unix://" + profile["dockerSocket"]]
        name = "retention-" + uuid.uuid4().hex
        net = rt.api("POST", "/networks/create", {"Name": name, "Internal": True})["Id"]
        self.addCleanup(rt.api, "DELETE", "/networks/" + net)
        with postgres_fixture(cli, name, name, jdbc=True) as setup:
            def sql(statement):
                return subprocess.check_output(setup + ["-At"], input=statement.encode()).decode().strip()
            sql("""CREATE SCHEMA ouf_mcp;
CREATE ROLE app_fixture LOGIN;
CREATE ROLE maintenance_fixture NOLOGIN;
CREATE ROLE worker_fixture LOGIN;
GRANT maintenance_fixture TO worker_fixture;
CREATE ROLE ouf_mcp_retention_owner NOLOGIN;
GRANT USAGE ON SCHEMA ouf_mcp TO app_fixture, maintenance_fixture, ouf_mcp_retention_owner;
CREATE TABLE ouf_mcp.predecessor_fixture(k integer primary key);
GRANT SELECT,INSERT,UPDATE ON ouf_mcp.predecessor_fixture TO app_fixture;
SET ROLE app_fixture;
INSERT INTO ouf_mcp.predecessor_fixture VALUES (1);
RESET ROLE;""")
            name_prefix = "ouf_mcp.purge_analysis_run_history"
            four = name_prefix + "(int,int,int,int)"
            five = name_prefix + "(int,int,int,int,int)"
            for signature in (four, five):
                sql(f"""CREATE FUNCTION {signature} RETURNS int LANGUAGE sql SECURITY DEFINER
 SET search_path=pg_catalog AS 'SELECT 1';
ALTER FUNCTION {signature} OWNER TO ouf_mcp_retention_owner;
REVOKE ALL ON FUNCTION {signature} FROM PUBLIC;
GRANT EXECUTE ON FUNCTION {signature} TO maintenance_fixture;""")
            pg = rt.inspect(name)
            db = profile["migration"]["database"]
            db.update(postgresCid=pg["Id"], socket="/tmp")
            spec = dict(functionName="purge_analysis_run_history", adminRole="fixture", maintenanceRole="maintenance_fixture",
                        maintenanceLogin="worker_fixture", maintenancePassfile="/fixture/passfile")
            profile["migration"]["retentionAdmin019"] = spec
            doc = {"Config": {"Env": ["MCP_DATABASE_URL=postgresql://app_fixture@" + name + "/postgres"]},
                   "NetworkSettings": pg["NetworkSettings"], "Id": pg["Id"], "Image": profile["ci"]["imageId"]}
            doc["Config"]["Env"].extend(["OUF_ANALYSIS_WORKLOAD=fixture", "OUF_ANALYSIS_STATUS_SECONDS=3600",
                                         "OUF_ANALYSIS_RESERVATION_DAYS=10", "OUF_ANALYSIS_ATTEMPT_DAYS=20",
                                         "OUF_ANALYSIS_SNAPSHOT_DAYS=30", "OUF_ANALYSIS_READ_DAYS=40",
                                         "OUF_ANALYSIS_RETENTION_BATCH=50"])
            definitions = sql(f"""SET search_path=pg_catalog;
SELECT json_build_array(pg_get_functiondef('{four}'::regprocedure), pg_get_functiondef('{five}'::regprocedure))""")
            spec["functionSha256"] = digest(sorted(json.loads(definitions)))
            def check():
                _, facts = retention.catalog(rt, doc)
                return retention.verified_routines(spec, facts["functions"])
            self.assertTrue(check())
            for change, undo in (
                ("ALTER ROLE ouf_mcp_retention_owner LOGIN", "ALTER ROLE ouf_mcp_retention_owner NOLOGIN"),
                ("GRANT ouf_mcp_retention_owner TO worker_fixture", "REVOKE ouf_mcp_retention_owner FROM worker_fixture"),
                *((f"GRANT EXECUTE ON FUNCTION {signature} TO {role}",
                   f"REVOKE EXECUTE ON FUNCTION {signature} FROM {role}") for signature in (four, five)
                  for role in ("app_fixture", "PUBLIC", "worker_fixture")),
                (f"REVOKE EXECUTE ON FUNCTION {five} FROM maintenance_fixture",
                 f"GRANT EXECUTE ON FUNCTION {five} TO maintenance_fixture"),
                (f"CREATE FUNCTION {name_prefix}() RETURNS int LANGUAGE sql AS 'SELECT 1'", f"DROP FUNCTION {name_prefix}()"),
            ):
                with self.subTest(change=change):
                    sql(change)
                    with self.assertRaisesRegex(Held, "RETENTION_FUNCTION_OR_ACL_DRIFT"):
                        check()
                    sql(undo)
            self.assertTrue(check())
            # Allow just the fixture worker over this disposable, internal network.
            subprocess.run([*cli, "exec", name, "/bin/sh", "-ec",
                            "echo 'host postgres worker_fixture samenet trust' >> /tmp/data/pg_hba.conf"], check=True)
            sql("SELECT pg_reload_conf()")
            _, facts = retention.catalog(rt, doc)
            request = retention.worker_request(rt, doc, retention.BATCH, facts)
            dsn = request["Env"][0].partition("=")[2]
            row = subprocess.check_output([*cli, "exec", name, "psql", "-XwAt", "-d", dsn, "-c",
                f"SELECT session_user,current_user,{name_prefix}(1,2,3,4),{name_prefix}(1,2,3,4,5)"]).decode().strip()
            self.assertEqual(row, "worker_fixture|maintenance_fixture|1|1")
            self.assertEqual(sql("SET ROLE app_fixture; UPDATE ouf_mcp.predecessor_fixture SET k=2 WHERE k=1;"
                                 "SELECT k FROM ouf_mcp.predecessor_fixture"), "2")

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
