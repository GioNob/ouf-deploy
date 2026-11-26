"""Governed MCP one-shots. Only an installed profile supplies roles and SQL pins."""
import json
import subprocess
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode

from . import operation as op, postgres
from .contract import SHA, Held, digest, matches, require

ADMIN = "mcp-retention-admin-019"
BATCH = "analysis-retention-once"
COMMAND = {ADMIN: "migrate-analysis-retention-019", BATCH: BATCH}
RECEIPT = "retention-admin-019.json"
BATCH_ENV = (
    "OUF_ANALYSIS_WORKLOAD", "OUF_ANALYSIS_STATUS_SECONDS", "OUF_ANALYSIS_RESERVATION_DAYS",
    "OUF_ANALYSIS_ATTEMPT_DAYS", "OUF_ANALYSIS_SNAPSHOT_DAYS", "OUF_ANALYSIS_READ_DAYS",
    "OUF_ANALYSIS_RETENTION_BATCH",
)


def catalog(rt, doc):
    migration = rt.p["migration"]
    spec, db = migration["retentionAdmin019"], migration["database"]
    pg = rt.inspect(db["postgresCid"])
    url, app, name = postgres.database_target(db, doc, pg)
    require(app not in (spec["adminRole"], spec["maintenanceRole"], spec["maintenanceLogin"], "ouf_mcp_retention_owner")
            and all(k in ("sslmode", "sslrootcert", "sslcert", "sslkey", "connect_timeout", "application_name")
                    for k, _ in parse_qsl(url.query, keep_blank_values=True)),
            "RETENTION_DATABASE_BINDING")
    # All interpolated identifiers are validated by the installed profile.
    sql = f"""BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path = pg_catalog;
WITH functions AS (
 SELECT p.pronargs AS arity, CASE WHEN p.prokind='f' THEN pg_get_functiondef(p.oid) END AS definition,
   p.proacl::text AS acl,
   (p.prokind='f' AND p.prosecdef AND owner.rolname='ouf_mcp_retention_owner'
    AND NOT owner.rolcanlogin AND NOT owner.rolsuper
    AND NOT EXISTS (SELECT FROM pg_auth_members WHERE roleid=owner.oid)
    AND login.rolcanlogin AND NOT login.rolsuper AND NOT login.rolcreaterole
    AND pg_has_role(login.oid,maint.oid,'MEMBER') AND NOT maint.rolsuper AND NOT maint.rolcreaterole
    AND NOT pg_has_role(current_user, maint.oid, 'MEMBER')
    AND has_schema_privilege(maint.oid,n.oid,'USAGE')
    AND has_function_privilege(maint.oid,p.oid,'EXECUTE')
    AND NOT has_function_privilege(current_user,p.oid,'EXECUTE')
    AND EXISTS (SELECT FROM aclexplode(p.proacl) a WHERE a.grantee=maint.oid AND a.privilege_type='EXECUTE')
    AND NOT EXISTS (SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',owner.oid))) a
      WHERE a.grantee NOT IN (owner.oid,maint.oid) OR (a.grantee=maint.oid AND a.is_grantable))
   ) AS permitted
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 JOIN pg_roles owner ON owner.oid=p.proowner
 LEFT JOIN pg_roles maint ON maint.rolname='{spec["maintenanceRole"]}'
 LEFT JOIN pg_roles login ON login.rolname='{spec["maintenanceLogin"]}'
 WHERE n.nspname='ouf_mcp' AND p.proname='{spec["functionName"]}'
)
SELECT json_build_object('oid',(SELECT oid::text FROM pg_database WHERE datname=current_database()),
 'application',current_user,'functions',coalesce((SELECT json_agg(json_build_object(
 'arity',arity,'definition',definition,'schemaItem',json_build_array('routine',definition)::text,
 'permitted',permitted,'acl',acl) ORDER BY arity) FROM functions),'[]'));
ROLLBACK;"""
    facts = postgres.database_snapshot(rt.p["dockerSocket"], db, doc, pg, sql=sql)
    require(facts["application"] == app and matches(r"[0-9]+", facts["oid"]), "RETENTION_DATABASE_BINDING")
    reference = digest([pg["Id"], url.port or 5432, name, facts["oid"]])
    return reference, facts


def binding(p, database_ref):
    spec = p["migration"]["retentionAdmin019"]
    return {"imageDigest": p["ci"]["imageId"], "databaseRef": database_ref,
            "sqlSha256": spec["sqlSha256"], "ownerAclSha256": spec["ownerAclSha256"]}


def verified_routines(spec, rows):
    drift = "RETENTION_FUNCTION_OR_ACL_DRIFT"
    require(isinstance(rows, list) and len(rows) == 2 and {row["arity"] for row in rows} == {4, 5}
            and all(row["permitted"] is True for row in rows), drift)
    require(digest(sorted(row["definition"] for row in rows)) == spec["functionSha256"], drift)
    return [digest(row["schemaItem"]) for row in rows]


def worker_request(rt, doc, phase, facts):
    migration = rt.p["migration"]
    db, spec = migration["database"], migration["retentionAdmin019"]
    url, _, _ = postgres.database_target(db, doc, rt.inspect(db["postgresCid"]))
    prefix = "admin" if phase == ADMIN else "maintenance"
    # The reviewed image consumes the role-specific password through libpq's
    # passfile. Its immutable command never receives the application's password.
    role = spec["adminRole"] if phase == ADMIN else spec["maintenanceLogin"]
    authority = role + "@" + url.netloc.rpartition("@")[2]
    query = parse_qsl(url.query, keep_blank_values=True)
    if phase == ADMIN:
        env = ["MCP_MIGRATION_DATABASE_OID=" + facts["oid"],
               "MCP_MIGRATION_APPLICATION_ROLE=" + facts["application"]]
    else:
        query.append(("options", "-c role=" + spec["maintenanceRole"]))
        env = []
        for key in BATCH_ENV:
            values = [entry for entry in doc["Config"]["Env"] if entry.startswith(key + "=")]
            require(len(values) == 1 and values[0].partition("=")[2].strip(), "RETENTION_CONFIG_INCOMPLETE")
            env.append(values[0])
    dsn = url._replace(netloc=authority, query=urlencode(query, quote_via=quote)).geturl()
    target = "/run/ouf-retention.pgpass"
    return {"Image": doc["Image"], "Entrypoint": [rt.p["gate"]["command"][0]], "Cmd": [COMMAND[phase]],
            "Env": [spec.get(prefix + "UrlEnv", db["urlEnv"]) + "=" + dsn, "PGPASSFILE=" + target, *env],
            "HostConfig": {"NetworkMode": "container:" + doc["Id"], "ReadonlyRootfs": True,
                           "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
                           "Mounts": [{"Type": "bind", "Source": spec[prefix + "Passfile"],
                                       "Target": target, "ReadOnly": True}]}}


def completed_worker(rt, doc, root, phase, facts):
    """Recover stdout and exit status of the same Docker execution after a crash."""
    request = worker_request(rt, doc, phase, facts)
    claim_file, start_file = phase + ".worker.json", phase + ".start.json"
    name = phase + "-" + root.name
    if (root / claim_file).exists():
        claim = op.read(root, claim_file)
    else:
        # A lost create response can leave only an unstarted container. Never
        # adopt an unjournalled CID or start a second worker in its place.
        cid = rt.create(name, request)
        require(matches(SHA, cid), "RETENTION_WORKER_UNPROVEN")
        claim = {"cid": cid, "requestSha256": op.public_output.binding("retention-request", request)}
        op.record(root, claim_file, claim)
    cid = claim["cid"]
    require(matches(SHA, cid) and claim["requestSha256"] == op.public_output.binding("retention-request", request), "RETENTION_WORKER_DRIFT")

    def inspect():
        worker = rt.inspect(cid)
        require(worker["Id"] == cid and worker["Name"] == "/" + name and worker["Image"] == request["Image"]
                and worker["Path"] == request["Entrypoint"][0] and worker["Args"] == request["Cmd"]
                and all(value in worker["Config"]["Env"] for value in request["Env"])
                and worker["HostConfig"]["NetworkMode"] == request["HostConfig"]["NetworkMode"]
                and worker["RestartCount"] == 0, "RETENTION_WORKER_DRIFT")
        return worker

    worker = inspect()
    if not (root / start_file).exists():
        require(op.never_started(worker), "RETENTION_OUTCOME_UNCONFIRMED")
        op.record(root, start_file, claim)
    else:
        require(op.read(root, start_file) == claim, "RETENTION_WORKER_DRIFT")
    if op.never_started(worker):
        rt.start(cid)
    for _ in range(rt.p["readiness"]["attempts"]):
        state = inspect()["State"]
        if state["Status"] == "exited":
            require(state["ExitCode"] == 0 and not state["OOMKilled"] and not state["Error"],
                    "RETENTION_COMMAND_FAILED")
            return cid
        require(state["Status"] == "running", "RETENTION_OUTCOME_UNCONFIRMED")
        rt.pause()
    require(False, "RETENTION_OUTCOME_UNCONFIRMED")


def retire_worker(rt, root, phase, cid):
    require(matches(SHA, cid) and op.read(root, phase + ".worker.json")["cid"] == cid, "RETENTION_WORKER_DRIFT")
    worker = rt.inspect(cid, missing=True)
    if worker is not None:
        require(worker["Id"] == cid and worker["Name"] == "/" + phase + "-" + root.name
                and worker["State"]["Status"] == "exited", "RETENTION_WORKER_DRIFT")
        rt.api("DELETE", "/containers/" + cid + "?v=true")


def verified_output(rt, cid):
    result = subprocess.run(["/usr/bin/docker", "--host", "unix://" + rt.p["dockerSocket"], "logs", cid],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=rt.p["readiness"]["attempts"])
    lines = result.stdout.splitlines()
    require(result.returncode == 0 and len(lines) == 1, "RETENTION_OUTPUT_UNCONFIRMED")

    def unique(pairs):
        obj = dict(pairs)
        require(len(obj) == len(pairs), "RETENTION_OUTPUT_UNCONFIRMED")
        return obj

    try:
        obj = json.loads(lines[0], object_pairs_hook=unique)
    except ValueError:
        raise Held("RETENTION_OUTPUT_UNCONFIRMED") from None
    require(isinstance(obj, dict) and obj.get("status") == "VERIFIED", "RETENTION_OUTPUT_UNCONFIRMED")
    return obj


def run(p, rt, source, phase, ready):
    require(phase in COMMAND and matches(SHA, source), "RETENTION_PLAN_DRIFT")
    root = Path(p["journal"]) / source
    plan = op.read(root, "plan.json")
    require(digest(plan) == source and plan["profileSha256"] == op.public_output.profile_binding(p, plan)
            and not (root / "return-intent.json").exists()
            and not (root.parent / "mcp.lock").exists(), "RETENTION_PLAN_DRIFT")
    doc = rt.inspect(p["container"])
    require(doc["Id"] == ready["successorCid"] and doc["Image"] == plan["ci"]["imageId"]
            and op.prior_snapshot(p, doc, ready) == ready["successorFrameSha256"] and op.ready(rt, doc, p["readiness"]),
            "RETENTION_CANDIDATE_DRIFT")
    spec = p["migration"]["retentionAdmin019"]
    expected = {"planSha256": source, **plan[ADMIN], "status": "VERIFIED"}
    baseline = op.database_baseline(lambda: op.read(root, "database.private.json"))
    require(digest(baseline) == plan["databaseSha256"], "DATABASE_BASELINE_CHANGED")

    def verify(*, installed):
        reference, facts = catalog(rt, doc)
        require(binding(p, reference) == plan[ADMIN], "RETENTION_BINDING_DRIFT")
        rows = facts["functions"]
        routines = verified_routines(spec, rows) if installed or rows != [] else ()
        postgres.verify(rt, doc, baseline, p["migration"], migrated=True, additive_routines=routines)
        return facts

    witness = "retention-catalog.json"
    if phase == ADMIN and not (root / RECEIPT).exists():
        facts = verify(installed=False)
        cid = completed_worker(rt, doc, root, phase, facts)
        output = verified_output(rt, cid)
        require(all(output.get(k) == expected[k] for k in ("sqlSha256", "ownerAclSha256")),
                "RETENTION_OUTPUT_DRIFT")
        op.confirm(root, witness, {"cid": cid, "receiptSha256": digest(expected),
                                   "catalogSha256": digest(verify(installed=True)["functions"])})
        op.record(root, RECEIPT, expected)
    require((root / RECEIPT).is_file() and op.read(root, RECEIPT) == expected, "RETENTION_RECEIPT_DRIFT")
    admin = op.read(root, witness)
    facts = verify(installed=True)
    require(admin == {"cid": op.read(root, ADMIN + ".worker.json")["cid"],
                      "receiptSha256": digest(expected), "catalogSha256": digest(facts["functions"])}, "RETENTION_CATALOG_DRIFT")
    if phase == ADMIN:
        retire_worker(rt, root, phase, admin["cid"])
    if phase == BATCH:
        if not (root / "retention-batch.json").exists():
            cid = completed_worker(rt, doc, root, phase, facts)
            verified_output(rt, cid)
            op.record(root, "retention-batch.json", {"cid": cid, "receiptSha256": digest(expected), "status": "VERIFIED"})
        done = op.read(root, "retention-batch.json")
        require(done["receiptSha256"] == digest(expected), "RETENTION_RECEIPT_DRIFT")
        require(done.get("status") == "VERIFIED", "RETENTION_OUTPUT_UNCONFIRMED")
        retire_worker(rt, root, phase, done["cid"])
    return expected


from .contract import validate_profile_options

_run = run


def run(p, rt, source, phase, ready):
    validate_profile_options(p)
    return _run(p, rt, source, phase, ready)


run = op.public_output.release_output(run)
