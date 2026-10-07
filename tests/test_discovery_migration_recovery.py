#!/usr/bin/env python3
"""Exercise additive V10 and backup restoration on isolated hosted PostgreSQL, never on OUF databases."""
import json, subprocess, tempfile, time
from pathlib import Path
DB="ouf-discovery-migration-ci"
def cmd(argv, data=None, ok=True):
    p=subprocess.run(argv,input=data,capture_output=True,timeout=60)
    if ok and p.returncode:raise RuntimeError("CI_COMMAND_FAILED")
    return p
def sql(text,database="semantic",ok=True):
    return cmd(["docker","exec","-i",DB,"psql","-X","-U","postgres","-d",database,"-v","ON_ERROR_STOP=1","-A","-t"],text.encode(),ok)
source=Path("semantic-source/src/main/resources/db/migration")
try:
    cmd(["docker","run","-d","--name",DB,"-e","POSTGRES_PASSWORD=ci-fixture-only","-e","POSTGRES_DB=semantic","postgres:17"])
    for _ in range(30):
        if cmd(["docker","exec",DB,"pg_isready","-U","postgres","-d","semantic"],ok=False).returncode==0:break
        time.sleep(1)
    else:raise RuntimeError("POSTGRES_NOT_READY")
    files=sorted(source.glob("*.sql"),key=lambda p:int(p.name.split("__")[0][1:]))
    before=[p for p in files if p.name!="V10__discovery_request_idempotency.sql"]
    if len(before)!=9:raise RuntimeError("BASELINE_MIGRATION_SET_CHANGED")
    for f in before:sql(f.read_text())
    legacy="00000000-0000-4000-8000-000000000001"
    sql("INSERT INTO ouf_sem.discovery_request(request_id,requested_artifact_type,intent,preferred_languages,state,created_by_subject) VALUES ('"+legacy+"','CLASS','retained historical theatre intent',ARRAY['it','en'],'PENDING','historical-subject');")
    query="SELECT to_jsonb(t)::text FROM (SELECT request_id,requested_artifact_type,intent,preferred_languages,provider_policy,state,attempt_count,lease_until,last_error_code,created_by_subject,created_at,completed_at FROM ouf_sem.discovery_request WHERE request_id='"+legacy+"') t;"
    legacy_before=sql(query).stdout.strip()
    dump=cmd(["docker","exec",DB,"pg_dump","-U","postgres","-d","semantic","-Fc"]).stdout
    sql("CREATE DATABASE restored;")
    cmd(["docker","exec","-i",DB,"pg_restore","-U","postgres","-d","restored","--exit-on-error"],dump)
    if sql(query,"restored").stdout.strip()!=legacy_before:raise RuntimeError("CI_BACKUP_RESTORE_CONTENT_DRIFT")
    sql((source/"V10__discovery_request_idempotency.sql").read_text())
    if sql(query).stdout.strip()!=legacy_before:raise RuntimeError("V10_CHANGED_HISTORICAL_REQUEST")
    key="a"*64;fingerprint="b"*64
    def insert(i,actor,key_hash=None,fp=None):
        extras="" if key_hash is None else ",idempotency_key_hash,request_fingerprint"
        values="" if key_hash is None else ",'"+key_hash+"','"+fp+"'"
        return "INSERT INTO ouf_sem.discovery_request(request_id,requested_artifact_type,intent,state,created_by_subject"+extras+") VALUES ('00000000-0000-4000-8000-"+str(i).zfill(12)+"','CLASS','fixture','PENDING','"+actor+"'"+values+");"
    sql(insert(2,"legacy-write-after-v10"))
    sql(insert(3,"actor-a",key,fingerprint))
    if sql(insert(4,"actor-a",key,fingerprint),ok=False).returncode==0:raise RuntimeError("DUPLICATE_KEY_NOT_REJECTED")
    sql(insert(5,"actor-b",key,fingerprint))
    if sql(insert(6,"actor-c","invalid",fingerprint),ok=False).returncode==0:raise RuntimeError("INVALID_HASH_NOT_REJECTED")
    sql("SELECT * FROM ouf_sem.claim_discovery_job('legacy-worker',30);")
    sql("SELECT ouf_sem.complete_discovery_job('"+legacy+"',true,NULL);")
    if sql("SELECT state FROM ouf_sem.discovery_request WHERE request_id='"+legacy+"';").stdout.strip()!=b"SUCCEEDED":raise RuntimeError("LEGACY_JOB_FUNCTION_BROKEN_AFTER_V10")
    print("OUF_DISCOVERY_MIGRATION_RECOVERY_CI="+json.dumps({"status":"PASS","postgresVersion":"17","baselineMigrations":9,"additiveMigration":"V10__discovery_request_idempotency.sql","historicalContentPreserved":True,"legacyWritesAfterMigration":True,"legacyClaimCompleteFunctions":True,"perActorIdempotencyEnforced":True,"baselineBackupRestoredAndCompared":True,"targetDatabaseTouched":False,"targetBackupPerformed":False}))
finally:
    cmd(["docker","rm","-f",DB],ok=False)
