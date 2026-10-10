#!/usr/bin/env python3
"""Exercise additive V10 and backup restoration on isolated hosted PostgreSQL, never on OUF databases."""
import hashlib, json, subprocess, tempfile, time, shutil, zipfile
import sys
from pathlib import Path
DB="ouf-discovery-migration-ci"
FLYWAY="--packaged-flyway" in sys.argv
OLD_FLYWAY="--installed-flyway" in sys.argv
JAR=Path("package/application.jar")
JAVA_ROOT=Path("package/flyway-fixture")
def flyway(mode, database, location):
    return cmd(["java","-cp",str(JAVA_ROOT)+":"+str(JAVA_ROOT/"lib/*"),"FlywayFixture",mode,database,str(location)])
def cmd(argv, data=None, ok=True):
    p=subprocess.run(argv,input=data,capture_output=True,timeout=60)
    if ok and p.returncode:raise RuntimeError("CI_FIXTURE_COMMAND_FAILED exit="+str(p.returncode)+" stderr="+p.stderr.decode(errors="replace")[:2000])
    return p
def sql(text,database="semantic",ok=True):
    return cmd(["docker","exec","-i",DB,"psql","-X","-U","postgres","-d",database,"-v","ON_ERROR_STOP=1","-A","-t"],text.encode(),ok)
source=Path("semantic-source/src/main/resources/db/migration")
try:
    cmd(["docker","run","-d","--name",DB,*(["-p","127.0.0.1:55439:5432"] if FLYWAY else []),"-e","POSTGRES_PASSWORD=ci-fixture-only","-e","POSTGRES_DB=semantic","postgres:17"])
    for _ in range(30):
        if cmd(["docker","exec",DB,"pg_isready","--host=127.0.0.1","-U","postgres","-d","semantic"],ok=False).returncode==0:break
        time.sleep(1)
    else:raise RuntimeError("POSTGRES_NOT_READY")
    qualification=json.loads(Path("evidence/discovery-remediated-application-qualification-20261009.json").read_bytes())
    frozen=qualification["migrationPlan"]["receipt"]
    actual={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.glob("*.sql")}
    if actual!=frozen["candidateMigrationDigests"]:raise RuntimeError("SIGNED_CANDIDATE_MIGRATION_BYTES_CHANGED")
    if frozen["candidateRevision"]!="403531a9df1cbc877078f8126fd1fc4ff18acea9":raise RuntimeError("SIGNED_CANDIDATE_REVISION_DRIFT")
    files=sorted(source.glob("*.sql"),key=lambda p:int(p.name.split("__")[0][1:]))
    before=[p for p in files if p.name!="V10__discovery_request_idempotency.sql"]
    if len(before)!=9:raise RuntimeError("BASELINE_MIGRATION_SET_CHANGED")
    if FLYWAY:
        JAVA_ROOT.mkdir(parents=True,exist_ok=True)
        (JAVA_ROOT/"lib").mkdir(exist_ok=True)
        with zipfile.ZipFile(JAR) as jar:
            for name, digest in actual.items():
                data=jar.read("BOOT-INF/classes/db/migration/"+name)
                if hashlib.sha256(data).hexdigest()!=digest:raise RuntimeError("PACKAGED_MIGRATION_BYTES_CHANGED")
            for name in jar.namelist():
                if name.startswith("BOOT-INF/lib/") and name.endswith(".jar"):
                    (JAVA_ROOT/"lib"/Path(name).name).write_bytes(jar.read(name))
        cmd(["javac","-cp",str(JAVA_ROOT/"lib/*"),"-d",str(JAVA_ROOT),"tests/fixtures/FlywayFixture.java"])
        baseline=JAVA_ROOT/"baseline";baseline.mkdir()
        for f in before:shutil.copyfile(f,baseline/f.name)
        flyway("migrate","semantic",baseline)
    else:
        for f in before:sql(f.read_text())
    legacy="00000000-0000-4000-8000-000000000001"
    sql("INSERT INTO ouf_sem.discovery_request(request_id,requested_artifact_type,intent,preferred_languages,state,created_by_subject) VALUES ('"+legacy+"','CLASS','retained historical theatre intent',ARRAY['it','en'],'PENDING','historical-subject');")
    query="SELECT to_jsonb(t)::text FROM (SELECT request_id,requested_artifact_type,intent,preferred_languages,provider_policy,state,attempt_count,lease_until,last_error_code,created_by_subject,created_at,completed_at FROM ouf_sem.discovery_request WHERE request_id='"+legacy+"') t;"
    legacy_before=sql(query).stdout.strip()
    dump=cmd(["docker","exec",DB,"pg_dump","-U","postgres","-d","semantic","-Fc"]).stdout
    sql("CREATE DATABASE restored;")
    cmd(["docker","exec","-i",DB,"pg_restore","-U","postgres","-d","restored","--exit-on-error"],dump)
    if sql(query,"restored").stdout.strip()!=legacy_before:raise RuntimeError("CI_BACKUP_RESTORE_CONTENT_DRIFT")
    if FLYWAY:flyway("migrate","semantic",source)
    else:sql((source/"V10__discovery_request_idempotency.sql").read_text())
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
    # A pre-V10 snapshot is historical once any writes complete after migration.
    # Restore a current migrated snapshot into a fresh database, never overwrite
    # the live fixture with the old backup. Target recovery still needs custody,
    # writer fencing and a separately authorized applicator.
    old_flyway_validation=None
    if OLD_FLYWAY:
        old=Path("old-flyway-package")
        receipt=json.loads((old/"capture-receipt.json").read_bytes())
        if receipt["imageId"]!="sha256:f6525f2512c72a600ebcbc7060d55355d86e0627487b655e7c5c6288a0be7fc6":raise RuntimeError("OLD_LIBRARY_IMAGE_DRIFT")
        for folder,field in (("lib","libraries"),("migrations","migrations")):
            digests={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (old/folder).iterdir()}
            if digests!=receipt[field]:raise RuntimeError("OLD_PACKAGE_TRANSFER_DRIFT")
        cmd(["javac","-cp",str(old/"lib/*"),"-d",str(old),"tests/fixtures/FlywayFixture.java"])
        cmd(["java","-cp",str(old)+":"+str(old/"lib/*"),"FlywayFixture","validate","restored",str(old/"migrations")])
        observed=cmd(["java","-cp",str(old)+":"+str(old/"lib/*"),"FlywayFixture","observe","semantic",str(old/"migrations")])
        statuses=[line.split(b"=",1)[1].decode() for line in observed.stdout.splitlines() if line.startswith(b"OUF_FLYWAY_VALIDATION=")]
        if len(statuses)!=1 or statuses[0] not in ("VALIDATED_WITH_CURRENT_SCHEMA","VALIDATION_DENIED"):raise RuntimeError("OLD_VALIDATION_RESULT_UNPROVEN")
        old_flyway_validation=statuses[0]
        # This is the actual installed library set, but not full Spring startup.
        # A denied legacy validator must block old-image rollback; no repair.
    all_requests="SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY request_id),'[]'::jsonb)::text FROM ouf_sem.discovery_request t;"
    current_requests=sql(all_requests).stdout.strip()
    historical_requests=sql(all_requests,"restored").stdout.strip()
    if current_requests==historical_requests:raise RuntimeError("POST_MIGRATION_WRITES_NOT_EXERCISED")
    migrated_dump=cmd(["docker","exec",DB,"pg_dump","-U","postgres","-d","semantic","-Fc"]).stdout
    sql("CREATE DATABASE restored_v10;")
    cmd(["docker","exec","-i",DB,"pg_restore","-U","postgres","-d","restored_v10","--exit-on-error"],migrated_dump)
    if FLYWAY:
        flyway("validate","restored_v10",source)
        history="SELECT version,checksum,success FROM ouf_sem.flyway_schema_history ORDER BY installed_rank;"
        if sql(history).stdout!=sql(history,"restored_v10").stdout:raise RuntimeError("FLYWAY_HISTORY_CHANGED_ON_RESTORE")
        tampered=JAVA_ROOT/"tampered";shutil.copytree(source,tampered)
        changed=next(tampered.glob("V9__*.sql"))
        changed.write_text(changed.read_text()+"\nSELECT 1;\n")
        flyway("reject","restored_v10",tampered)
        flyway("validate","restored_v10",source)
    if sql(all_requests,"restored_v10").stdout.strip()!=current_requests:raise RuntimeError("POST_MIGRATION_WRITES_LOST_ON_CURRENT_RESTORE")
    if sql("SELECT state FROM ouf_sem.discovery_request WHERE request_id='"+legacy+"';","restored_v10").stdout.strip()!=b"SUCCEEDED":
        raise RuntimeError("LEGACY_JOB_STATE_LOST_ON_CURRENT_RESTORE")
    if sql(insert(7,"actor-a",key,fingerprint),"restored_v10",ok=False).returncode==0:
        raise RuntimeError("V10_IDEMPOTENCY_CONSTRAINT_LOST_ON_RESTORE")
    sql(insert(8,"legacy-write-after-current-restore"),"restored_v10")
    sql("SELECT * FROM ouf_sem.claim_discovery_job('legacy-worker-after-current-restore',30);","restored_v10")
    if sql(all_requests).stdout.strip()!=current_requests:raise RuntimeError("RESTORE_CHANGED_LIVE_FIXTURE")
    print("OUF_DISCOVERY_MIGRATION_RECOVERY_CI="+json.dumps({"status":"PASS","postgresVersion":"17","baselineMigrations":9,"additiveMigration":"V10__discovery_request_idempotency.sql","historicalContentPreserved":True,"legacyWritesAfterMigration":True,"legacyClaimCompleteFunctions":True,"perActorIdempotencyEnforced":True,"baselineBackupRestoredAndCompared":True,"exactRemediatedMigrationBytesVerified":True,"currentV10SnapshotRestoredWithPostMigrationWrites":True,"baselineSnapshotDiffersAfterWrites":True,"restoredV10IdempotencyConstraintRetained":True,"legacyWritesAndClaimAfterCurrentRestore":True,"liveFixtureUnchangedByCurrentRestore":True,"packagedCandidateFlywayExercised":FLYWAY,"packagedMigrationBytesVerified":FLYWAY,"restoredFlywayHistoryValidated":FLYWAY,"checksumDriftRejectedWithoutRepair":FLYWAY,"installedFlywayValidationOnV10":old_flyway_validation,"installedApplicationLibraryBytesExercised":OLD_FLYWAY,"oldApplicationRuntimeQualified":False,"fullSpringStartupQualified":False,"targetDatabaseTouched":False,"targetBackupPerformed":False}))
finally:
    cmd(["docker","rm","-f",DB],ok=False)
