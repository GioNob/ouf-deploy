"""Disposable PG17 proves the exact read-only query; no production profile."""
import importlib.util,json,os,pathlib,shutil,subprocess
ROOT=pathlib.Path(__file__).parents[1]
s=importlib.util.spec_from_file_location('unit',ROOT/'tests/test_onboarding_diagnostic_state_fence.py');u=importlib.util.module_from_spec(s);s.loader.exec_module(u);f=u.f
cid=os.environ['CI_POSTGRES_ID'];assert len(cid)==64
docker=shutil.which('docker');assert docker
def psql(sql):
    return subprocess.check_output([docker,'exec',cid,'psql','-X','-w','-q','-A','-t','-U','postgres','-d','postgres','-c',sql],text=True,timeout=20).strip()
psql('CREATE SCHEMA ouf_onboarding;')
for table in f.TABLES:
    if table=='file_profile_job':ddl='job_id uuid,asset_id uuid,state text,attempts integer,profile_id uuid'
    elif table=='managed_onboarding_review':ddl='id integer,readiness_lease_until timestamptz,readiness_phase text'
    else:ddl='id integer,payload text'
    psql('CREATE TABLE ouf_onboarding.'+table+'('+ddl+');')
psql('CREATE TABLE ouf_onboarding.flyway_schema_history(installed_rank integer,version text,script text,checksum integer,success boolean,type text);')
for n,row in enumerate(u.MIGRATIONS,1):
    assert row['version'].isdigit()and row['script'].replace('_','').replace('.','').isalnum()
    psql("INSERT INTO ouf_onboarding.flyway_schema_history VALUES(%d,'%s','%s',%d,true,'SQL')"%(n,row['version'],row['script'],row['flywayChecksum']))
psql("INSERT INTO ouf_onboarding.file_profile_job VALUES('%s','%s','FAILED',5,NULL)"%(f.JOB,f.ASSET))
psql("INSERT INTO ouf_onboarding.source VALUES(1,'PRIVATE_SOURCE_CANARY');INSERT INTO ouf_onboarding.managed_onboarding_review VALUES(1,NULL,'ACTIVE');")
profile={'schema':'ouf.current-onboarding-database-snapshot-profile.v1','identity':{'database':'postgres','databaseOid':int(psql("SELECT oid FROM pg_database WHERE datname='postgres'")),'adminRole':'postgres','runtimeRole':'postgres','postgresPort':5432},'postgresRuntimeBinding':{'containerId':cid},'engineBinding':{'socketPath':str(pathlib.Path('/var/run/docker.sock').resolve())},'dockerExecutable':{'path':docker},'containerPrograms':{'env':'/usr/bin/env','timeout':'/usr/bin/timeout','psql':'/usr/bin/psql'},'unixSocketDirectory':'/var/run/postgresql'}
empty=ROOT/'ci-empty-docker';empty.mkdir(mode=0o700)
def read():
    raw=subprocess.check_output(f.arguments(profile,empty,f.query()),text=True,timeout=20)
    assert 'PRIVATE_SOURCE_CANARY' not in raw
    return json.loads(raw)
before=read();assert f.validate(before,profile,u.MIGRATIONS)['retainedFailedJobUnchanged'];f.validate(read(),profile,u.MIGRATIONS,before)
psql("UPDATE ouf_onboarding.file_profile_job SET state='READY'")
try:f.validate(read(),profile,u.MIGRATIONS);raise AssertionError('pending job admitted')
except f.StateFenceDenied:pass
psql("UPDATE ouf_onboarding.file_profile_job SET state='FAILED';UPDATE ouf_onboarding.source SET payload='CHANGED';")
try:f.validate(read(),profile,u.MIGRATIONS,before);raise AssertionError('source drift accepted')
except f.StateFenceDenied:pass
print('REAL_PG17_READ_ONLY_OWNER_FENCE_AND_NEGATIVES_PASS')
