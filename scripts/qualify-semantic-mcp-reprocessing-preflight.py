#!/usr/bin/env python3
"""Synthetic PostgreSQL 17 qualification only; never a deployment action."""
import importlib.util,json,os,subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('preflight',root/'scripts/read-chatbot-semantic-mcp-reprocessing-preflight-20261016.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert os.environ.get('OUF_SYNTHETIC_PREFLIGHT_QUALIFICATION')=='POSTGRESQL17_FIXTURE_ONLY'
dsn=os.environ['MCP_TEST_DATABASE_URL']
def sql(text):
 p=subprocess.run(['psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',dsn,'-c',text],capture_output=True,timeout=20)
 assert p.returncode==0,'SYNTHETIC_SQL_QUALIFICATION_FAILED'
 assert len(p.stdout)<=65536 and len(p.stderr)<=65536
 return p.stdout.decode().strip()
identity=json.loads(sql("SELECT json_build_object('database',current_database(),'user',current_user,'oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'version',current_setting('server_version_num')::int)"))
assert identity['database']=='preflight_fixture' and identity['user']=='mcp' and 170000<=identity['version']<180000
sql("CREATE ROLE fixture_application NOLOGIN NOSUPERUSER NOCREATEROLE; GRANT USAGE,CREATE ON SCHEMA ouf_mcp TO fixture_application; GRANT INSERT ON ouf_mcp.schema_migration TO fixture_application; GRANT REFERENCES ON ouf_mcp.tool_attempt,ouf_mcp.budget_window TO fixture_application")
def observe():
 facts=json.loads(sql(m.query('fixture',identity['database'],identity['user'],'fixture_application')))
 return m.project(facts,{'databaseOid':identity['oid']})
facts=observe();p=facts['preflight']
assert facts['readOnly'] and facts['claimCount']==0 and p['migrationCount']==12
for key in ('applicationRoleExists','applicationCanCreateInSchema','applicationCanInsertMigration',
 'applicationCanReferenceAttempts','applicationCanReferenceWindows','applicationCanExecuteImmutableTrigger',
 'retentionRoleExists','retentionRoleNoLogin','retentionFunctionOwnedByRetentionRole','newSessionTableAbsent'):
 assert p[key]is True,key
for key in ('applicationSuperuser','applicationCreateRole','retentionRoleSuperuser','applicationCanSetRetentionRole','applicationCanUseRetentionRole'):
 assert p[key]is False,key
assert p['retentionRoleMembers']==0
sql('GRANT ouf_mcp_retention_owner TO fixture_application')
p=observe()['preflight'];assert p['applicationCanSetRetentionRole']is True and p['applicationCanUseRetentionRole']is True and p['retentionRoleMembers']==1
sql('REVOKE ouf_mcp_retention_owner FROM fixture_application')
assert observe()['preflight']['retentionRoleMembers']==0
print(json.dumps({'schema':'ouf.mcp-reprocessing-preflight-synthetic-qualification.v1','postgresMajor':17,'nativeReadOnlyQueryPassed':True,'unmodifiedTwelveMigrationPrefixPassed':True,'temporaryMembershipVisibilityPassed':True,'targetOperations':0}))
