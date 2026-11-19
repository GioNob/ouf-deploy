#!/usr/bin/env python3
"""Installation-specific bounded metadata read using existing runner access only."""
import json
import os
import re
import subprocess
import sys

SUBJECT = 'b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'
TENANT = 'ouf-lab'
COMMAND = 'linked-property-v1:teatri-csv-6609b245:9860853e'
PG_ID = '50b36d71620ad00fee1bae45aaf0bf652b9171dc09f567fa552798daf12614ea'
PG_IMAGE = 'sha256:894f570c0cf0664ed5576a8fd5d5bfb8fb1b19d592885b686c3a88c8bd90c41f'
MCP_ID = 'c6fc3a462f4e1faf1e8121fee13ca445f7a3f7f1f39df65d738ea9cc1d4185f4'
MCP_REVISION = 'a79b139c7a26d64a584b0a432ebb8df8c32a52ed'
ONB_ID = '3197c8d5ae9acc00a2e99d54bc969db1d199623960b5efed09c891ba0a3138c8'
ONB_REVISION = 'be388e1462778438a208c2e00e166370fee32189'
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'DOCKER_HOST': 'unix:///var/run/docker.sock', 'DOCKER_API_VERSION': '1.44'}
FORMAT = '{"id":{{json .Id}},"image":{{json .Image}},"state":{{json .State}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}}}'
HEADER = "BEGIN READ ONLY; SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s'; "

def require(ok, code):
    if not ok:
        raise ValueError(code)

def query(database):
    require(database in ('ouf_mcp', 'ouf_onboarding'), 'CLOSED_DATABASE_SELECTION_REQUIRED')
    if database == 'ouf_mcp':
        # No arguments, raw evidence, fingerprints, tokens or HUMAN journal rows.
        sql = f"""
WITH windows AS (
 SELECT * FROM ouf_mcp.budget_window
 WHERE principal_id='{SUBJECT}' AND tenant_id='{TENANT}'
 AND window_start >= '2026-10-19T07:35:00Z'::timestamptz
 AND window_start < '2026-10-19T08:35:00Z'::timestamptz
 ORDER BY window_start DESC,budget_window_id LIMIT 20
), attempts AS (
 SELECT * FROM ouf_mcp.tool_attempt
 WHERE principal_id='{SUBJECT}' AND tenant_id='{TENANT}'
 AND admitted_at >= '2026-10-19T07:35:00Z'::timestamptz
 AND capability_id IN ('ouf.onboarding.revision.read','ouf.onboarding.revision.prepare')
 ORDER BY admitted_at DESC,attempt_id LIMIT 12
)
SELECT jsonb_build_object(
 'database',current_database(),'transactionReadOnly',current_setting('transaction_read_only')='on',
 'windows',coalesce((SELECT jsonb_agg(jsonb_build_object(
 'start',w.window_start,'end',w.window_end,'expired',w.window_end<=clock_timestamp(),
 'controlWindow',w.policy_ref LIKE '%:ouf.operational-control-budget.v1',
 'consumedCalls',w.consumed_tool_calls,'reservedCalls',w.reserved_tool_calls,
 'consumedBytes',w.consumed_result_bytes,'reservedBytes',w.reserved_result_bytes,
 'consumedObjects',w.consumed_distinct_objects,'reservedObjects',w.reserved_distinct_objects,
 'limitCalls',w.limit_tool_calls,'limitBytes',w.limit_result_bytes,'limitObjects',w.limit_distinct_objects,
 'activeObjectDebt',(SELECT coalesce(sum(d.debt_amount),0) FROM ouf_mcp.budget_object_debt d WHERE d.budget_window_id=w.budget_window_id AND d.debt_state='ACTIVE'),
 'exceedsRevisionEnvelope',w.reserved_tool_calls+w.consumed_tool_calls+1>3 OR w.reserved_result_bytes+w.consumed_result_bytes+65536>196608 OR w.reserved_distinct_objects+w.consumed_distinct_objects+(SELECT coalesce(sum(d.debt_amount),0) FROM ouf_mcp.budget_object_debt d WHERE d.budget_window_id=w.budget_window_id AND d.debt_state='ACTIVE')+1>3
 )) FROM windows w),'[]'::jsonb),
 'revisionAttempts',coalesce((SELECT jsonb_agg(jsonb_build_object('capability',a.capability_id,'admittedAt',a.admitted_at,'state',a.state,'dispatchState',a.dispatch_state,'originalCommand',a.idempotency_key='{COMMAND}')) FROM attempts a),'[]'::jsonb)
);"""
    else:
        sql = f"""
WITH active AS (
 SELECT b.version,b.bundle_payload FROM ouf_authorization.active_policy_bundle a
 JOIN ouf_authorization.policy_bundle b ON b.bundle_id=a.bundle_id AND b.version=a.version WHERE a.singleton_key=true
)
SELECT jsonb_build_object(
 'database',current_database(),'transactionReadOnly',current_setting('transaction_read_only')='on',
 'activeBundleCount',(SELECT count(*) FROM active),'activePolicyVersion',(SELECT version FROM active),
 'ingestionOperationsRegistered',(SELECT count(*) FROM ouf_authorization.capability_registration WHERE capability_id='ingestion.operations.read'),
 'ingestionOperationsActive',(SELECT count(*) FROM active CROSS JOIN LATERAL jsonb_array_elements(bundle_payload->'capabilities') c WHERE c->>'capabilityId'='ingestion.operations.read'),
 'ingestionOperationsDescriptor',(SELECT descriptor FROM ouf_authorization.capability_registration WHERE capability_id='ingestion.operations.read'),
 'nominalIngestionOperationsGrants',(SELECT count(*) FROM active CROSS JOIN LATERAL jsonb_array_elements(bundle_payload->'grants') g WHERE g->>'capabilityId'='ingestion.operations.read' AND g->>'tenantId'='{TENANT}' AND g->>'subjectId'='{SUBJECT}')
);"""
    return HEADER + sql + ' ROLLBACK;'

def call(arguments, maximum=131072):
    # run() drains both pipes; output is never forwarded, including stderr.
    r = subprocess.run(['/usr/bin/docker'] + arguments, input=None, stdin=subprocess.DEVNULL,
                       capture_output=True, timeout=12, env=ENV)
    require(r.returncode == 0, 'NATIVE_METADATA_READ_FAILED')
    require(len(r.stdout) <= maximum and len(r.stderr) <= maximum, 'NATIVE_METADATA_OUTPUT_LIMIT')
    return r.stdout

def inspect(identifier):
    value = json.loads(call(['inspect', '--type', 'container', '--format', FORMAT, identifier], 32768))
    require(value['id'] == identifier and value['state']['Running'] is True and value['state']['Paused'] is False
            and value['state']['Restarting'] is False, 'EXACT_RUNNING_CONTAINER_REQUIRED')
    # Project only fixed state fields; .State.Error is deliberately not emitted.
    return {k: value[k] for k in ('id', 'image', 'revision')} | {
        'pid': value['state']['Pid'], 'startedAt': value['state']['StartedAt']}

def validate(database, result):
    require(result.get('database') == database and result.get('transactionReadOnly') is True, 'READ_ONLY_DATABASE_IDENTITY_REQUIRED')
    if database == 'ouf_mcp':
        require(set(result) == {'database','transactionReadOnly','windows','revisionAttempts'}, 'CLOSED_MCP_RESULT_REQUIRED')
        require(len(result['windows']) <= 20 and len(result['revisionAttempts']) <= 12, 'METADATA_ROW_LIMIT')
        window_keys = {'start','end','expired','controlWindow','consumedCalls','reservedCalls','consumedBytes','reservedBytes','consumedObjects','reservedObjects','limitCalls','limitBytes','limitObjects','activeObjectDebt','exceedsRevisionEnvelope'}
        attempt_keys = {'capability','admittedAt','state','dispatchState','originalCommand'}
        require(all(set(w)==window_keys for w in result['windows']) and all(set(a)==attempt_keys for a in result['revisionAttempts']), 'CLOSED_MCP_ROW_REQUIRED')
    else:
        require(set(result) == {'database','transactionReadOnly','activeBundleCount','activePolicyVersion','ingestionOperationsRegistered','ingestionOperationsActive','ingestionOperationsDescriptor','nominalIngestionOperationsGrants'}, 'CLOSED_AUTHORIZATION_RESULT_REQUIRED')
        require(result['activeBundleCount'] == 1 and result['ingestionOperationsRegistered'] in (0,1), 'SINGLE_ACTIVE_POLICY_REQUIRED')
        descriptor = result['ingestionOperationsDescriptor']
        if descriptor is not None:
            require(isinstance(descriptor,dict) and descriptor.get('capabilityId') == 'ingestion.operations.read', 'EXACT_DESCRIPTOR_REQUIRED')
    return result

def collect():
    before = {identifier: inspect(identifier) for identifier in (PG_ID, MCP_ID, ONB_ID)}
    require(before[PG_ID]['image'] == PG_IMAGE and before[MCP_ID]['revision'] == MCP_REVISION
            and before[ONB_ID]['revision'] == ONB_REVISION, 'REVIEWED_INSTALLATION_REQUIRED')
    # Select only the public POSTGRES_USER setting, never all Env or password values.
    fmt = '{{range .Config.Env}}{{if eq (index (split . "=") 0) "POSTGRES_USER"}}{{println .}}{{end}}{{end}}'
    raw = call(['inspect','--type','container','--format',fmt,PG_ID], 256).decode().strip()
    require(re.fullmatch(r'POSTGRES_USER=[A-Za-z_][A-Za-z0-9_]{0,62}',raw) is not None, 'EXISTING_DATABASE_ADMIN_REQUIRED')
    admin = raw.split('=',1)[1]
    facts = {}
    for database in ('ouf_mcp','ouf_onboarding'):
        raw = call(['exec',PG_ID,'env','PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000',
                    'timeout','-s','KILL','8','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,'-d',database,'-c',query(database)], 65536)
        facts[database] = validate(database, json.loads(raw))
    require(before == {identifier: inspect(identifier) for identifier in before}, 'GENERATION_CHANGED_DURING_READ')
    return facts

def main():
    report = {'schema':'ouf.cloud-admission-policy-metadata-read.v1','installationSpecific':True,
              'readOnly':True,'databaseMutations':0,'credentialFilesRead':0,'humanJournalsRead':0,
              'tokensRead':0,'serviceMutations':0,'automaticRetry':False,'budgetReset':False,
              'maximumSqlSessions':2,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
    try:
        report.update(complete=True,facts=collect())
    except Exception as error:
        code = str(error)
        report.update(complete=False,reason=code if type(error) is ValueError and re.fullmatch('[A-Z_]+',code) else type(error).__name__,exceptionMessagePrinted=False)
    print(json.dumps(report,sort_keys=True))
    return 0 if report['complete'] else 1

if __name__ == '__main__':
    sys.exit(main())
