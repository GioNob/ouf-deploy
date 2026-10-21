"""Disposable PostgreSQL owner-schema qualification. Never targets the VPS."""
import json
from pathlib import Path
import subprocess
import uuid
import os

ROOT=Path(__file__).resolve().parents[1]
proposal=json.loads((ROOT/'releases/teatri-native-semantic-proposal-20261013.json').read_text())
if os.environ.get('OUF_DISPOSABLE_POSTGRES')!='1':raise SystemExit('DISPOSABLE_OWNER_SCHEMA_REQUIRED')
def quote(value):return "'"+str(value).replace("'","''")+"'"
def execute(statement):
    result=subprocess.run(['psql','--no-psqlrc','-X','-tA','-v','ON_ERROR_STOP=1'],input=statement,text=True,
                          capture_output=True,check=True)
    return result.stdout.strip()
def insert(command,suffix):
    artifact=uuid.uuid5(uuid.NAMESPACE_URL,'ouf-disposable-teatri-artifact:'+suffix)
    revision=uuid.uuid5(uuid.NAMESPACE_URL,'ouf-disposable-teatri-revision:'+suffix)
    execute('INSERT INTO ouf_sem.semantic_artifact(artifact_id,semantic_id,artifact_type,namespace,local_name,owner_ref,authority_ref,origin_kind) VALUES('+','.join(map(quote,[artifact,command['semanticId'],command['artifactType'],command['namespace'],command['localName'],'fixture-owner','fixture-authority','OUF']))+');'+
        'INSERT INTO ouf_sem.artifact_revision(revision_id,artifact_id,revision_no,lifecycle_status,semantic_version,label_json,definition_json,created_by_subject) VALUES('+','.join([quote(revision),quote(artifact),'1',quote('DRAFT'),quote(command['semanticVersion']),quote(json.dumps(command['labels']))+'::jsonb',quote(json.dumps(command['definition']))+'::jsonb',quote('AI_AGENT_FIXTURE')])+');')
    return revision
revisions=[insert(c,c['semanticId']) for c in proposal['nativeDraftCommands']]
passed=warnings=0
for revision in revisions:
    run=execute("SELECT ouf_sem.validate_revision("+quote(revision)+"::uuid,'AI_AGENT_FIXTURE');")
    row=json.loads(execute('SELECT row_to_json(v) FROM ouf_sem.validation_run v WHERE validation_run_id='+quote(run)+'::uuid;'))
    # The owner's native creation DTO has no description_json field. Preserve
    # and expose this warning; do not pretend the definition text removes it.
    if row['status']!='PASS' or row['error_count']!=0:raise SystemExit('OWNER_NATIVE_VALIDATION_FAILED')
    passed+=1;warnings+=row['warning_count']
    if execute('SELECT count(*) FROM ouf_sem.validation_issue WHERE validation_run_id='+quote(row['validation_run_id'])+"::uuid AND (severity<>'WARN' OR rule_id<>'VAL-008');")!='0':
        raise SystemExit('UNEXPECTED_OWNER_WARNING')
base=dict(proposal['nativeDraftCommands'][1]);base['semanticId']+='FixtureNegative';base['localName']+='FixtureNegative'
base['definition']={**base['definition'],'domainRefs':['urn:ouf:disposable:unresolved-class']}
invalid=insert(base,'negative-unresolved')
negative_run=execute("SELECT ouf_sem.validate_revision("+quote(invalid)+"::uuid,'AI_AGENT_FIXTURE');")
failed=execute('SELECT status FROM ouf_sem.validation_run WHERE validation_run_id='+quote(negative_run)+'::uuid;')
if failed!='FAIL':raise SystemExit('OWNER_UNRESOLVED_DOMAIN_ACCEPTED')
if execute("SELECT count(*) FROM ouf_sem.artifact_revision WHERE lifecycle_status<>'DRAFT';")!='0':raise SystemExit('UNAUTHORIZED_LIFECYCLE_EFFECT')
if execute('SELECT count(*) FROM ouf_sem.approval_decision;')!='0':raise SystemExit('UNAUTHORIZED_APPROVAL_EFFECT')
print('OUF_TEATRI_NATIVE_OWNER_SQL='+json.dumps({'validatedNativeDrafts':passed,'errors':0,'warnings':warnings,
    'warningsPreserved':True,'unresolvedDomainDenied':True,'allFixtureRevisionsRemainDraft':True,
    'productionOwnerRequests':0,'humanDecisionsIssued':0,'csvRunsIssued':0,'notReleaseAcceptance':True},sort_keys=True))
