"""Disposable CI PostgreSQL + actual owner migration default; no target access."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('synthetic_protocol', ROOT/'tests/test_acquisition_descriptor_publication.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
owner = fixture.SyntheticOwner()
m = fixture.m
m.BASE_RESPONSE = m.digest(owner.current)
plan = m.prepare(owner.current, owner.catalogue, time.time()+600)
text = (ROOT/'tests/fixtures/onboarding-V16-authorization-admin-lifecycle.sql').read_text()
table = text[text.index('create table ouf_authorization.policy_draft'):text.index('create table ouf_authorization.admin_audit')]
sql = "create schema ouf_authorization;\n"+table+"\n"+"""
insert into ouf_authorization.policy_draft(draft_id,state,base_active_ref,payload,created_by)
values('00000000-0000-4000-8000-000000000001','DRAFT','ouf-lab-authorization:48', :'candidate'::jsonb,'SYNTHETIC_HUMAN');
select json_build_object('id',draft_id::text,'revision',revision,'state',state,'baseActiveRef',base_active_ref,'policy',payload)
from ouf_authorization.policy_draft;
"""
result = subprocess.run(['psql',os.environ['CI_POSTGRES_URL'],'-X','-Atq','-v','ON_ERROR_STOP=1',
                         '-v','candidate='+json.dumps(plan['candidatePolicy'])],input=sql,text=True,capture_output=True,check=True)
row = json.loads(result.stdout.strip())
assert row['revision'] == 0
m.validate_draft(row, plan)
print('REAL_POSTGRES_DRAFT_REVISION_ZERO_NATIVE_VALIDATOR_PASS')
