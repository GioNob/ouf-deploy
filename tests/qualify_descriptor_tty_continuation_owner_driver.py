"""CI adapter: real owner HTTP bridge + synthetic trusted principal/TTY approval.

Never imported/executed by production. No real IAM or target credentials.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time

spec=importlib.util.spec_from_file_location('real_owner_residual_client',Path(__file__).resolve().parents[1]/'scripts/continue-existing-descriptor-publication-tty-20261026.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
fixture=json.loads(Path(sys.argv[1]).read_text());mode=sys.argv[2]
m.ADMIN=fixture['origin']
m.DRAFT_ID=fixture['draft']['id']
candidate=fixture['draft']['policy']
m.CANDIDATE_HASH=m.digest(candidate)
m.BASE_RESPONSE=m.digest(fixture['active'])
m.BASE_HASH=fixture['active']['contentHash'].removeprefix('sha256:')
old={'baselineCapabilitiesHash':m.digest(fixture['active']['policy']['capabilities'])}
with tempfile.TemporaryDirectory() as tmp:
    j=m.Journal(Path(tmp)/'one-ci-residual')
    t=m.Transport('CI_SYNTHETIC_PRINCIPAL_NOT_IAM',j)
    j.row['retainedInitialPreview']=fixture['initialPreview']
    plan=m.prepare(candidate,old,j,t,time.time()+180)
    assert plan['initialOwnerPreview']['revision']==0
    master,slave=os.openpty()
    try:
        # Explicitly synthetic test approval, isolated from real production UUID/hash.
        command='APPROVO '+m.digest(plan)+(' extra' if mode=='decline' else '')+'\n'
        os.write(master,command.encode())
        try:
            m.approve(plan,j,t,fd=slave,emit=lambda _:None)
            result=m.execute(plan,j,t)
        except m.Stop:
            assert mode in ('decline','lost'), 'unexpected stop from actual owner'
            result={'complete':False,'counts':t.counts,'effects':j.row['effects']}
        else:
            assert mode=='success'
            assert result['counts']['administrativeWrites']==7
            assert result['counts']['previewPosts']==2
            assert result['candidateGrantCount']==106 and result['allGrantsPreserved']
        if mode=='decline':
            assert t.counts['administrativeWrites']==6 and 'PUBLISH_DRAFT' not in j.row['effects']
        elif mode=='lost':
            assert t.counts['administrativeWrites']==7 and j.row['effects']['PUBLISH_DRAFT']['state']=='CLAIMED'
            try:m.execute(plan,j,t)
            except m.Stop:pass
            else:raise AssertionError('lost publication replayed')
        else:
            response=json.loads((j.path/'owner-publish-response.json').read_text())
            assert response['etag']=='"1"' and json.loads(response['bodyUtf8'])['revision']==1
        print('ACTUAL_OWNER_TTY_CONTINUATION_'+mode.upper()+'_PASS',flush=True)
    finally:os.close(master);os.close(slave)
