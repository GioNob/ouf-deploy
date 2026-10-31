"""Real nonroot audit hook and fixed child; all retained facts are synthetic."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('synthetic_retained',ROOT/'tests/test_descriptor_publication_retained_stop.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
m = fixture.m
assert os.geteuid() != 0
os.umask(0o077)
temporary = tempfile.TemporaryDirectory()
context = Path(temporary.name)/'retained'
context.mkdir(mode=0o700)
code = Path(sys.argv[1])
grants = [{'grantId':str(n),'validFrom':'2026-01-01T00:00:00Z','private':'SYNTHETIC_CANARY'} for n in range(106)]
candidate = {'bundleId':'ouf-lab-authorization','version':49,'publishedAt':'2026-10-25T19:40:00Z','capabilities':[], 'grants':grants}
review = {'candidatePolicy':candidate,'baselineGrantCount':106,'baselineGrantsHash':m.digest(grants),
          'activatedDescriptorIds':list(m.CAPS),'newGrants':0,'roleCatalogueMutations':0}
review_hash = m.digest(review)
state = {'reviewHash':review_hash,'humanReviewApproved':True,'state':'STOP_RECONCILE',
         'budgetReset':False,'automaticReplayAllowed':False,'effects':{'REGISTER:'+cap:{'state':'APPLIED','bodyHash':'a'*64} for cap in m.CAPS},
         'counts':{'ownerGets':5,'administrativeWrites':6,'previewPosts':0,'bytes':1000},'reads':{}}
state['effects']['CREATE_DRAFT'] = {'state':'CLAIMED','bodyHash':m.digest(candidate)}
for name,value in (('review.json',review),('state.json',state)):
    (context/name).write_text(json.dumps(value))
    (context/name).chmod(0o600)
original_observe = m.observe
m.CONTEXT, m.CODE = str(context), str(code)
m.observe = lambda: original_observe(context,code,owner=os.geteuid(),expected_review=review_hash)
# Fixture-only substitutions before installing the real audit hook; production CLI has no selectors.
sys.argv = ['synthetic-retained-reader']
m.main()
for action in (lambda:socket.socket(), lambda:open(context/'state.json','w'), lambda:os.chmod(context/'state.json',0o777)):
    try:
        action()
    except m.Stop:
        pass
    else:
        raise AssertionError('real audit boundary did not reject the operation')
try:
    m.main()
except m.Stop as error:
    assert str(error) == 'RETAINED_READ_SCOPE_CONSUMED_NO_REPLAY'
else:
    raise AssertionError('diagnostic child replay allowed')
print('REAL_NONROOT_AUDIT_AND_NO_REPLAY_PASS',flush=True)
# Avoid cleanup enumeration after installing the deliberately restrictive audit hook.
os._exit(0)
