"""Disposable CI bootstrap; synthetic consent only, never a target launcher."""
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import time

v=json.loads(sys.stdin.buffer.read(8388609))
loader=base64.b64decode(v['loader'],validate=True)
sources={n:base64.b64decode(b,validate=True)for n,b in v['sources'].items()}
namespace={'__name__':'verified_native_loader'}
exec(compile(loader,'<verified-native-loader>','exec'),namespace)
entry,manifest=namespace['load_entry'](v['commit'],sources,loader,v['approvedDeclarationHash'],v['sourcePins'])
a=entry.authority;c=entry.c
b=v['nativeReview']['humanBinding']
human=a.human_reader.existing.HumanSession(v['selection'],b['sessionDirectory'],b['tokenPath'],b['expiresAt'])
library=a.stdlib_binding()
closure={'declaration':manifest,'executables':v['executables'],'stdlibHash':c.digest(library),'stdlibFileCount':len(library['fileHashes'])}
qualification={'schema':'ouf.ingestion-rollout-native-qualification.v1','sourceCommit':v['commit'],
    'sourceHashes':manifest['sourceHashes'],'candidateNativeImageId':v['packet']['candidate']['nativeImageId'],
    'candidateSourceCommit':v['packet']['candidate']['sourceCommit'],'results':dict.fromkeys(a.QUALIFICATION,'PASS'),
    'runtimeAuthorityIssued':False,'notReleaseAcceptance':True,
    'evidenceRefs':{k:{'repository':'synthetic/isolated-ci-bootstrap-only','runId':1,'jobId':1,'sourceCommit':v['commit']}for k in a.QUALIFICATION}}
review=a.compile_action_review(v['nativeReview'],v['packet'],closure,v['issuer'],qualification,900)
now=int(time.time());decision={'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':c.digest(review),
    'approvalRef':'mcp-scoped-'+c.digest(review)[:24]+'-'+str(now),'sourceClosureHash':review['sourceClosureHash'],
    'humanSessionHash':c.digest(review['authenticatedHuman']),'approvedAt':now,'expiresAt':now+900,
    'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
context=Path(review['authorityDirectory']);selected=context/'review.json'
with selected.open('xb')as stream:stream.write(c.encoded(review))
selected.chmod(0o600)
try:
    a.issue_action(review,decision,human,c.digest(decision))
    mandate_hash=hashlib.sha256((context/'human.json').read_bytes()).hexdigest()
    action=entry.load_action(review,decision,human,c.digest(decision),mandate_hash)
    entry.execute('initialize',review,v['packet'],human,action,manifest)
    journal=entry.Journal(context)
    for index,stage in enumerate(v['nativeReview']['stages']):
        while journal.read()['nextStage']==index:
            try:entry.execute('step',review,v['packet'],human,action,manifest)
            except c.Paused:
                row=journal.read()
                if row['readState']!='RETRY_WAIT':raise
                delay=max(row['nextReadAt']-time.time(),row['nextReadMonotonic']-time.monotonic())
                time.sleep(max(0,delay)+.01)
    result=entry.execute('step',review,v['packet'],human,action,manifest)
    assert result['complete']and result['functionalMilestonesProven']==4 and not result['releaseAcceptance']
    print(json.dumps({'sealedEntrySequenceComplete':True,'moduleCount':manifest['moduleCount'],
        'syntheticConsentAndQualification':True,'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}))
except BaseException as error:
    reason=str(error)
    print(json.dumps({'sealedEntrySequenceComplete':False,'errorType':type(error).__name__,
        'reasonCode':reason if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason)else'NON_CODE_ERROR_REDACTED'}))
    sys.exit(2)
