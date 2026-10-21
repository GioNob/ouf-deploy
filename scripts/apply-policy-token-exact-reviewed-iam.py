"""Exact target review: explicit current terminal HUMAN witness, one finite IAM action."""
import base64
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess

CAPSULE_COMMIT='1aa054279ad2d4f21bc27b65585be7dc40cb6f79'
CAPSULE_SHA='e6fe660992f5f018975de73aaf9c83dfe4df9036620257735a5f59b7cf60379d'
CAPSULE_PATH='releases/policy-token-iam-action-source-capsule-20261013.json'
REVIEW_HASH='8bbc31ce396711acf94ebbc6b541ba60cd99d715315c29736ab697b62b6f78bc'
CLOSURE_HASH='bf9c2aad3ff684a9e2b8fced56d7c0e76e0e7647e7309dc66739d5be3e6db4e6'
ROOT_BODY=r'''
import base64,hashlib,json,os,re,sys,types
raw=sys.stdin.buffer.read(1048577)
if not 0<len(raw)<=1048576 or hashlib.sha256(raw).hexdigest()!=CAPSULE_SHA:raise SystemExit('phase=ROOT_DELIVERY reason=FULL_CAPSULE_HASH_MISMATCH')
p=json.loads(raw)
if type(p)is not dict or set(p)!={'schema','sourceCommit','loader','sources','declarationHash'} or p['schema']!='ouf.policy-token-iam-action-memory-capsule.v1':raise SystemExit('phase=ROOT_DELIVERY reason=EXACT_FULL_CAPSULE_REQUIRED')
loader=base64.b64decode(p['loader'],validate=True)
if not 0<len(loader)<=65536:raise SystemExit('phase=ROOT_DELIVERY reason=LOADER_UNBOUNDED')
sources={n:base64.b64decode(v,validate=True) for n,v in p['sources'].items()}
runtime=types.ModuleType('verified_iam_action_loader')
exec(compile(loader,'verified-iam-action-loader','exec'),runtime.__dict__)
entry,manifest=runtime.load_entry(p['sourceCommit'],sources,loader,p['declarationHash'])
import signal,time,subprocess,tempfile
binding=entry.binding
phase='EXACT_TARGET_REVIEW_READ'
witness_path=None
safe_diagnostics={}
try:
    binding.require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
        and sys.dont_write_bytecode,'ROOT_ISOLATED_HUMAN_WITNESS_REQUIRED')
    with binding.protected_parent() as directory:
        name='policy-token-iam-action-review-'+REVIEW_HASH+'.private.json'
        review_raw=binding.read_member(directory,name)
        binding.require(binding.sha(review_raw)==REVIEW_HASH,'APPROVED_TARGET_REVIEW_HASH_DRIFT')
        review=binding.decode(review_raw)
        binding.require(review.get('schema')=='ouf.policy-token-iam-owner-action-review.v1'
            and review.get('sourceClosureHash')==CLOSURE_HASH
            and review['sourceClosure']['declaration']==manifest
            and binding.sha(binding.encoded(review['sourceClosure']))==CLOSURE_HASH
            and review.get('maximumIamPostAttempts')==1
            and review.get('maximumExistingRoleSignatures')==2
            and review.get('authorityLifetimeSeconds')==240
            and review.get('requiredFirstInvocationWindowSeconds')==900
            and review.get('runtimeAuthorityIssued')is False
            and review.get('productionApplyReady')is False,'EXACT_ONE_MAPPER_REVIEW_REQUIRED')
    phase='CURRENT_EXISTING_IAM_SESSION_PREFLIGHT'
    with binding.protected_parent() as directory:entry.inputs(directory)
    resource=review['policyTokenIamPreparation']['resource']
    match=re.fullmatch('clients/([0-9a-fA-F-]{36})/protocol-mappers/models',resource)
    binding.require(match is not None,'EXACT_APPROVED_CLIENT_REFERENCE_REQUIRED')
    with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
        result=subprocess.run(['/usr/bin/docker','exec','ouf-keycloak','/opt/keycloak/bin/kcadm.sh',
            'get','clients/'+match[1],'--server','http://localhost:8080','-r','ouf','--fields','id'],
            stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=15)
        stdout.seek(0);stderr.seek(0);out=stdout.read(262145);err=stderr.read(65537)
    safe_diagnostics.update(iamMetadataGetAttempts=1,iamGetExitCode=result.returncode,
        diagnosticTextTruncated=len(err)>65536,rawDiagnosticTextPrinted=False,
        diagnosticCategoriesAreNotRootCauseProof=True)
    if result.returncode!=0:
        text=err[:65536].decode('utf-8','replace').lower()
        patterns=((r'session (?:has )?expired|failed to refresh access token|invalid_grant|not logged in|no token specified','SESSION_AUTH_FAILURE_TEXT_OBSERVED'),
            (r'unauthorized|\b401\b','UNAUTHORIZED_TEXT_OBSERVED'),(r'forbidden|\b403\b','FORBIDDEN_TEXT_OBSERVED'),
            (r'connection refused|connectexception','CONNECTION_REFUSED_TEXT_OBSERVED'),
            (r'timed out|timeout','CONNECTION_TIMEOUT_TEXT_OBSERVED'),
            (r'no such container|is not running','CONTAINER_UNAVAILABLE_TEXT_OBSERVED'),
            (r'permission denied','LOCAL_PERMISSION_FAILURE_TEXT_OBSERVED'))
        safe_diagnostics['diagnosticCategories']=[label for pattern,label in patterns if re.search(pattern,text)] or ['UNCLASSIFIED_CLI_FAILURE']
        binding.require(False,'EXISTING_IAM_SESSION_PREFLIGHT_FAILED')
    binding.require(0<len(out)<=262144 and binding.decode(out)=={'id':match[1]},'EXACT_SESSION_GET_SCHEMA_REQUIRED')
    phase='EXPLICIT_TERMINAL_HUMAN_DECISION' 
    phrase='APPROVO IAM '+REVIEW_HASH
    def deadline(*_):raise binding.CandidateDenied('FINITE_HUMAN_PROMPT_DEADLINE')
    signal.signal(signal.SIGALRM,deadline);signal.alarm(120)
    with open('/dev/tty','r',encoding='utf-8') as reader, open('/dev/tty','w',encoding='utf-8') as terminal:
        terminal.write('\nApprovazione HUMAN richiesta: un solo mapper oidc-audience-mapper sul client SERVICE registrato nella review.\n'
            'Due firme del proprietario esistente; massimo un POST IAM. Nessuna autorita runtime, modifica servizi o reset budget/R12.\n'
            'Review: '+REVIEW_HASH+'\nSource closure: '+CLOSURE_HASH+'\n'
            'Per approvare questa sola azione scrivi esattamente:\n'+phrase+'\n> ')
        terminal.flush();answer=reader.readline(256)
    signal.alarm(0)
    binding.require(answer==phrase+'\n','EXPLICIT_ONE_MAPPER_HUMAN_APPROVAL_NOT_GIVEN')
    now=int(time.time())
    witness={'schema':'ouf.policy-token-explicit-terminal-human-witness.v1',
        'actor':'EXISTING_VPS_OPERATOR_EXPLICIT_TTY_DECISION','approvedAt':now,
        'firstInvocationBefore':now+900,'approvedReviewHash':REVIEW_HASH,
        'approvedSourceClosureHash':CLOSURE_HASH,'enteredDecision':phrase,
        'maximumIamPostAttempts':1,'maximumExistingRoleSignatures':2,
        'authorityLifetimeSeconds':240,'runtimeAuthorityIssued':False,'budgetReset':False,'r12Touched':False}
    witness_raw=binding.encoded(witness);witness_hash=binding.sha(witness_raw)
    phase='PRIVATE_EXPLICIT_HUMAN_WITNESS_PUBLICATION'
    witness_name='policy-token-iam-human-witness-'+witness_hash+'.private.json'
    with binding.protected_parent() as directory:
        binding.require(entry.publish(directory,witness_name,witness_raw),'HUMAN_WITNESS_ALREADY_PUBLISHED')
        binding.require(binding.read_member(directory,witness_name)==witness_raw,'HUMAN_WITNESS_PUBLICATION_DRIFT')
    witness_path=str(binding.PARENT/witness_name)
    decision={'approvalRef':'human-iam-'+witness_hash,'approvedReviewHash':REVIEW_HASH,
        'approvedSourceClosureHash':CLOSURE_HASH,'approvedAt':now,'firstInvocationBefore':now+900,
        'decision':'APPROVE_ONE_EXACT_IAM_CALLER_AUDIENCE_MAPPER','state':'ACTIVE'}
except Exception as error:
    signal.alarm(0)
    reason=str(error)
    if not re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason):reason=type(error).__name__
    report={'schema':'ouf.policy-token-human-witness-delivery-receipt.v1','status':'BLOCKED',
        'phase':phase,'reason':reason,'privateEvidencePath':witness_path,
        'evidencePublicationMayBePartial':phase=='PRIVATE_EXPLICIT_HUMAN_WITNESS_PUBLICATION',
        'installationKeyAccessAttempted':False,'signaturesIssued':0,'iamMutations':0,
        'serviceMutations':0,'runtimeAuthorityIssued':False,'productionApplyReady':False,
        'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
    report.update(safe_diagnostics)
    if isinstance(error,OSError):report['errno']=error.errno
    print(binding.encoded(report).decode());raise SystemExit(1)
raise SystemExit(entry.main(manifest,mode='apply',review_hash=REVIEW_HASH,decision=decision))
'''

def main():
    if not re.fullmatch('[0-9a-f]{40}',CAPSULE_COMMIT) or not re.fullmatch('[0-9a-f]{64}',CAPSULE_SHA):
        raise SystemExit('phase=DELIVERY reason=FULL_CAPSULE_NOT_QUALIFIED; no sudo executed')
    preferred=Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
    gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
    if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
    endpoint='repos/GioNob/ouf-deploy/contents/'+CAPSULE_PATH+'?ref='+CAPSULE_COMMIT
    try:
        result=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,timeout=30)
        if len(result.stdout)>1500000:raise ValueError()
        raw=base64.b64decode(b''.join(result.stdout.split()),validate=True)
    except Exception:raise SystemExit('phase=DELIVERY reason=FULL_CAPSULE_UNAVAILABLE; no sudo executed') from None
    if not 0<len(raw)<=1048576 or hashlib.sha256(raw).hexdigest()!=CAPSULE_SHA:
        raise SystemExit('phase=DELIVERY reason=FULL_CAPSULE_HASH_MISMATCH; no sudo executed')
    root_code='CAPSULE_SHA='+repr(CAPSULE_SHA)+'\nREVIEW_HASH='+repr(REVIEW_HASH)+'\nCLOSURE_HASH='+repr(CLOSURE_HASH)+'\n'+ROOT_BODY
    try:return subprocess.run(['sudo','--','/usr/bin/python3','-I','-B','-S','-c',root_code],input=raw,timeout=440).returncode
    except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=APPROVED_IAM_RESULT_UNAVAILABLE; preserve output, do not automatically rerun') from None

if __name__=='__main__':raise SystemExit(main())
