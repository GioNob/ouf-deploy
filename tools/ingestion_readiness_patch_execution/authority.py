"""Exact finite infrastructure issuance through existing HUMAN/two-role gates.

No login, refresh, authority provisioning or key generation. Semantic/source
approval remains in THS. Existing infrastructure terminal consent is reused;
development authorization cannot substitute for its exact current decision.
Every installation authority, policy, path and issuer reference is an input.
"""
import copy
import hashlib
import json
from pathlib import Path
import time
from tools.ingestion_readiness_patch_execution import contract as c,native_review,private_file,human_reader
from tools.ingestion_readiness_patch_execution.infrastructure_consent import terminal_consent,decision_valid
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,policy
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_provider_deployment_protocol import identity
from cutover_authority import CutoverAuthority
from iam_owner_action import publish,stdlib_binding
import iam_governance_intake as governance

SCHEMA='ouf.ingestion-readiness-patch-infrastructure-review.v1'
QUALIFICATION={'rootCas','dockerTwoNetworks','apisix','jvmValidateOnly','postgres17','adversarial'}

def qualification_valid(q,closure,candidate):
    c.require(type(q)is dict and q.get('schema')=='ouf.ingestion-readiness-patch-native-qualification.v1'
              and q.get('sourceCommit')==closure['declaration'].get('sourceCommit')
              and q.get('sourceHashes')==closure['declaration']['sourceHashes']
              and q.get('candidateNativeImageId')==candidate['nativeImageId']
              and q.get('candidateSourceCommit')==candidate['sourceCommit']
              and q.get('results')==dict.fromkeys(QUALIFICATION,'PASS')
              and q.get('runtimeAuthorityIssued')is False and q.get('notReleaseAcceptance')is True,
              'COMPLETE_EXACT_NATIVE_REPRESENTATIVE_QUALIFICATION_REQUIRED')
    refs=q.get('evidenceRefs')
    c.require(type(refs)is dict and set(refs)==QUALIFICATION and all(type(v)is dict
              and type(v.get('repository'))is str and v['repository']
              and type(v.get('runId'))is int and v['runId']>0
              and type(v.get('jobId'))is int and v['jobId']>0
              and type(v.get('sourceCommit'))is str and len(v['sourceCommit'])==40
              and all(x in '0123456789abcdef'for x in v['sourceCommit'])for v in refs.values()),
              'IMMUTABLE_QUALIFICATION_PROVIDER_REFERENCES_REQUIRED')

def validate_issuer_profile(p):
    c.require(type(p)is dict and set(p)=={'schema','installationAuthority','policy','authorityContext'}
              and p['schema']=='ouf.ingestion-rollout-existing-issuer-profile.v1','EXACT_EXISTING_ISSUER_PROFILE_REQUIRED')
    private_file.validate(p['installationAuthority']);private_file.validate(p['policy'])
    context=p['authorityContext']
    c.require(type(context)is dict and set(context)=={'installationRef','entityRef','intentIssuerRef','approvalIssuerRef','attestorRef'}
              and all(identity(v)for v in context.values()),'EXPLICIT_INSTALLATION_AUTHORITY_CONTEXT_REQUIRED')
    return p

def closure_shape(closure):
    c.require(type(closure)is dict and set(closure)=={'declaration','executables','stdlibHash','stdlibFileCount'}
              and c.hashed(closure['stdlibHash'])and type(closure['stdlibFileCount'])is int and closure['stdlibFileCount']>0,
              'EXACT_NATIVE_EXECUTABLE_CLOSURE_REQUIRED')
    declaration=closure['declaration']
    c.require(declaration.get('entryModule')=='tools.ingestion_readiness_patch_execution.entry'
              and declaration.get('requiredPythonFlags')==['-I','-B','-S']
              and declaration.get('runtimeAuthorityIssued')is False
              and type(declaration.get('sourceHashes'))is dict and declaration['sourceHashes']
              and all(c.hashed(h)for h in declaration['sourceHashes'].values())
              and type(closure['executables'])is dict and {'python','openssl','docker'}<=set(closure['executables']),
              'EXACT_NATIVE_ENTRY_AND_EXECUTABLES_REQUIRED')

def compile_action_review(review,packet,closure,issuer_profile,qualification,maximum_seconds):
    native_review.validate_review(review,packet);c.require(review.get('humanReadProfile')is not None,'QUALIFIED_READ_ONLY_HUMAN_PROFILE_REQUIRED');closure_shape(closure);validate_issuer_profile(issuer_profile)
    c.require(type(maximum_seconds)is int and 210<=maximum_seconds<=900,'FINITE_NATIVE_ISSUANCE_WINDOW_REQUIRED')
    qualification_valid(qualification,closure,packet['candidate'])
    programs=closure['executables']
    c.require(programs['docker']==review['databaseControlProfile']['dockerExecutable']
              and all(review[k]['pythonExecutable']=={x:programs['python'][x]for x in('path','sha256')}
                  for k in('ownerControlProfile','gatewayTransportProfile','ingestionReadinessProfile')),
              'SIGNED_TRANSPORT_EXECUTABLES_MUST_MATCH_CLOSURE')
    return {'schema':SCHEMA,'kind':'INGESTION_READINESS_PATCH','authorityDirectory':review['executionContext'],
        'executionReview':copy.deepcopy(review),'packetHash':c.digest(packet),
        'sourceClosure':copy.deepcopy(closure),'sourceClosureHash':c.digest(closure),
        'scopes':{c.AUTHORITY_KEY:c.scope(review)},'authenticatedHuman':copy.deepcopy(review['humanBinding']),
        'issuerProfile':copy.deepcopy(issuer_profile),'qualificationHash':c.digest(qualification),
        'qualification':copy.deepcopy(qualification),
        'candidateBinding':{k:packet['candidate'][k]for k in('sourceCommit','nativeImageId')},
        'creationRequestHash':c.digest(c.scope(review)),
        'predecessorHistoryHash':c.digest({'preparedInputsHash':review['preparedInputsHash'],'parentReviewHash':review['preparedInputs']['parentReviewHash']}),
        'predecessorIncidentRef':review['logicalOperationRef'],'maximumElapsedSeconds':maximum_seconds,
        'automaticReplayAllowed':False,'budgetReset':False,'notReleaseAcceptance':True}

def validate_action_review(review):
    c.require(review.get('schema')==SCHEMA and review.get('kind')=='INGESTION_READINESS_PATCH'
              and review.get('scopes')=={c.AUTHORITY_KEY:c.scope(review['executionReview'])}
              and review['sourceClosureHash']==c.digest(review['sourceClosure'])
              and review['authorityDirectory']==review['executionReview']['executionContext']
              and review['authenticatedHuman']==review['executionReview']['humanBinding']
              and review['creationRequestHash']==c.digest(review['scopes'][c.AUTHORITY_KEY])
              and review.get('automaticReplayAllowed')is review.get('budgetReset')is False
              and type(review.get('maximumElapsedSeconds'))is int and 210<=review['maximumElapsedSeconds']<=900,
              'EXACT_NATIVE_INFRASTRUCTURE_REVIEW_REQUIRED')
    for key in('qualificationHash','packetHash','predecessorHistoryHash','predecessorIncidentRef'):c.require(c.hashed(review[key]),'EXACT_REVIEWED_NATIVE_HISTORY_REQUIRED')
    closure_shape(review['sourceClosure']);validate_issuer_profile(review['issuerProfile'])
    c.require(c.digest(review['qualification'])==review['qualificationHash'],'NATIVE_QUALIFICATION_RECEIPT_CHANGED')
    qualification_valid(review['qualification'],review['sourceClosure'],review['candidateBinding'])
    intents={s['name']:s['intent']for s in review['executionReview']['stages']}
    c.require(intents['IMPORT_INGESTION_IMAGE']['nativeImageId']==review['candidateBinding']['nativeImageId']
              and intents['ingestion.CREATE_REPLACEMENT']['requestTemplate']['Labels']['org.opencontainers.image.revision']
              ==review['candidateBinding']['sourceCommit'],'QUALIFICATION_MUST_MATCH_ACTUAL_NATIVE_INTENTS')

def current_issuer(p,expiry):
    validate_issuer_profile(p)
    installed=json.loads(private_file.read(p['installationAuthority']));raw=private_file.read(p['policy'])
    context=p['authorityContext'];now=time.time();configured=policy(raw,context['installationRef'],context['entityRef'],now)
    c.require(installed.get('schema')=='ouf.semantic-existing-installation-authority-bindings.v1'
              and installed.get('authorities')==context
              and installed.get('policyBinding')=={k:p['policy'][k]for k in('path','sha256')}
              and set(installed.get('keyRefs',{}))==set(installed.get('keyBindings',{}))=={'installer','attestor'},
              'SAME_EXISTING_INSTALLATION_AUTHORITY_REQUIRED')
    for role,issuer in(('DEPLOYMENT_INTENT',context['intentIssuerRef']),
                       ('FINAL_DEPLOYMENT_APPROVAL',context['approvalIssuerRef']),('CREATION_ATTESTATION',context['attestorRef'])):
        keys=[k for k in configured['keys']if k['issuerRef']==issuer and role in k['roles']
              and k['state']=='ACTIVE'and k['notBefore']<=now<expiry<=k['expiresAt']]
        c.require(len(keys)==1,'CURRENT_EXISTING_ROLE_WINDOW_REQUIRED')
        selected='attestor'if role=='CREATION_ATTESTATION'else'installer'
        c.require(keys[0]['keyRef']==installed['keyRefs'][selected],'EXACT_EXISTING_ROLE_KEY_REFERENCE_REQUIRED')
    return installed,raw

def verify_closure(closure):
    closure_shape(closure)
    for program in closure['executables'].values():
        c.require(governance.executable(program['path'])=={k:program[k]for k in('path','sha256')},'NATIVE_EXECUTABLE_CHANGED')
    library=stdlib_binding()
    c.require(c.digest(library)==closure['stdlibHash']and len(library['fileHashes'])==closure['stdlibFileCount'],
              'NATIVE_STDLIB_CHANGED')

def issue_action(review,decision,human,explicitly_approved_decision_hash):
    validate_action_review(review)
    human_reader.require_profile(human,review['executionReview'])
    c.require(c.hashed(explicitly_approved_decision_hash)and c.digest(decision)==explicitly_approved_decision_hash,
              'INDEPENDENT_EXACT_HUMAN_DECISION_HASH_REQUIRED')
    decision_valid(review,decision,human,time.time());verify_closure(review['sourceClosure'])
    installed,policy_raw=current_issuer(review['issuerProfile'],decision['expiresAt'])
    expected={k:review[k]for k in('sourceClosureHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef')}
    expected['intakeHash']=c.digest(review);context=Path(review['authorityDirectory'])
    raw=c.encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',
        **{k:v for k,v in expected.items()if k!='intakeHash'},'issuedAt':int(time.time()),'expiresAt':decision['expiresAt'],
        **review['scopes'],'automaticReplayAllowed':False,'databaseRestoreAuthorized':False,'r12ReplayAuthorized':False})
    c.require(len(raw)<=131072,'BOUNDED_NATIVE_AUTHORITY_REQUIRED')
    mandate=c.encoded({'schema':'ouf.semantic-cutover-human-mandate.v1','approvalRef':decision['approvalRef'],
        'decision':'APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY','state':'ACTIVE','issuedAt':decision['approvedAt'],
        'expiresAt':decision['expiresAt'],'executionAuthorityHash':hashlib.sha256(raw).hexdigest(),**expected})
    # The reviewed file must preexist. Issuance never rewrites a review or old claim.
    with protected_directory(context)as directory:
        from iam_binding_candidate import read_member
        c.require(read_member(directory,'review.json')==c.encoded(review),'PUBLISHED_EXACT_NATIVE_REVIEW_REQUIRED')
        c.require(publish(directory,'ingestion-readiness-patch-issuance.claim.json',c.encoded({'reviewHash':c.digest(review),
            'decisionHash':c.digest(decision),'automaticReplayAllowed':False,'budgetReset':False})),
            'NATIVE_ISSUANCE_ALREADY_CONSUMED_RECONCILE_ONLY')
        for name,body in(('decision.json',c.encoded(decision)),('human.json',mandate),('authority.json',raw)):
            c.require(publish(directory,name,body),'NATIVE_AUTHORITY_ARTIFACT_EXISTS_RECONCILE_ONLY')
        selected={k:review['issuerProfile']['policy'][k]for k in('path','sha256')}
        verifier=DetachedAuthenticator(selected,str(context),review['sourceClosure']['executables']['openssl'])
        mandate_hash=hashlib.sha256(mandate).hexdigest();ctx=review['issuerProfile']['authorityContext']
        gate=CutoverAuthority(verifier,{'path':str(context/'human.json'),'sha256':mandate_hash},mandate_hash,ctx,expected)
        for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
            gate.mandate(raw);decision_valid(review,decision,human,time.time())
            c.require(current_issuer(review['issuerProfile'],decision['expiresAt'])==(installed,policy_raw),
                      'EXISTING_ISSUER_PROFILE_CHANGED_DURING_ISSUANCE')
            signer=ExistingEd25519Signer(installed['keyBindings']['installer'],installed['keyRefs']['installer'],verifier,
                {'role':role,'issuerRef':ctx[key],'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef']})
            c.require(publish(directory,hashlib.sha256(raw).hexdigest()+'.'+role+'.json',signer.sign(raw)),
                      'NATIVE_ROLE_SIGNATURE_EXISTS_RECONCILE_ONLY')
        gate(raw)
    return AggregateAction(gate,raw,review['sourceClosureHash'])
