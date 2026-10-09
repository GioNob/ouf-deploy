"""Root operator bridge for the explicitly approved two-CID transaction.

Reuse the existing sealed package and sixteen private inputs. No key generation,
bootstrap repetition, direct Docker shortcut, automatic retry or recovery.
The existing sealed intake owns actual issuance, signatures, switch and start.
"""
import copy
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

SCOPE = json.loads(r'''{"schema":"ouf.semantic-provider-controlled-execution-review.v1","reviewRef":"OUF_PROVIDER_V2_SIGN_START_REVIEW_20261009_R1","state":"PROPOSED_NOT_AUTHORITY","existingHumanAcceptanceRefs":["OUF_PROVIDER_V2_LAB_IMAGE_REVIEW_20261008_233809","OUF_PROVIDER_V2_FULL_INPUT_REVIEW_20261009_005751"],"package":{"path":"/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n","manifestSha256":"2699c82124b6bfcbd61991f09a96ebb5c6a2d336aaf3384dcae9288101b29de4","entrySha256":"edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5","sourceClosureHash":"dc87593c5c3b2e4859545de25b92702d93666e8d5c988f03e35fcf2df24c1ae4","sourceFiles":41},"inputDirectory":"/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-draft-g1yrsazc","roleProposals":{"adapter":{"schema":"ouf.semantic-provider-role-mandate-proposal.v1","state":"PROPOSED_NOT_AUTHORITY","reviewRef":"OUF_PROVIDER_V2_SIGN_START_REVIEW_20261009_R1","role":"adapter","installationRef":"ouf-lab-netcup-01","entityRef":"ouf-lab","containerId":"f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67","imageManifestDigest":"sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc","imageConfigDigest":"sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320","runtimeSeal":{"schema":"ouf.semantic-rootfs-seal.v1","sha256":"8744724088d02145b86b433058a4336fcb9c873a4a92e7009753209c284d3d73","entries":3390,"bytes":46079786},"transactionId":"a1c2768460dc488c73a9d5aabc71fa106373512eb8fe58510654326ce3743b07","applicationHash":"816cdcc143d99047151c337eefefe3df29d5ea8a999d50597f1d0b899cd295f4","transportHash":"bcf108752031439eef2ba1685ebf4aa9781229b2a7dca01ad6c9f97f5eeedab8","inputHashes":{"context":"ede2f4ee4de3b869d11e125cad094cbc5bad900bdb365a10d5d365d3104853ca","dependencyEvidence":"3e66cfb38a24923e1880cd1c28e53abdbd39d09fdca2f2cdfd105115f16b193b","deploymentConstraints":"2ea27b1d19bf4bd151b3f9199a651a5f693aced13ad9b02490485452aec82ef7","framePolicy":"e8047e92e8b3938abe67dc8e57f385fced9de1218db348b4723eb3c6d34867fd","launch":"061e2bd245d45d7e435ff86e07a6897413ae6c164d2d2c9ade2d455d80846943","preparerTemplate":"0a9a12a36b9f28eca2edcb3a2ad2c3d741559abb5d3699029bcc105c287dab53","provenanceEvidence":"0e5de8878e68d8fe555024cd5c0b911361c713e6547f93ebebd243ca34791f9f","template":"bf536f60c1d511f4cdbeb8546e84f46d426f693019938a0a9b4dbf76b3308e01"},"sourceClosureHash":"dc87593c5c3b2e4859545de25b92702d93666e8d5c988f03e35fcf2df24c1ae4","roleSigningScopes":{"installer":["TARGET_REVIEW","DEPLOYMENT_INTENT","FINAL_DEPLOYMENT_APPROVAL"],"attestor":["LIVE_NODE_ACCEPTANCE"]},"proposedDecision":"ACCEPT_PROVIDER_IMAGE_AND_COMPLETE_FRAME_AND_CONTROLLED_ADMISSION","timeWindow":{"issuedAt":"T0 from root clock at actual invocation","expiresAt":"T0 + 240 seconds","mustNotExceed":"2026-10-09T06:31:48Z"},"authorityGranted":false},"southbound":{"schema":"ouf.semantic-provider-role-mandate-proposal.v1","state":"PROPOSED_NOT_AUTHORITY","reviewRef":"OUF_PROVIDER_V2_SIGN_START_REVIEW_20261009_R1","role":"southbound","installationRef":"ouf-lab-netcup-01","entityRef":"ouf-lab","containerId":"1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916","imageManifestDigest":"sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366","imageConfigDigest":"sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04","runtimeSeal":{"schema":"ouf.semantic-rootfs-seal.v1","sha256":"52e06f47e1da5a107525e2260b9d375329997181dd13de7023654278aeaf3f39","entries":7458,"bytes":255900260},"transactionId":"a2cb1cd204239fba17e43f71530345ee6e50dde60967a2c40a605d9f70cd6266","applicationHash":"fc99be8319b210322292a6f468121de97f764800f5e4fb9717e9ac85a9293322","transportHash":"494ce1976af397a48c27453eb1991d63c2fcd06b28e1b187931732a99be9f1b7","inputHashes":{"context":"e515366dbe8412bf261711ea98bcaac3e6d9e9d8bc3f77109829613ec166f4eb","dependencyEvidence":"5c60aa4def36d5ea09cb01f0b2a76ac93640b9df2878b5cdd5b83232b7db53c9","deploymentConstraints":"e349f6f9c059fa11415b6255a115d4d00972468e892624376b45d43365e718c2","framePolicy":"f49155fa412bb76d529713cb4ac2c253105884e9e72f7d2d74dfc5ccf9c5c822","launch":"cbc1f30c200a6a27e92b8055aa5542df30f7d124d08004d6f3bfe7dfb9ed2a39","preparerTemplate":"7ac15676ff00e38e1ac5bf5bd2356e42c34dbe9b485a5ba38d562380dcb1a894","provenanceEvidence":"75fc6a4022bbec82cad2e77e1d48fae3b3af77218edb1f8bade4d46c867dfa8b","template":"0ef8aa503bfb6a5c789000cd73de6e987d1a55688894475e555f4d566581ad05"},"sourceClosureHash":"dc87593c5c3b2e4859545de25b92702d93666e8d5c988f03e35fcf2df24c1ae4","roleSigningScopes":{"installer":["TARGET_REVIEW","DEPLOYMENT_INTENT","FINAL_DEPLOYMENT_APPROVAL"],"attestor":["LIVE_NODE_ACCEPTANCE"]},"proposedDecision":"ACCEPT_PROVIDER_IMAGE_AND_COMPLETE_FRAME_AND_CONTROLLED_ADMISSION","timeWindow":{"issuedAt":"T0 from root clock at actual invocation","expiresAt":"T0 + 240 seconds","mustNotExceed":"2026-10-09T06:31:48Z"},"authorityGranted":false}},"existingAuthorityProfile":{"path":"/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json","sha256":"7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18"},"existingTrustPolicy":{"path":"/etc/ouf/deploy-snapshots/semantic-trust-policy-preparation-20261004-172336/trust-policy.json","sha256":"21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42"},"authorities":{"installerRef":"ouf-lab-infrastructure-installer","nodeAttestorRef":"ouf-lab-node-attestor","keyRefs":["ouf-lab-installer-ed25519-1","ouf-lab-attestor-ed25519-1"],"keyGenerationPermitted":false,"keyExportPermitted":false},"runtime":{"name":"ouf-semantic-admitted-v2","wrapperPath":"/usr/local/sbin/ouf-semantic-admitted-v2","originalEmptyWrapperSha256":"4956b05ec41fd54a27c00f2b6606d17be97dd84b3c09cff8b252d0fc886331bd","maximumCandidateAllowlist":2,"ownerConfigurationSha256":"656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8","guardPointerPath":"/etc/ouf/coordinated-boot-installation.json"},"proposedOperations":["Root operator materializes exactly two scope-bound short-lived mandates after explicit human approval","Existing installer/attestor keys sign target review, creation-only intent, live node acceptance authorization and final installer mandate","Actual signatures are verified before new private profiles and STAGED journals are published","Fresh locked custody/native empty-guard observation precedes and surrounds compare-and-swap of the original empty wrapper","Exactly two concurrent Docker start requests go through the named authenticated runtime, with actual complete OCI/rootfs/NIC/peer/generation/guard checks before application release","Both bounded candidate readbacks and durable success or denial evidence are collected"],"excludedOperations":["Direct ad-hoc Docker start","Daemon restart","General sudo grant","Automatic replay, rollback or retry","Orchestrator provider lease grant or provider API call","Teatri discovery job","Release acceptance"],"authorityGranted":false,"startAuthorized":false,"notReleaseAcceptance":true,"partialFailurePolicy":"Retain claims, wrapper state and both available candidate observations. No automatic recovery; explicit scoped human recovery is required.","freshnessPolicy":"All signing/activation windows must fit within DB validity. If expired or insufficient, deny; do not extend old evidence or silently replace accepted hashes.","targetNativeAdmissionObservedHere":false}''')
APPROVAL_REF = 'OUF_PROVIDER_V2_SIGN_START_HUMAN_APPROVAL_20261009_075624'
APPROVED_AT = int(datetime.fromisoformat('2026-10-09T07:56:24+02:00').timestamp())
FRESH_UNTIL = int(datetime.fromisoformat('2026-10-09T06:31:48+00:00').timestamp())
PHASE = 'VERIFY_EXPLICIT_HUMAN_APPROVAL_AND_SEALED_ENTRY'
CONTEXT = None
PACKAGE = Path(SCOPE['package']['path'])

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(ok,reason):
    if not ok:raise ValueError(reason)

def build_mandates(scope,actual_hashes,now,approval_ref):
    """Pure exact-scope construction; does not supply signatures or authority."""
    require(approval_ref==APPROVAL_REF,'EXPLICIT_RECORDED_HUMAN_APPROVAL_REQUIRED')
    require(scope==SCOPE,'APPROVED_EXECUTION_SCOPE_DRIFT')
    require(type(now) is int and now>=APPROVED_AT,'ROOT_CLOCK_BEFORE_HUMAN_APPROVAL')
    require(now+240<=FRESH_UNTIL,'DEPENDENCY_VALIDITY_DOES_NOT_COVER_240_SECOND_WINDOW')
    require(set(actual_hashes)==set(scope['roleProposals'])=={'adapter','southbound'},'EXACT_TWO_APPROVED_ROLES_REQUIRED')
    result={}
    for role,proposal in scope['roleProposals'].items():
        require(actual_hashes[role]==proposal['inputHashes'],'APPROVED_EIGHT_INPUT_HASHES_DRIFT')
        result[role]={key:copy.deepcopy(proposal[key]) for key in ('role','installationRef','entityRef',
            'containerId','imageManifestDigest','imageConfigDigest','runtimeSeal','inputHashes',
            'sourceClosureHash','roleSigningScopes','transactionId')}
        result[role].update(schema='ouf.semantic-provider-transaction-role-mandate.v1',state='ACTIVE',
            decision=proposal['proposedDecision'],approvalRef=approval_ref,issuedAt=now,expiresAt=now+240)
    return result

def write(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())

def sync(directory):
    for path in (directory,directory.parent):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)

def main(approval_ref):
    global PHASE,CONTEXT
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_OPERATOR_REQUIRED')
    require(approval_ref==APPROVAL_REF,'EXPLICIT_RECORDED_HUMAN_APPROVAL_REQUIRED')
    # The sole entry file is verified in memory before executing its definitions.
    path=PACKAGE/'provider_transaction_intake.py'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        raw=os.read(fd,131073)
        require(sha(raw)==SCOPE['package']['entrySha256'],'INSTALLED_SEALED_ENTRY_HASH_DRIFT')
    finally:os.close(fd)
    entry={'__name__':'approved_provider_entry','__file__':str(path)}
    exec(compile(raw,str(path),'exec'),entry)
    require(entry['read'](path)==raw,'INSTALLED_SEALED_ENTRY_CUSTODY_DRIFT')
    require(not any(os.path.lexists(PACKAGE/name) for name in ('execution-claim.json','intake-claim.json','intake-denial.json','operator-context-claim.json')),
        'DO_NOT_REPLAY_EXISTING_INTAKE_ATTEMPT')
    sources,observer=entry['load'](PACKAGE)
    require(sha(encoded({**{k:sha(v) for k,v in sources.items()},'frame-observer.py':sha(observer)}))
        ==SCOPE['package']['sourceClosureHash'],'APPROVED_RUNTIME_OBSERVER_CLOSURE_DRIFT')
    PHASE='READ_APPROVED_EXISTING_INPUTS_AND_PUBLIC_BINDINGS'
    bindings={role:{name:{'path':str(Path(SCOPE['inputDirectory'])/role/(name+'.json')),'sha256':expected}
        for name,expected in proposal['inputHashes'].items()} for role,proposal in SCOPE['roleProposals'].items()}
    records={role:{name:entry['bound'](binding) for name,binding in values.items()} for role,values in bindings.items()}
    from authenticate_provider_transaction import preflight_input_pair,validate_dependency_evidence,AUTHORITIES
    preflight_input_pair(records)
    for name in ('AUTHORITY','POLICY','EMPTY_ADAPTER'):entry['bound'](entry[name])
    authority=entry['parse'](entry['bound'](entry['AUTHORITY']))
    require(authority['authorities']==AUTHORITIES and authority['policyBinding']==entry['POLICY'],
        'EXISTING_INSTALLATION_AUTHORITY_DRIFT')
    entry['bound'](entry['PYTHON'],True);entry['bound'](entry['OPENSSL'],True)
    require(Path(sys.executable).absolute()==Path(entry['PYTHON']['path']),'TARGET_OPERATOR_INTERPRETER_DRIFT')
    with tempfile.TemporaryFile() as output:
        result=subprocess.run([entry['OPENSSL']['path'],'version'],stdin=subprocess.DEVNULL,stdout=output,
            stderr=subprocess.DEVNULL,timeout=5,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        output.seek(0);version=output.read(1025).decode('ascii')
    match=re.match(r'^OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*) ',version)
    require(result.returncode==0 and len(version)<=1024 and match is not None,'PUBLIC_OPENSSL_VERSION_UNPROVEN')
    pointer_path=Path(SCOPE['runtime']['guardPointerPath']);pointer_raw=entry['read'](pointer_path)
    pointer=entry['parse'](pointer_raw)
    owner_path=Path('/etc/ouf/deploy-snapshots/semantic-coordinated-boot-install-v2-e4repg0a/coordinated-configuration.json')
    owner=entry['parse'](entry['bound']({'path':str(owner_path),'sha256':SCOPE['runtime']['ownerConfigurationSha256']}))
    commands={'docker':{'path':'/usr/bin/docker','sha256':'7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40'},
        'nft':{'path':owner['nftPath'],'sha256':owner['nftSha256']},
        'systemctl':{'path':'/usr/bin/systemctl','sha256':sha(entry['read']('/usr/bin/systemctl',True))}}
    for value in commands.values():entry['bound'](value,True)
    PHASE='VERIFY_FRESHNESS_BEFORE_MANDATE_PUBLICATION'
    now=int(time.time())
    mandates=build_mandates(SCOPE,{role:{name:sha(raw) for name,raw in values.items()} for role,values in records.items()},now,approval_ref)
    for role,values in records.items():validate_dependency_evidence(entry['parse'](values['dependencyEvidence']),role,now,now+240)
    # No keys or active mandate publication before exact pair/freshness validation.
    PHASE='PUBLISH_EXPLICIT_ROOT_MANDATES_AND_CONFIGURATION'
    CONTEXT=Path(tempfile.mkdtemp(prefix='semantic-provider-v2-approved-context-',dir='/etc/ouf/deploy-snapshots'))
    os.chmod(CONTEXT,0o700)
    write(PACKAGE/'operator-context-claim.json',encoded({'schema':'ouf.semantic-provider-operator-context-claim.v1',
        'state':'CONTEXT_RESERVED','contextDirectory':str(CONTEXT),'approvalRef':approval_ref,'notReleaseAcceptance':True}))
    sync(PACKAGE)
    mandate_bindings={}
    for role,value in mandates.items():
        path=CONTEXT/(role+'-mandate.json');raw=encoded(value);write(path,raw)
        mandate_bindings[role]={'path':str(path),'sha256':sha(raw)}
    output_root=CONTEXT.parent/('semantic-provider-v2-transaction-'+CONTEXT.name.removeprefix('semantic-provider-v2-approved-context-'))
    cfg={'schema':'ouf.semantic-provider-approved-transaction.v1','authorityProfileBinding':entry['AUTHORITY'],
        'runtimeAdapterBinding':entry['EMPTY_ADAPTER'],'pythonBinding':entry['PYTHON'],
        'opensslBinding':{**entry['OPENSSL'],'version':match.group(1)},'recordsByRole':bindings,
        'mandatesByRole':mandate_bindings,'outputRoot':str(output_root),
        'guardPointerBinding':{'path':str(pointer_path),'sha256':sha(pointer_raw)},'commandBindings':commands}
    raw=encoded(cfg);path=CONTEXT/'execution-configuration.json';write(path,raw)
    write(CONTEXT/'human-approval-binding.json',encoded({'schema':'ouf.semantic-provider-approved-root-context.v1',
        'approvalRef':approval_ref,'reviewRef':SCOPE['reviewRef'],'sourcePackage':str(PACKAGE),
        'configurationHash':sha(raw),'mandateHashes':{role:v['sha256'] for role,v in mandate_bindings.items()},
        'issuedAt':now,'expiresAt':now+240,'notReleaseAcceptance':True}));sync(CONTEXT)
    PHASE='INVOKE_EXISTING_SEALED_APPROVED_TRANSACTION'
    sys.argv=[str(PACKAGE/'provider_transaction_intake.py'),'--configuration',str(path),
        '--configuration-sha256',sha(raw),'--execute-approved-transaction']
    code=entry['main']()
    require(code==0,'SEALED_TRANSACTION_DENIED_READ_RETAINED_EVIDENCE')
    print('OUF_APPROVED_PROVIDER_TRANSACTION=PASS CONTEXT='+str(CONTEXT)+' NOT_RELEASE_ACCEPTANCE=true')

if __name__=='__main__':
    try:
        require(len(sys.argv)==2,'EXACT_HUMAN_APPROVAL_REFERENCE_ARGUMENT_REQUIRED');main(sys.argv[1])
    except Exception as error:
        reason=str(error)
        if not re.fullmatch('[A-Z0-9_]{1,96}',reason):reason='APPROVED_PROVIDER_OPERATOR_TRANSACTION_UNPROVEN'
        attempted=os.path.lexists(PACKAGE/'execution-claim.json')
        report={'status':'BLOCKED','phase':PHASE,'reason':reason,'errorType':type(error).__name__,
            'contextDirectory':str(CONTEXT) if CONTEXT else None,'sourcePackage':str(PACKAGE),
            'doNotRerunApply':CONTEXT is not None or attempted,'privateValuesPrinted':False,
            'privateKeysRead':None if attempted else 0,'containerLifecycleOperations':None if attempted else 0,
            'targetRuntimeChanged':None if attempted else False,'notReleaseAcceptance':True}
        if isinstance(error,OSError):report['errno']=error.errno
        if CONTEXT:
            try:write(CONTEXT/'operator-denial.json',encoded(report));sync(CONTEXT)
            except Exception:report['diagnosisSaved']=False
        print('OUF_APPROVED_PROVIDER_TRANSACTION='+json.dumps(report,sort_keys=True,separators=(',',':')));raise SystemExit(1)
