"""Bind the existing IAM review to existing public authority, without issuance.

Read-only IAM/profile/policy/executable observation; one immutable private
preparation intake. No key/token/credential read, signer, grant or apply path.
The recorded source closure is preparation code, never an apply authorization.
"""
import hashlib
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import iam_binding_candidate as binding
import iam_mapper_enrichment as metadata

PROFILE={'path':'/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json',
         'sha256':'7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18'}
POLICY={'path':'/etc/ouf/deploy-snapshots/semantic-trust-policy-preparation-20261004-172336/trust-policy.json',
        'sha256':'21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42'}
CONTEXT={'installationRef':'ouf-lab-netcup-01','entityRef':'ouf-lab',
         'intentIssuerRef':'ouf-lab-infrastructure-installer','approvalIssuerRef':'ouf-lab-infrastructure-installer',
         'attestorRef':'ouf-lab-node-attestor'}
PLAN='policy-token-introspection-review-4a3d1c444012c8f30bf4480a518dea8448d815397cb1d71f97d26d99ad1fef76.private.json'
PLAN_HASH='4a3d1c444012c8f30bf4480a518dea8448d815397cb1d71f97d26d99ad1fef76'
SNAPSHOT='policy-token-iam-metadata-830709d5bc5348309025c3a82212a62e.private.json'
SNAPSHOT_HASH='7e0f46ad0f66ee40b2ce0f662fdb70007744f81f933865264fdf279227681927'
SOURCE_NAMES={'iam_binding_candidate','iam_mapper_enrichment','iam_governance_intake'}

def public_input(item):
    path=Path(item['path'])
    # The same strict root-directory traversal protects only this exact public
    # JSON member; private key paths in the profile are never opened or probed.
    previous=binding.PARENT
    try:
        binding.PARENT=path.parent
        with binding.protected_parent() as directory:raw=binding.read_member(directory,path.name)
    finally:binding.PARENT=previous
    binding.require(binding.sha(raw)==item['sha256'],'EXISTING_GOVERNANCE_INPUT_HASH_DRIFT')
    return raw

def authority_metadata(profile,policy,now):
    binding.require(profile.get('schema')=='ouf.semantic-existing-installation-authority-bindings.v1'
        and profile.get('authorities')==CONTEXT and profile.get('policyBinding')==POLICY
        and set(profile.get('keyRefs',{}))==set(profile.get('keyBindings',{}))=={'installer','attestor'},
        'EXACT_EXISTING_INSTALLATION_CONTEXT_REQUIRED')
    binding.require(set(policy)=={'schema','installationRef','entityRef','keys'}
        and policy['schema']=='ouf.semantic-deployment-trust-policy.v1'
        and policy['installationRef']==CONTEXT['installationRef'] and policy['entityRef']==CONTEXT['entityRef']
        and type(policy['keys'])is list and len(policy['keys'])==2,'EXACT_EXISTING_PUBLIC_POLICY_REQUIRED')
    rows=[]
    for role,issuer,roles in (('installer',CONTEXT['intentIssuerRef'],{'DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'}),
                              ('attestor',CONTEXT['attestorRef'],{'CREATION_ATTESTATION'})):
        keys=[k for k in policy['keys'] if type(k)is dict and k.get('keyRef')==profile['keyRefs'][role] and k.get('issuerRef')==issuer]
        binding.require(len(keys)==1,'UNIQUE_EXISTING_ROLE_KEY_REQUIRED');key=keys[0]
        binding.require(set(key)=={'keyRef','issuerRef','roles','publicKey','notBefore','expiresAt','state'}
            and type(key['roles'])is list and len(key['roles'])==len(roles) and set(key['roles'])==roles
            and type(key['publicKey'])is str and re.fullmatch('[0-9a-f]{64}',key['publicKey'])
            and key['state']=='ACTIVE' and type(key['notBefore'])is int and type(key['expiresAt'])is int
            and 0<=key['notBefore']<=now<key['expiresAt'],'CURRENT_EXISTING_ROLE_POLICY_REQUIRED')
        item=profile['keyBindings'][role]
        binding.require(type(item)is dict and set(item)=={'path','sha256'} and type(item['path'])is str
            and Path(item['path']).is_absolute() and '..' not in Path(item['path']).parts
            and type(item['sha256'])is str and re.fullmatch('[0-9a-f]{64}',item['sha256']),
            'EXACT_EXISTING_KEY_REFERENCE_REQUIRED')
        rows.append({'role':role,'policyWindowCurrent':True,'expiresAt':key['expiresAt']})
    return rows

def executable(path):
    path=Path(path).resolve(strict=True)
    for parent in path.parents:
        row=parent.lstat()
        binding.require(stat.S_ISDIR(row.st_mode) and row.st_uid==row.st_gid==0 and not row.st_mode&0o022,
            'EXECUTABLE_ANCESTRY_UNPROVEN')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        row=os.fstat(fd)
        binding.require(stat.S_ISREG(row.st_mode) and row.st_uid==row.st_gid==0 and row.st_nlink==1
            and row.st_mode&0o111 and not row.st_mode&0o022 and 0<row.st_size<=64000000,'ROOT_EXECUTABLE_CUSTODY_REQUIRED')
        digest=hashlib.sha256();count=0
        while True:
            raw=os.read(fd,65536)
            if not raw:break
            count+=len(raw);binding.require(count<=64000000,'EXECUTABLE_UNBOUNDED');digest.update(raw)
        binding.require(count==row.st_size and binding.identity(row)==binding.identity(os.fstat(fd))
            ==binding.identity(path.lstat()),'EXECUTABLE_CHANGED')
        return {'path':str(path),'sha256':digest.hexdigest()}
    finally:os.close(fd)

def prepare(closure,report):
    binding.require(type(closure)is dict and set(closure)=={'sourceCommit','sourceHashes'}
        and type(closure['sourceCommit'])is str and re.fullmatch('[0-9a-f]{40}',closure['sourceCommit'])
        and type(closure['sourceHashes'])is dict and set(closure['sourceHashes'])==SOURCE_NAMES
        and all(type(v)is str and re.fullmatch('[0-9a-f]{64}',v) for v in closure['sourceHashes'].values()),
        'EXACT_PREPARATION_SOURCE_CLOSURE_REQUIRED')
    report['phase']='EXISTING_PUBLIC_AUTHORITY_READ'
    profile_raw=public_input(PROFILE);policy_raw=public_input(POLICY)
    profile,policy=binding.decode(profile_raw),binding.decode(policy_raw)
    role_rows=authority_metadata(profile,policy,int(time.time()))
    with binding.protected_parent() as directory:
        report['phase']='EXACT_RETAINED_IAM_REVIEW_READ'
        plan_raw=binding.read_member(directory,PLAN);snapshot_raw=binding.read_member(directory,SNAPSHOT)
        binding.require(binding.sha(plan_raw)==PLAN_HASH and binding.sha(snapshot_raw)==SNAPSHOT_HASH,'EXACT_RETAINED_REVIEW_HASH_REQUIRED')
        plan,snapshot=binding.decode(plan_raw),binding.decode(snapshot_raw)
        binding.require(plan.get('schema')=='ouf.policy-token-introspection-audience-review-plan.v1'
            and plan.get('snapshotHash')==SNAPSHOT_HASH and plan.get('runtimeAuthorityIssued')is False
            and plan.get('productionApplyReady')is False,'REVIEW_ONLY_IAM_PLAN_REQUIRED')
        change=plan.get('changeProposal')
        binding.require(type(change)is dict and change.get('operation')=='ADD_EXACT_CALLER_AUDIENCE_MAPPER'
            and change.get('applyAuthorized')is False and change.get('introspectionCheckMustRemainEnabled')is True
            and change.get('resource')=='clients/'+snapshot['client']['id']+'/protocol-mappers/models',
            'EXACT_RETAINED_ADDITIVE_MAPPER_REQUEST_REQUIRED')
        reader=metadata.Reader(report);report['phase']='CURRENT_SELECTED_IAM_BASELINE_READ'
        current=metadata.core(reader,snapshot['client']['id']);anchor=metadata.canonical(metadata.anchor(snapshot))
        binding.require(metadata.canonical(current)==anchor,'CURRENT_CORE_OR_SCOPE_DRIFT')
        mappers=metadata.complete_mappers(reader,snapshot,current)
        fresh=metadata.enriched(snapshot,current,mappers)
        binding.require(fresh==snapshot,'CURRENT_COMPLETE_MAPPER_BASELINE_DRIFT')
        report['phase']='EXECUTABLE_BINDING_OBSERVATION'
        programs={name:executable(path) for name,path in (('python',sys.executable),('openssl','/usr/bin/openssl'),('docker','/usr/bin/docker'))}
        version=subprocess.run([programs['openssl']['path'],'version'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,timeout=5,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'})
        match=re.match(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b',version.stdout)
        binding.require(version.returncode==0 and len(version.stdout)<=256 and match is not None,'OPENSSL_VERSION_OBSERVATION_UNPROVEN')
        programs['openssl']['version']=match[1].decode()
        report['phase']='STABLE_PREPARATION_INPUT_RECHECK'
        binding.require(mappers==metadata.complete_mappers(reader,snapshot,current)
            and metadata.canonical(metadata.core(reader,snapshot['client']['id']))==anchor,'CURRENT_IAM_BASELINE_CHANGED')
        binding.require(public_input(PROFILE)==profile_raw and public_input(POLICY)==policy_raw
            and binding.read_member(directory,PLAN)==plan_raw and binding.read_member(directory,SNAPSHOT)==snapshot_raw,
            'PREPARATION_INPUT_CHANGED')
        authority_metadata(profile,policy,int(time.time()))
        for name,item in programs.items():binding.require(executable(item['path'])=={k:item[k] for k in ('path','sha256')},'EXECUTABLE_BINDING_CHANGED')
        intake={'schema':'ouf.policy-token-governed-iam-preparation-intake.v1','reviewPlanHash':PLAN_HASH,'snapshotHash':SNAPSHOT_HASH,
            'authorityProfile':PROFILE,'trustPolicy':POLICY,'context':CONTEXT,'preparationSourceClosure':closure,
            'executablesProposedNotAccepted':programs,'metadataAndCoreDriftChecked':True,
            'observedClientMapperSetHash':binding.sha(binding.encoded(snapshot['client']['protocolMappers'])),
            'policyTokenIamPreparation':{'reviewPlanHash':PLAN_HASH,'resource':change['resource'],
                'mapperHash':binding.sha(binding.encoded(change['proposedMapper'])),'operation':'ADD_EXACT_CALLER_AUDIENCE_MAPPER',
                'maximumIamMutations':1,'introspectionCheckMustRemainEnabled':True,'runtimeAuthorityIssued':False},
            'observationsAreHistorical':True,'freshAuthorityAndReconciliationRequiredBeforePost':True,
            'applySourceClosurePrepared':False,'runtimeAuthorityIssued':False,'productionApplyReady':False,
            'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
        body=binding.encoded(intake);digest=binding.sha(body);name='policy-token-governed-iam-intake-'+digest+'.private.json'
        report['phase']='IMMUTABLE_PRIVATE_INTAKE_PUBLICATION'
        try:fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        except FileExistsError:binding.require(binding.read_member(directory,name)==body,'EXISTING_INTAKE_CONFLICT')
        else:
            report['privateEvidenceWrites']+=1
            try:
                with os.fdopen(os.dup(fd),'wb')as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
                os.fsync(directory)
            finally:os.close(fd)
        binding.require(binding.read_member(directory,name)==body,'INTAKE_PUBLICATION_RECONCILIATION_REQUIRED')
        report.update(status='GOVERNED_IAM_PREPARATION_INTAKE_COMPILED_NOT_ACCEPTED',phase='COMPILED_NOT_ACCEPTED',
            privateEvidencePath=str(binding.PARENT/name),privateEvidenceHash=digest,authorityProfileHash=PROFILE['sha256'],
            trustPolicyHash=POLICY['sha256'],currentRolePolicyObserved=True,completeIamBaselineMatched=True,
            preparationSourceModuleCount=len(SOURCE_NAMES),applySourceClosurePrepared=False,plannedIamMutations=1)
    return intake

def main(closure):
    report={'schema':'ouf.policy-token-governance-intake-receipt.v1','status':'BLOCKED','phase':'PREPARATION_DELIVERY',
        'privateEvidenceWrites':0,'privateKeysRead':0,'credentialFilesRead':0,'mountedTokenFilesRead':0,
        'signaturesIssued':0,'iamMutations':0,'serviceMutations':0,'providerCalls':0,'tokenGrantRequests':0,
        'runtimeAuthorityIssued':False,'productionApplyReady':False,'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
    try:
        binding.require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ROOT_ISOLATED_PREPARATION_REQUIRED')
        def timeout(*_):raise binding.CandidateDenied('FINITE_PREPARATION_DEADLINE')
        signal.signal(signal.SIGALRM,timeout);signal.alarm(200)
        prepare(closure,report);code=0
    except Exception as error:
        report['reason']=str(error) if type(error)is binding.CandidateDenied else type(error).__name__
        if isinstance(error,OSError):report['errno']=error.errno
        report['evidencePublicationMayBePartial']=report['phase']=='IMMUTABLE_PRIVATE_INTAKE_PUBLICATION';code=1
    finally:signal.alarm(0)
    print(binding.encoded(report).decode());return code
