"""Pinned offline GitHub/Sigstore publisher verification under current parent.

Local reviewed bundle/trust roots and a pinned >=2.97.0 gh executable are used;
no GitHub credential, download, login or runtime signature is requested. Exact
certificate identity/repository IDs/source/signer digests and hosted runner are
checked independently of CLI filters. Predicate metadata never grants authority.
This proves selected artifact provenance only, not OCI/DB/mount/target admission.

Contract: https://cli.github.com/manual/gh_attestation_verify
"""
import copy,hashlib,os,re,stat,subprocess,tempfile
from pathlib import Path
from .custody_capture import decode,digest,encoded,require
from .current_cohort import INPUT_SCHEMA_V2,REVIEW_SCHEMA,validate_inputs
from .parent_authority import DiscoveryParentAuthority
from .node_owner import ObservationBudget
from .private_review import absolute,hashed
from tools.semantic_provider_deployment_authentication import ancestors,attributes

SCHEMA='ouf.discovery-current-publisher-inputs.v1'
ISSUER='https://token.actions.githubusercontent.com'
PREDICATE='https://slsa.dev/provenance/v1'


def reference(ref,maximum):
    require(type(ref) is dict and set(ref)=={'path','sha256','maximumBytes','metadataHash'}
        and hashed(ref['sha256']) and hashed(ref['metadataHash']) and type(ref['maximumBytes']) is int
        and 0<ref['maximumBytes']<=maximum,'EXACT_CURRENT_PUBLISHER_FILE_REFERENCE_REQUIRED')
    absolute(ref['path'])


def validate(inputs):
    fields={'schema','sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash',
        'ghExecutable','trustedRoot','artifacts'}
    require(type(inputs) is dict and set(inputs)==fields and inputs['schema']==SCHEMA
        and all(hashed(inputs[k]) for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash'))
        and len(encoded(inputs))<=65536,'EXACT_CURRENT_PUBLISHER_INPUTS_REQUIRED')
    reference(inputs['ghExecutable'],134217728);reference(inputs['trustedRoot'],1048576)
    rows=inputs['artifacts'];require(type(rows) is list and 1<=len(rows)<=32,'BOUNDED_REVIEWED_PUBLISHER_SUBJECT_SET_REQUIRED')
    roles=set();subjects=set()
    for row in rows:
        require(type(row) is dict and set(row)=={'role','subject','bundle','repository','repositoryId','ownerId',
            'workflowPath','sourceRef','sourceCommit','signerCommit'} and type(row['role']) is str
            and re.fullmatch('[a-z][A-Za-z0-9]{0,63}',row['role']) and row['role'] not in roles,
            'EXACT_CURRENT_PUBLISHER_SUBJECT_AND_IDENTITY_REQUIRED')
        reference(row['subject'],17179869184);reference(row['bundle'],8388608)
        require(row['subject']['path'] not in subjects and type(row['repository']) is str
            and re.fullmatch('[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+',row['repository'])
            and all(type(row[k]) is str and re.fullmatch('[1-9][0-9]{0,19}',row[k]) for k in ('repositoryId','ownerId'))
            and type(row['workflowPath']) is str and re.fullmatch(r'[.]github/workflows/[A-Za-z0-9_-]+[.]ya?ml',row['workflowPath'])
            and type(row['sourceRef']) is str and re.fullmatch(r'refs/(?:heads/[A-Za-z0-9_./-]+|tags/[A-Za-z0-9_.-]+|pull/[0-9]+/merge)',row['sourceRef'])
            and '..' not in row['sourceRef'] and all(type(row[k]) is str and re.fullmatch('[a-f0-9]{40}',row[k]) for k in ('sourceCommit','signerCommit')),
            'EXACT_CURRENT_PUBLISHER_CERTIFICATE_REPOSITORY_AND_SOURCE_REQUIRED')
        roles.add(row['role']);subjects.add(row['subject']['path'])
    return digest(inputs)


def bind_publisher_inputs(runtime_inputs,inputs):
    validate_inputs(runtime_inputs);sha=validate(inputs)
    require(all(runtime_inputs[k]==inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')),
        'SAME_CURRENT_COHORT_AND_PUBLISHER_INPUTS_REQUIRED')
    result=copy.deepcopy(runtime_inputs);extra=result.setdefault('additionalInputsHashes',{})
    require('custody' not in extra or extra['custody']==sha,'CURRENT_PUBLISHER_BINDING_CANNOT_BE_REPLACED')
    extra['custody']=sha;result['schema']=INPUT_SCHEMA_V2;validate_inputs(result);return result


def certificate_result(rows,subject):
    require(type(rows) is list and 1<=len(rows)<=8,'BOUNDED_VERIFIED_PUBLISHER_RESULTS_REQUIRED')
    identity='https://github.com/'+subject['repository']+'/'+subject['workflowPath']+'@'+subject['sourceRef']
    accepted=[]
    for row in rows:
        require(type(row) is dict and type(row.get('verificationResult')) is dict,'ACTUAL_GH_VERIFICATION_RESULT_REQUIRED')
        result=row['verificationResult'];certificate=result['signature']['certificate'];statement=result['statement']
        require(certificate['issuer']==ISSUER and certificate['subjectAlternativeName']=={'type':'URI','value':identity}
            and all(certificate.get(k)==v for k,v in {
                'sourceRepositoryURI':'https://github.com/'+subject['repository'],
                'sourceRepositoryIdentifier':subject['repositoryId'],'sourceRepositoryOwnerIdentifier':subject['ownerId'],
                'sourceRepositoryOwnerURI':'https://github.com/'+subject['repository'].split('/')[0],
                'sourceRepositoryDigest':subject['sourceCommit'],'sourceRepositoryRef':subject['sourceRef'],
                'buildSignerURI':identity,'buildSignerDigest':subject['signerCommit'],'runnerEnvironment':'github-hosted'}.items()),
            'EXACT_VERIFIED_PUBLISHER_CERTIFICATE_IDENTITY_REQUIRED')
        require(type(result.get('verifiedTimestamps')) is list and bool(result['verifiedTimestamps'])
            and statement.get('_type') in ('https://in-toto.io/Statement/v1','https://in-toto.io/Statement/v0.1')
            and statement.get('predicateType')==PREDICATE and type(statement.get('subject')) is list
            and 1<=len(statement['subject'])<=256,'WITNESSED_SLSA_PUBLISHER_STATEMENT_REQUIRED')
        matches=[v for v in statement['subject'] if type(v) is dict and v.get('digest')=={'sha256':subject['subject']['sha256']}]
        require(bool(matches),'VERIFIED_PUBLISHER_SUBJECT_DIGEST_MISMATCH')
        accepted.append({'certificateHash':digest(certificate),'verifiedTimestampsHash':digest(result['verifiedTimestamps']),
            'subjectSha256':subject['subject']['sha256']})
    return digest(accepted)


class CurrentPublisherCustody:
    def __init__(self,parent,runtime_inputs,inputs):
        require(type(parent) is DiscoveryParentAuthority,'ACTUAL_CURRENT_DISCOVERY_PARENT_FOR_PUBLISHER_REQUIRED')
        self.parent=parent;self.runtime_inputs=copy.deepcopy(runtime_inputs);self.inputs=copy.deepcopy(inputs)
        self.runtime_hash=validate_inputs(runtime_inputs);self.input_hash=validate(inputs);self.parent_hash=parent.sha;self.parent_id=id(parent)
        self.cache=None;self.cache_hash=None;self.guard()

    def guard(self):
        p,r,i=self.parent,self.runtime_inputs,self.inputs
        require(type(p) is DiscoveryParentAuthority and id(p)==self.parent_id and p.sha==self.parent_hash and validate(i)==self.input_hash
            and validate_inputs(r)==self.runtime_hash and r['schema']==INPUT_SCHEMA_V2
            and r['additionalInputsHashes'].get('custody')==self.input_hash
            and all(r[k]==i[k]==p.scope[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash'))
            and r['cohortManifestHash']==i['cohortManifestHash'],'EXACT_PARENT_BOUND_CURRENT_PUBLISHER_INPUTS_REQUIRED')
        component=p.review['components']['cohortInstallation'];admission=component['currentAdmission']
        require(admission['schema']==REVIEW_SCHEMA and admission['nativeRuntimeInputsHash']==self.runtime_hash
            and admission['requirements']['cohortManifestHash']==i['cohortManifestHash'],
            'CURRENT_REVIEWED_PUBLISHER_AND_COHORT_BINDING_REQUIRED')
        p.guard('cohortInstallation',component)

    def files(self):
        rows=[('ghExecutable',self.inputs['ghExecutable']),('trustedRoot',self.inputs['trustedRoot'])]
        for row in self.inputs['artifacts']:
            rows.extend((row['role']+'/'+key,row[key]) for key in ('subject','bundle'))
        return rows

    def pin(self,ref,*,executable=False,read=False,budget=None):
        path=Path(ref['path']);ancestors(path);info=path.lstat();pin=attributes(info)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
            and stat.S_IMODE(info.st_mode) in ({0o755} if executable else {0o400,0o440,0o600,0o644})
            and 0<info.st_size<=ref['maximumBytes'] and digest(pin)==ref['metadataHash'],
            'CURRENT_PUBLISHER_FILE_CUSTODY_CHANGED')
        if read:
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                require(attributes(os.fstat(fd))==pin,'CURRENT_PUBLISHER_FILE_REPLACED')
                h=hashlib.sha256();count=0
                while raw:=os.read(fd,1048576):
                    budget.check();count+=len(raw);require(count<=ref['maximumBytes'],'CURRENT_PUBLISHER_FILE_GREW')
                    h.update(raw)
                require(count==info.st_size and h.hexdigest()==ref['sha256'] and attributes(os.fstat(fd))==pin,
                    'CURRENT_PUBLISHER_FILE_BYTES_CHANGED')
            finally:os.close(fd)
        require(attributes(path.lstat())==pin,'CURRENT_PUBLISHER_FILE_CHANGED_DURING_READ');return pin

    def verify(self,row,budget,config):
        gh=self.inputs['ghExecutable']['path'];identity='https://github.com/'+row['repository']+'/'+row['workflowPath']+'@'+row['sourceRef']
        args=[gh,'attestation','verify',row['subject']['path'],'--bundle',row['bundle']['path'],
            '--custom-trusted-root',self.inputs['trustedRoot']['path'],'--repo',row['repository'],
            '--signer-digest',row['signerCommit'],
            '--source-digest',row['sourceCommit'],'--source-ref',row['sourceRef'],'--cert-identity',identity,
            '--cert-oidc-issuer',ISSUER,'--deny-self-hosted-runners','--predicate-type',PREDICATE,'--hostname','github.com','--format','json']
        # gh2.97 makes --cert-identity and --signer-workflow mutually exclusive.
        # Exact SAN plus the independent buildSignerURI check above binds the
        # workflow without weakening either identity or repository policy.
        result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            timeout=budget.remaining(20),env=self.environment(config))
        require(result.returncode==0 and 0<len(result.stdout)<=2097152,'CURRENT_OFFLINE_PUBLISHER_CRYPTOGRAPHY_UNPROVEN')
        return certificate_result(decode(result.stdout),row)

    @staticmethod
    def environment(config):
        return {'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':config,'GH_CONFIG_DIR':config,'XDG_CACHE_HOME':config,
            'GH_PROMPT_DISABLED':'1','GH_HOST':'github.com','GH_NO_UPDATE_NOTIFIER':'1','NO_COLOR':'1'}

    def observe(self):
        budget=ObservationBudget(180);self.guard();files=self.files()
        before={name:self.pin(ref,executable=name=='ghExecutable',read=self.cache is None,budget=budget) for name,ref in files}
        if self.cache is None:
            with tempfile.TemporaryDirectory(prefix='ouf-current-publisher-') as config:
                version=subprocess.run([self.inputs['ghExecutable']['path'],'--version'],stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=budget.remaining(5),env=self.environment(config))
                match=re.match(rb'gh version ([0-9]+)[.]([0-9]+)[.]([0-9]+)(?:\s|$)',version.stdout)
                require(version.returncode==0 and len(version.stdout)<=4096 and match is not None
                    and tuple(map(int,match.groups()))>=(2,97,0),'PINNED_PATCHED_GH_PUBLISHER_VERIFIER_REQUIRED')
                proofs={row['role']:self.verify(row,budget,config) for row in self.inputs['artifacts']}
        else:
            require(digest(self.cache)==self.cache_hash,'CURRENT_PUBLISHER_PROVENANCE_CACHE_CHANGED')
            proofs=self.cache['proofs'];require(self.cache['pins']==before,'CURRENT_PUBLISHER_VERIFIED_MATERIAL_CHANGED')
        require({name:self.pin(ref,executable=name=='ghExecutable') for name,ref in files}==before,
            'CURRENT_PUBLISHER_MATERIAL_CHANGED_DURING_CRYPTOGRAPHY')
        self.guard();budget.check()
        if self.cache is None:self.cache={'proofs':proofs,'pins':before};self.cache_hash=digest(self.cache)
        return {'schema':'ouf.discovery-current-publisher-byte-custody.v1','inputHash':self.input_hash,
            'parentAuthorityHash':self.parent_hash,'publisherEvidenceHash':digest(proofs),'artifactRoles':sorted(proofs),
            'currentFilePinsHash':digest(before),'localBundlesAndExplicitTrustRootUsed':True,
            'exactCertificateRepositoryIdsAndWorkflowVerified':True,'selectedArtifactPublisherCryptographyVerified':True,
            'targetOciOrMigrationArtifactMembershipProvenHere':False,'privateMountCustodyProvenHere':False,
            'fullCohortProven':False,'runtimeSignaturesIssued':0,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'releaseAcceptance':False}
