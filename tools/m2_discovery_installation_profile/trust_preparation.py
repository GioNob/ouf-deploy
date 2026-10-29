"""Bounded public-store staging for a later coordinated installation preparation.

No CLI/delivery is published here. Existing consumed scopes remain read only.
No application secret, credential, signing key, IAM, SQL or lifecycle operation
is used. The root file is an unadmitted input, never runtime authority.
"""
import hashlib,os,stat,time
from pathlib import Path
from .material_preparation import Preparation,ReadOnlyEngine,stable_binding
from .custody_capture import attrs,decode,digest,process_pin,require
from .audit import path
from .trust_inputs import compile_trust

MATERIAL_ROOT=Path('/etc/ouf/deploy-snapshots/m2-discovery-material-roles-2d133870-20261029-v1')
MATERIAL_HASH='68daa9c9af2e3d5b41aceff988405e78a6fd3cb90a8c71f922816dd85964d392'
OWNER_REVIEW=Path('/etc/ouf/deploy-snapshots/semantic-registry-operational-review-e4e54229fd43165b0f11f9779d8428ac56a69201cff91c36fe1445cd305eed0f/review.json')
OWNER_REVIEW_HASH='b67488693c49241d8b6bdf1691216847bd07d7057895a26aa35946442ee450fe'
OWNER_CONFIGURATION_HASH='0b72275fcc2c51be0929ca0ba454de932ae4863af1b2410dd67bef61bf81e91a'


class TrustPreparation(Preparation):
    def __init__(self,scope):
        super().__init__(scope)
        self.counts.update(publicTrustStoresPrepared=0,publicTrustStoreReadbacks=0)

    def stage_public_store(self,raw):
        """One exact new immutable public store; claim precedes file creation."""
        self.guarded()
        require(type(raw) is bytes and 0<len(raw)<=4194304
                and self.counts['publicTrustStoresPrepared']==0,
                'ONE_BOUNDED_PUBLIC_TRUSTSTORE_REQUIRED')
        name='provider-trust.p12';sha=hashlib.sha256(raw).hexdigest()
        self.put('public-truststore-claim.json',{'name':name,'sha256':sha,
            'uid':0,'gid':10001,'mode':0o440,'attemptNotCompletion':True})
        directory=os.open(self.scope,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            try:
                os.fchown(fd,0,10001);os.fchmod(fd,0o440)
                with os.fdopen(os.dup(fd),'wb') as out:
                    require(out.write(raw)==len(raw),'PUBLIC_TRUSTSTORE_SHORT_WRITE')
                    out.flush();os.fsync(out.fileno())
                info=os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==10001
                        and stat.S_IMODE(info.st_mode)==0o440 and info.st_nlink==1
                        and info.st_size==len(raw),'PUBLIC_TRUSTSTORE_CUSTODY_UNPROVEN')
            finally:os.close(fd)
            os.fsync(directory)
        finally:os.close(directory)
        self.counts['publicTrustStoresPrepared']+=1
        require(self.read(self.scope/name,0,10001,0o440,4194304,'publicTrustStoreReadbacks')==raw,
                'PUBLIC_TRUSTSTORE_READBACK_UNPROVEN')
        return {'path':str(self.scope/name),'sha256':sha,'uid':0,'gid':10001,
                'mode':0o440,'metadata':attrs(info)}


def prepare(c,*,material_root=MATERIAL_ROOT,material_hash=MATERIAL_HASH,
            owner_review=OWNER_REVIEW,owner_review_hash=OWNER_REVIEW_HASH,
            owner_configuration_hash=OWNER_CONFIGURATION_HASH,pin=process_pin,
            boot_path=Path('/proc/sys/kernel/random/boot_id'),engine_factory=ReadOnlyEngine,
            now=time.time):
    """No default output scope or operator entrypoint; caller owns delivery."""
    require(type(c) is TrustPreparation,'EXACT_PUBLIC_TRUST_PREPARATION_REQUIRED')
    def metadata(selected,expected):
        value=decode(c.read(selected,0,0,0o600,2097152,'metadataReads'))
        require(digest(value)==expected,'EXACT_PUBLIC_TRUST_METADATA_BINDING_REQUIRED')
        return value
    material_path=material_root/'prepared-inputs.private.json'
    material=metadata(material_path,material_hash)
    review=metadata(owner_review,owner_review_hash)
    require(review.get('schema')=='ouf.registry-operational-installation-review.v1'
            and review.get('runtimeAuthorityIssued') is False
            and review.get('targetApplyAuthorized') is False
            and review.get('releaseAcceptance') is False
            and digest(review['configuration'])==owner_configuration_hash,
            'EXACT_RETAINED_IAM_OWNER_REVIEW_REQUIRED')
    root=Path(path(review['configuration']['destinations']['installationRoot']))
    configuration_path=root/'configuration.json'
    configuration=metadata(configuration_path,owner_configuration_hash)
    require(configuration==review['configuration']
            and configuration['tlsCa']['path']==str(root/'iam-ca.pem'),
            'EXACT_INSTALLED_PUBLIC_IAM_CONFIGURATION_REQUIRED')
    # The pure compiler checks the complete selected-role view and provenance.
    # Before reading public CA bytes or staging, check all current native pins.
    current=material['currentObservations'];pins=material['processPins'];roots=material['rootProcessPins']
    require(len(current)==13 and set(current)==set(pins) and set(roots)=={'pid1','engine'},
            'EXACT_PUBLIC_TRUST_THIRTEEN_PEER_GENERATION_REQUIRED')
    boot=boot_path.read_text().strip()
    def unchanged():
        c.guarded()
        require(boot_path.read_text().strip()==boot==material['bootId']
                and roots['pid1']==pin(1)
                and roots['engine']==pin(material['engineBinding']['peerCredentials'][0])
                and all(row['State']['Pid']==pins[alias]['pid']
                    and pin(pins[alias]['pid'])==pins[alias] for alias,row in current.items())
                and all(attrs(Path(p).lstat())==s for p,s in c.seals.items()),
                'PUBLIC_TRUST_SOURCE_OR_NATIVE_GENERATION_CHANGED')
    unchanged()
    engine=engine_factory(c,material['engineBinding'],[row['Id'] for row in current.values()])
    require(engine.get('/v1.44/info').get('ServerVersion')=='29.8.1',
            'QUALIFIED_PUBLIC_TRUST_ENGINE_REQUIRED')
    def observe():
        for alias,prior in sorted(current.items()):
            actual=engine.get('/v1.44/containers/'+prior['Id']+'/json')
            require(stable_binding(actual)==stable_binding(prior)
                    and actual['State']['Running'] is True and actual['State']['Paused'] is False
                    and actual['State']['Restarting'] is False
                    and pin(actual['State']['Pid'])==pins[alias],
                    'PUBLIC_TRUST_CURRENT_COHORT_CHANGED')
    observe();unchanged()
    iam=c.read(Path(configuration['tlsCa']['path']),0,0,0o600,4194304,'publicCertificateReads')
    provider=material['preparedCopies']['publicProviderCa']
    provider_path=Path(path(provider['path']))
    public=c.read(provider_path,0,0,0o600,1048576,'publicCertificateReads')
    require(attrs(provider_path.lstat())==provider['metadata'],
            'PREPARED_PUBLIC_PROVIDER_CA_CUSTODY_CHANGED')
    raw,proposal=compile_trust(material,{'path':str(material_path),'sha256':material_hash},
        configuration,{'path':str(configuration_path),'sha256':owner_configuration_hash},
        iam,public,now())
    unchanged()
    store=c.stage_public_store(raw)
    observe();unchanged()
    require(c.counts['engineGets']==27 and c.counts['metadataReads']==3
            and c.counts['publicCertificateReads']==2
            and c.counts['publicTrustStoresPrepared']==c.counts['publicTrustStoreReadbacks']==1
            and c.counts['credentialFileReads']==c.counts['applicationMacKeyReads']==0,
            'EXACT_BOUNDED_PUBLIC_TRUST_EFFECT_COUNTS_REQUIRED')
    record={'schema':'ouf.m2-discovery-prepared-public-trust.v1','proposal':proposal,
        'ownerReviewBinding':{'path':str(owner_review),'sha256':owner_review_hash},
        'publicStore':store,'bootId':boot,'processPins':pins,'rootProcessPins':roots,
        'currentCohortBindingHashes':{alias:digest(stable_binding(row)) for alias,row in current.items()},
        'sourceSeals':dict(c.seals),'counts':dict(c.counts),'currentPeerCount':13,
        'currentOwnerAdmissionProven':False,'targetTlsAdmissionProven':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'historicalAuthorityReused':False,
        'automaticReplayAllowed':False,'budgetReset':False}
    c.put('public-trust-inputs.json',record)
    return {'schema':'ouf.m2-discovery-public-trust-preparation-result.v1',
        'status':'PUBLIC_JAVA_TRUSTSTORE_PREPARED_NOT_ADMITTED','complete':True,
        'scope':str(c.scope),'scopeConsumed':True,'publicTrustInputsHash':digest(record),
        'counts':dict(c.counts),'currentPeerCount':13,
        'rawCredentialOrKeyValuesPrinted':False,'historicalSourceFilesPreserved':True,
        'targetTlsAdmissionProven':False,'currentOwnerAdmissionProven':False,
        'engineWrites':0,'iamRequests':0,'oauthRequests':0,'sqlSessions':0,
        'newKeysGenerated':0,'signaturesIssued':0,'containerLifecycleOperations':0,
        'imageImports':0,'budgetsGranted':0,'uploads':0,'newJobs':0,'resumes':0,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'historicalAuthorityReused':False,
        'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,
        'stableCapabilitiesOperationalProven':False,'releaseAcceptance':False}
