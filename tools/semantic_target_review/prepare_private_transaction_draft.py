"""Prepare new unsigned review inputs from existing fixed target snapshots.

Never sign, start, install, change runtime/guard, call a provider or read keys.
Known frame preparations are reused byte-for-byte. New documents are proposals;
they do not replace independent complete-frame/rootfs and role acceptance.
"""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import tempfile
import time

# Frozen repository facts are populated below before publication.
SEED = {'targets': {'adapter': {'containerId': 'f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67', 'imageManifestDigest': 'sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc', 'imageConfigDigest': 'sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320', 'runtimeSeal': {'schema': 'ouf.semantic-rootfs-seal.v1', 'sha256': '8744724088d02145b86b433058a4336fcb9c873a4a92e7009753209c284d3d73', 'entries': 3390, 'bytes': 46079786}}, 'southbound': {'containerId': '1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916', 'imageManifestDigest': 'sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366', 'imageConfigDigest': 'sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04', 'runtimeSeal': {'schema': 'ouf.semantic-rootfs-seal.v1', 'sha256': '52e06f47e1da5a107525e2260b9d375329997181dd13de7023654278aeaf3f39', 'entries': 7458, 'bytes': 255900260}}}, 'frameHashes': {'adapter': {'launch': '061e2bd245d45d7e435ff86e07a6897413ae6c164d2d2c9ade2d455d80846943', 'template': 'bf536f60c1d511f4cdbeb8546e84f46d426f693019938a0a9b4dbf76b3308e01', 'context': 'ede2f4ee4de3b869d11e125cad094cbc5bad900bdb365a10d5d365d3104853ca', 'policy': 'e8047e92e8b3938abe67dc8e57f385fced9de1218db348b4723eb3c6d34867fd'}, 'southbound': {'launch': 'cbc1f30c200a6a27e92b8055aa5542df30f7d124d08004d6f3bfe7dfb9ed2a39', 'template': '0ef8aa503bfb6a5c789000cd73de6e987d1a55688894475e555f4d566581ad05', 'context': 'e515366dbe8412bf261711ea98bcaac3e6d9e9d8bc3f77109829613ec166f4eb', 'policy': 'f49155fa412bb76d529713cb4ac2c253105884e9e72f7d2d74dfc5ccf9c5c822'}}, 'sourceClosureHash': 'dc87593c5c3b2e4859545de25b92702d93666e8d5c988f03e35fcf2df24c1ae4', 'pythonBinding': {'path': '/usr/bin/python3.13', 'sha256': '889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9'}, 'runtimeBinding': {'path': '/usr/bin/runc', 'sha256': '3c2ed035be881749630c18eb693dc373a518e938924c1b4c345db72d36a6a256'}, 'dependencies': {'adapter': {'databasePin': {'built': '2026-10-07T06:31:48Z', 'checksum': 'sha256:008449eb30e10988569b3bd54eb46158f33187211ba723f41ed9326ccfa1e174', 'path': 'vulnerability-db_v6.1.10_2026-10-07T00:34:45Z_1791354708.tar.zst', 'schemaVersion': 'v6.1.10', 'status': 'active'}, 'ignoredMatchCount': 0, 'imageConfigDigest': 'sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320', 'inventorySha256': '1024e4f3e53664afe7a20de6760388308f80f640f8e420acfea675b45c579c55', 'packageAlertCount': 0, 'reportSha256': '7c7bd5137efacd2369a4ca6aa7803e394c2b6a893809607b965986c9e5f3a86b', 'role': 'adapter', 'scanDatabaseBuilt': '2026-10-07T06:31:48Z', 'scanDatabaseSchemaVersion': 'v6.1.10', 'schema': 'ouf.semantic-provider-dependency-evidence.v1', 'severityCounts': {'Critical': 0, 'High': 0, 'Low': 0, 'Medium': 5, 'Negligible': 0, 'Unknown': 0}, 'sourceArtifactSha256': '2cdd7a73c1fc2a710f1e6604eb6cab2988492e4c45b5252defffa9832b91d9d0'}, 'southbound': {'databasePin': {'built': '2026-10-07T06:31:48Z', 'checksum': 'sha256:008449eb30e10988569b3bd54eb46158f33187211ba723f41ed9326ccfa1e174', 'path': 'vulnerability-db_v6.1.10_2026-10-07T00:34:45Z_1791354708.tar.zst', 'schemaVersion': 'v6.1.10', 'status': 'active'}, 'ignoredMatchCount': 0, 'imageConfigDigest': 'sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04', 'inventorySha256': '1024e4f3e53664afe7a20de6760388308f80f640f8e420acfea675b45c579c55', 'packageAlertCount': 0, 'reportSha256': 'd5fba2edae1da0dbb3fc69202a462d7ff274a04c6c128f3c7250fe6715216114', 'role': 'southbound', 'scanDatabaseBuilt': '2026-10-07T06:31:48Z', 'scanDatabaseSchemaVersion': 'v6.1.10', 'schema': 'ouf.semantic-provider-dependency-evidence.v1', 'severityCounts': {'Critical': 0, 'High': 0, 'Low': 18, 'Medium': 142, 'Negligible': 4, 'Unknown': 0}, 'sourceArtifactSha256': '2cdd7a73c1fc2a710f1e6604eb6cab2988492e4c45b5252defffa9832b91d9d0'}}, 'provenance': {'adapter': {'schema': 'ouf.semantic-provider-provenance-review-input.v1', 'role': 'adapter', 'imageManifestDigest': 'sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc', 'imageConfigDigest': 'sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320', 'originalArchiveSha256': '8301649b854a01d0306fabb14a5f93dd08eb4b1df98c2af356c0c84773821207', 'originalProvenanceSha256': 'dd647a14dd704c28a19ccb721880fbdbefc2d34878fcab54280ef5bc269e6f08', 'originalBuilderWorkflow': 'GioNob/ouf-semantic-registry/.github/workflows/semantic-image-remediation.yml@refs/pull/26/merge', 'originalSourceMerge': '0a1b4460c52c74cefe806286f043f71cbf5a5647', 'recoveredFreshVerificationRun': 37614224542, 'operatorFreshVerificationPreviouslyCompleted': True, 'labImageHumanApprovalRef': 'OUF_PROVIDER_V2_LAB_IMAGE_REVIEW_20261008_233809', 'evidenceCryptographicallyReverifiedByThisDraftHelper': False, 'completeFrameAcceptanceGranted': False}, 'southbound': {'schema': 'ouf.semantic-provider-provenance-review-input.v1', 'role': 'southbound', 'imageManifestDigest': 'sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366', 'imageConfigDigest': 'sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04', 'originalArchiveSha256': '1588c2391f9da45f300d16dd191cfe483dff83f81ed9424baec40201e64d7641', 'originalProvenanceSha256': 'dd647a14dd704c28a19ccb721880fbdbefc2d34878fcab54280ef5bc269e6f08', 'originalBuilderWorkflow': 'GioNob/ouf-semantic-registry/.github/workflows/semantic-image-remediation.yml@refs/pull/26/merge', 'originalSourceMerge': '0a1b4460c52c74cefe806286f043f71cbf5a5647', 'recoveredFreshVerificationRun': 37614224542, 'operatorFreshVerificationPreviouslyCompleted': True, 'labImageHumanApprovalRef': 'OUF_PROVIDER_V2_LAB_IMAGE_REVIEW_20261008_233809', 'evidenceCryptographicallyReverifiedByThisDraftHelper': False, 'completeFrameAcceptanceGranted': False}}}
OWNER = Path('/etc/ouf/deploy-snapshots/semantic-coordinated-boot-install-v2-e4repg0a/coordinated-configuration.json')
OWNER_HASH = '656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
FRAME = Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-frame-policies-5m18tpzh')
LAUNCH = Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-launch-inputs-7g1du3a6')
PHASE = 'READ_EXISTING_TARGET_INPUTS'
OUTPUT = None

def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def require(ok, reason):
    if not ok: raise ValueError(reason)

def private(path, expected=None):
    path=Path(path)
    require(path.resolve(strict=True)==path,'PRIVATE_INPUT_PATH_ALIAS_DENIED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
                and stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=131072,'PRIVATE_INPUT_CUSTODY_DRIFT')
        raw=os.read(fd,131073);after=os.fstat(fd)
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
        require(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k) for k in fields)
                and (expected is None or sha(raw)==expected),'PRIVATE_INPUT_HASH_DRIFT')
        return raw
    finally:os.close(fd)

def native(path):
    path=Path(path).resolve(strict=True)
    require(path.is_absolute(),'ABSOLUTE_COMMAND_REQUIRED')
    for parent in path.parents:
        info=parent.stat();require(info.st_uid==0 and not info.st_mode&0o022,'COMMAND_PARENT_CUSTODY_DRIFT')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
                and before.st_mode&0o111 and not before.st_mode&0o022 and before.st_size<=64000000,'COMMAND_CUSTODY_DRIFT')
        digest=hashlib.sha256();size=0
        while True:
            raw=os.read(fd,65536)
            if not raw:break
            size+=len(raw);require(size<=64000000,'COMMAND_UNBOUNDED');digest.update(raw)
        after=os.fstat(fd)
        require(before.st_mtime_ns==after.st_mtime_ns and before.st_ctime_ns==after.st_ctime_ns
                and size==before.st_size,'COMMAND_CHANGED_DURING_READ')
        return {'path':str(path),'sha256':digest.hexdigest()}
    finally:os.close(fd)

def proposals(owner, frames, commands, namespace):
    """Pure proposal: reciprocal peer declarations fixed before any create."""
    kernel=owner['kernel'];guard={'tableName':kernel['tableName'],'configurationHash':sha(encoded(kernel))}
    networks={}
    for role,suffix in (('adapter',3),('southbound',2)):
        networks[role]=[{'interface':iface,'bridge':bridge,'mac':f'02:42:ac:{octet}:00:0{suffix}',
            'ipv4':f'172.{subnet}.0.{suffix}','workloadRef':'ouf-semantic-'+role+'-v2',
            'bindingRef':role+'-'+purpose,'leaseGuard':copy.deepcopy(guard)}
            for purpose,iface,bridge,subnet,octet in (
                ('internal','oufint0','oufsp-int',21,'15'),('egress','oufeg0','oufsp-egress',22,'16'))]
    networks['southbound'].insert(0,{'interface':'oufback0','bridge':'br-113b5f0a3c53',
        'mac':'02:42:ac:12:00:0e','ipv4':'172.18.0.14','workloadRef':'ouf-semantic-southbound-v2',
        'bindingRef':'southbound-backend'})
    declarations={role:{'containerId':SEED['targets'][role]['containerId'],
        'applicationHash':sha(encoded(frames[role]['expectedOci'])),
        'networkBindings':copy.deepcopy(networks[role])} for role in networks}
    result={}
    for role in networks:
        peer='southbound' if role=='adapter' else 'adapter'
        transport=[{'purpose':'GATEWAY_ADAPTER','authorityRef':'ouf-lab-infrastructure-installer',
            'source':'172.21.0.2','destination':'172.21.0.3','protocol':'tcp','port':9443,
            'peerIngress':{'kind':'CREATED_CANDIDATE','declaration':declarations[peer],
                           'bindingRef':peer+'-internal'}}]
        if role=='southbound':
            transport.append({'purpose':'WORKLOAD_GATEWAY','authorityRef':'ouf-lab-infrastructure-installer',
                'source':'172.18.0.6','destination':'172.18.0.14','protocol':'tcp','port':10443,
                'peerIngress':{'kind':'BRIDGE_PORT','ifindex':1377}})
        candidate={'containerId':SEED['targets'][role]['containerId'],
            'transactionId':sha(encoded({'role':role,'ownerHash':OWNER_HASH,
                'applicationHash':declarations[role]['applicationHash'],
                'sourceClosureHash':SEED['sourceClosureHash']})),
            'networkBindings':networks[role],'transport':transport,
            'tableName':'ouf_v2_'+role,'runtimeBinding':SEED['runtimeBinding']}
        result[role]={'schema':'ouf.semantic-admission-preparer-template.v1',
            'pythonPath':SEED['pythonBinding']['path'],'pythonHash':SEED['pythonBinding']['sha256'],
            'commands':{name:b['path'] for name,b in commands.items()},
            'commandHashes':{name:b['sha256'] for name,b in commands.items()},'candidate':candidate,
            'kernel':copy.deepcopy(kernel),'dns':copy.deepcopy(owner['dns']),
            'coordinationBinding':copy.deepcopy(owner['binding']),'coordinationJournal':owner['journalFile'],
            'lockFile':owner['commonLockFile'],'budgetSeconds':5,'hostNetworkNamespace':namespace}
    return result

def publish(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)

def main():
    global PHASE,OUTPUT
    require(os.geteuid()==0,'OPERATOR_ROOT_PREPARATION_REQUIRED');os.umask(0o077)
    raw_owner=private(OWNER,OWNER_HASH);owner=json.loads(raw_owner)
    require(owner['schema']=='ouf.semantic-coordinated-owner-runtime.v1'
            and len(owner['kernel']['providerFlows'])==2
            and all(flow['addresses']==[] for flow in owner['kernel']['providerFlows']),
            'TWO_EMPTY_PROVIDER_FLOW_PROFILE_REQUIRED')
    records={};frames={}
    for role,hashes in SEED['frameHashes'].items():
        records[role]={name:private((LAUNCH if name=='launch' else FRAME)/(role+'.'+name+'.json'),expected)
                       for name,expected in hashes.items()}
        frames[role]=json.loads(records[role]['policy'])
    PHASE='BIND_NATIVE_COMMANDS_AND_EXISTING_QUIESCENT_JOURNAL'
    require(native(SEED['pythonBinding']['path'])==SEED['pythonBinding']
            and native(SEED['runtimeBinding']['path'])==SEED['runtimeBinding'],'PINNED_TARGET_BINARY_DRIFT')
    commands={name:native(shutil.which(name,path='/usr/sbin:/usr/bin:/sbin:/bin'))
              for name in ('nft','ip','nsenter','unshare','mount','umount')}
    require(commands['nft']=={'path':owner['nftPath'],'sha256':owner['nftSha256']},'INSTALLED_NFT_COMMAND_DRIFT')
    require(socket.if_nametoindex('vethca2111d')==1377
            and Path('/sys/class/net/vethca2111d/master').resolve(strict=True).name=='br-113b5f0a3c53',
            'EXISTING_SEMANTIC_HOST_PEER_PORT_DRIFT')
    lock=Path(owner['commonLockFile']);require(lock.resolve(strict=True)==lock,'GUARD_LOCK_PATH_ALIAS_DENIED')
    fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd);require(stat.S_ISREG(info.st_mode) and info.st_nlink==1
            and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o600,'GUARD_LOCK_CUSTODY_DRIFT')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        journal=private(owner['journalFile'])
        require(json.loads(journal)=={'schema':'ouf.semantic-lease-coordination.v1',**owner['binding'],
            'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[],[]]},
            'EXISTING_EMPTY_COORDINATION_REQUIRED')
        require(private(OWNER,OWNER_HASH)==raw_owner,'OWNER_CHANGED_DURING_PREPARATION')
        live=lock.lstat();require((info.st_dev,info.st_ino)==(live.st_dev,live.st_ino),'GUARD_LOCK_INODE_DRIFT')
        namespace=os.stat('/proc/self/ns/net').st_ino
        values=proposals(owner,frames,commands,namespace)
    finally:os.close(fd)
    PHASE='PUBLISH_NEW_UNSIGNED_REVIEW_INPUTS'
    OUTPUT=Path(tempfile.mkdtemp(prefix='semantic-provider-v2-transaction-draft-',dir='/etc/ouf/deploy-snapshots'))
    report={'schema':'ouf.semantic-provider-target-input-draft.v1','status':'UNSIGNED_INPUT_DRAFT_PREPARED','directory':str(OUTPUT),'roles':{},
        'sourceClosureHash':SEED['sourceClosureHash'],'installedOwnerHash':OWNER_HASH,
        'scope':'UNSIGNED_REVIEW_INPUTS_ONLY','nativeGuardObservedHere':False,
        'existingSemanticPeerIfindex':1377,'semanticPeerPortFreshnessVerifiedHere':False,
        'existingSemanticHostPortIndexAndBridgeVerifiedHere':True,
        'privateKeysRead':0,'signaturesIssued':0,'existingConfigurationWrites':0,
        'newPrivateInputFiles':16,'newReceiptFiles':1,'privateValuesPrinted':False,
        'containerLifecycleOperations':0,'providerCalls':0,'roleMandatesCreated':0,
        'acceptanceGranted':False,'startAuthorized':False,'notReleaseAcceptance':True}
    for role in values:
        directory=OUTPUT/role;directory.mkdir(mode=0o700)
        role_records={('framePolicy' if name=='policy' else name):raw for name,raw in records[role].items()}
        role_records['preparerTemplate']=encoded(values[role])
        role_records['deploymentConstraints']=encoded({'schema':'ouf.semantic-provider-deployment-constraints.v1',
            'role':role,**SEED['targets'][role],'manifest':frames[role]['manifest'],
            'framePolicyHash':sha(role_records['framePolicy']),'allowedRuntime':'ouf-semantic-admitted-v2',
            'installedOwnerHash':OWNER_HASH,'providerLeaseAuthorized':False,'automaticRetryAuthorized':False})
        role_records['provenanceEvidence']=encoded(SEED['provenance'][role])
        role_records['dependencyEvidence']=encoded(SEED['dependencies'][role])
        hashes={}
        for name,raw in role_records.items():publish(directory/(name+'.json'),raw);hashes[name]=sha(raw)
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
        report['roles'][role]={'containerId':SEED['targets'][role]['containerId'],'inputHashes':hashes,
            'applicationHash':sha(encoded(frames[role]['expectedOci'])),
            'transactionId':values[role]['candidate']['transactionId'],
            'transportHash':sha(encoded({k:values[role]['candidate'][k] for k in ('networkBindings','transport','tableName')})),
            'networkBindingCount':len(values[role]['candidate']['networkBindings']),
            'reciprocalPeerDeclarations':1,'authorityMandatesPresent':False}
    publish(OUTPUT/'draft-receipt.json',encoded(report))
    fd=os.open(OUTPUT,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    print('OUF_PROVIDER_V2_TRANSACTION_DRAFT='+encoded(report).decode())

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error) if type(error) is ValueError and str(error).isupper() else type(error).__name__
        diagnosis={'status':'BLOCKED','phase':PHASE,'reason':reason,
            'evidenceDirectory':None if OUTPUT is None else str(OUTPUT),'doNotRerunApply':OUTPUT is not None,
            'privateValuesPrinted':False,'privateKeysRead':0,'containerLifecycleOperations':0,
            'startAuthorized':False,'notReleaseAcceptance':True}
        if OUTPUT is not None:
            try:publish(OUTPUT/'draft-denial.json',encoded(diagnosis))
            except Exception:diagnosis['diagnosisSaved']=False
        print('OUF_PROVIDER_V2_TRANSACTION_DRAFT='+encoded(diagnosis).decode());raise SystemExit(1)
