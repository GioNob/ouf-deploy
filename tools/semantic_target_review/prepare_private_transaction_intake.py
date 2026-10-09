"""Promote a new sealed source package and pure-preflight existing accepted inputs.

No keys, signing, role mandates, runtime publication, Docker or provider calls.
The source download is untrusted until every exact SHA256 has been checked.
Keep an incomplete new directory and its diagnosis; never retry blindly.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

SEED = json.loads(r'''{"manifestHash":"2699c82124b6bfcbd61991f09a96ebb5c6a2d336aaf3384dcae9288101b29de4","entryHash":"edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5","files":{"frame-observer.py":"122a1a44705892ba577d2e83467f39870627ffc16685f886757828611063b3fc","source/scripts/semantic_provider_admission_preparer.py":"67b40905ab00ab397b67c5de9a0f5256ca2e69163b92880bc66462b6d2ec973b","source/scripts/semantic_provider_creation_intent.py":"38a2b9c4fc7206d1d73b750316f1a7257e1da32857114775d185aea70a4d1dca","source/scripts/semantic_provider_deployment_broker.py":"943ebeaee7d714ea5b00e59a1bac680803bff097b7f9e7cb2f218a26c61bf140","source/scripts/semantic_provider_docker_runtime.py":"acf9c5140b700fbb4448d4b8eccd3d3ae3f7e6af5e173aa0474965ad170e6141","source/scripts/semantic_provider_installer_approval.py":"13e6d8cbec328d678f8f190bb2706606a22625329c1740f2b9c96fa4526d13e0","source/scripts/semantic_provider_node_attestor.py":"d0aa3bf56ebe6f69a324ab3260da60a737ab1508cec8adb644801999b29af191","source/scripts/semantic_provider_preexec_hook.py":"3489f894c45f182f0a2179bf431a8cc5bde6fe94bc4d9bfda67e134a23fde143","source/scripts/stage_semantic_local_producers_package.py":"12411ff383c29f64d37158626415a15c3acc8303d6dae729703ab0c8f0bb0028","source/tools/materialize_semantic_shared_faces.py":"66986436206e9448e0bad58b651f4802a53e54eb179327c7050d963c22f33b62","source/tools/materialize_southbound_kernel.py":"98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de","source/tools/materialize_southbound_lease_refresh.py":"1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084","source/tools/semantic_provider_creation_intent.py":"04d33434c23054ff96d8b03b44f7e65746b76317d9b2931db5b8223227f54314","source/tools/semantic_provider_deployment_admission.py":"fccde9a325939b400a95dc5e8714755727ed57b476b01c82019a15ffac8f8df4","source/tools/semantic_provider_deployment_authentication.py":"29e1942733abc74e8eb21eb927427c3e6e39806b06492f1dc614bd0805e53013","source/tools/semantic_provider_deployment_consumption.py":"053e2e5031cd51adf957388296a808cd8ba824dbc2ab671143e756312d050aef","source/tools/semantic_provider_deployment_producer.py":"582371358c769f7724fb76bb17fd5e11530a09ab06c19a3a66351fc77d984776","source/tools/semantic_provider_deployment_protocol.py":"53f5629c3a57de622e51a05f9bf86b29f34328bf5756857afa458fb738f24e15","source/tools/semantic_provider_deployment_reauthorization.py":"866801d9ef955371c66cac61bce7d0f807574ba08406adb39529155514dd818a","source/tools/semantic_provider_deployment_signing.py":"b079f11f1175afb3bcf3f2e33bfa3d06fe188a38fd8fa53b0e52d1d80cd31cad","source/tools/semantic_provider_dns.py":"c466172113d1ffe850bf2c69762113b55fbc65d9091c96dca98a74548fddf930","source/tools/semantic_provider_installer_approval.py":"75b637b792ba1c83da95166f6c16db4c200e5affbd9220875b00de8fdb9b2c72","source/tools/semantic_provider_lease_coordination.py":"e267e0f86637191b9830895930daa35afc10fec733b6957f427ab8a0ccddf587","source/tools/semantic_provider_lease_nft.py":"7a5f2b21c096228a3e4d298674e380f667c3004dd6d8ec19934a2302844c0f93","source/tools/semantic_provider_lease_owner.py":"92736eebeccf344e565186bce94d29c65ffe1d50638d57eae81486e7b26e884d","source/tools/semantic_provider_node_attestor.py":"ff1a13cea1c64b5ad76c09cd8b715507ee3f9016bdaf37c74e9804d575c4e91b","source/tools/semantic_provider_node_observation.py":"5a355a9904b6fc4bf665bb79c438e1cb9f3d11f8c2505b16df9834c046fde9c2","source/tools/semantic_provider_peer_bindings.py":"4d99b60459d7122b5126d8424fb6233a9f3de15858219cd9061131b23f45af8b","source/tools/semantic_provider_preexec.py":"53eb9b79efcdca0ffe93bb0c80a582a285caf9126fd97e930fa503b6106eb797","source/tools/semantic_provider_preexec_native.py":"ef0b98c96879933480a26418edc2b971b21a116509ac87cbc39e3b2062e7a528","utility/assemble_provider_profiles.py":"890dff15e3826175ef01467a812cdd523e8ea5d50a306ad8727f866475ab9734","utility/authenticate_provider_transaction.py":"b47e245abab2bb55ccd172c5e3f8da2a0b167e89c588811159f87cc4d929f258","utility/authenticated_runtime_switch.py":"ee35e3ac5ff3687f4261ababa1f9b92bb69b097aebe1eaa25a7a22b4fce0417e","utility/compile_creation_frame_policy.py":"36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d","utility/docker_cohort_activation.py":"df5f6c9a87d39f7c8120bdebb6af270d80db4a92d00d5b0b45e509fac8d8e17a","utility/guarded_runtime_switch.py":"a0b7a48eb93a331070a5258d1eedb954416557943d671e511ffe32101227911b","utility/issue_provider_transaction_authority.py":"eaed26b96c2ec6bdf3f0e295689f04b3d877e414528817a9b92391c38913c00a","utility/publish_provider_transaction.py":"761fcced56b43ea255f43f2efde11de116538289e24e2fca9b1f958a1ba80ff0","utility/transaction_guard_observation.py":"6c05d0db29abe2c950fb36d6e16c518ca03e4462c5e4d76c0ccdea54e3e2806d"},"roles":{"adapter":{"containerId":"f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67","applicationHash":"816cdcc143d99047151c337eefefe3df29d5ea8a999d50597f1d0b899cd295f4","transactionId":"a1c2768460dc488c73a9d5aabc71fa106373512eb8fe58510654326ce3743b07","transportHash":"bcf108752031439eef2ba1685ebf4aa9781229b2a7dca01ad6c9f97f5eeedab8","networkBindingCount":2,"reciprocalPeerDeclarations":1,"authorityMandatesPresent":false,"inputHashes":{"context":"ede2f4ee4de3b869d11e125cad094cbc5bad900bdb365a10d5d365d3104853ca","dependencyEvidence":"3e66cfb38a24923e1880cd1c28e53abdbd39d09fdca2f2cdfd105115f16b193b","deploymentConstraints":"2ea27b1d19bf4bd151b3f9199a651a5f693aced13ad9b02490485452aec82ef7","framePolicy":"e8047e92e8b3938abe67dc8e57f385fced9de1218db348b4723eb3c6d34867fd","launch":"061e2bd245d45d7e435ff86e07a6897413ae6c164d2d2c9ade2d455d80846943","preparerTemplate":"0a9a12a36b9f28eca2edcb3a2ad2c3d741559abb5d3699029bcc105c287dab53","provenanceEvidence":"0e5de8878e68d8fe555024cd5c0b911361c713e6547f93ebebd243ca34791f9f","template":"bf536f60c1d511f4cdbeb8546e84f46d426f693019938a0a9b4dbf76b3308e01"}},"southbound":{"containerId":"1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916","applicationHash":"fc99be8319b210322292a6f468121de97f764800f5e4fb9717e9ac85a9293322","transactionId":"a2cb1cd204239fba17e43f71530345ee6e50dde60967a2c40a605d9f70cd6266","transportHash":"494ce1976af397a48c27453eb1991d63c2fcd06b28e1b187931732a99be9f1b7","networkBindingCount":3,"reciprocalPeerDeclarations":1,"authorityMandatesPresent":false,"inputHashes":{"context":"e515366dbe8412bf261711ea98bcaac3e6d9e9d8bc3f77109829613ec166f4eb","dependencyEvidence":"5c60aa4def36d5ea09cb01f0b2a76ac93640b9df2878b5cdd5b83232b7db53c9","deploymentConstraints":"e349f6f9c059fa11415b6255a115d4d00972468e892624376b45d43365e718c2","framePolicy":"f49155fa412bb76d529713cb4ac2c253105884e9e72f7d2d74dfc5ccf9c5c822","launch":"cbc1f30c200a6a27e92b8055aa5542df30f7d124d08004d6f3bfe7dfb9ed2a39","preparerTemplate":"7ac15676ff00e38e1ac5bf5bd2356e42c34dbe9b485a5ba38d562380dcb1a894","provenanceEvidence":"75fc6a4022bbec82cad2e77e1d48fae3b3af77218edb1f8bade4d46c867dfa8b","template":"0ef8aa503bfb6a5c789000cd73de6e987d1a55688894475e555f4d566581ad05"}}},"sourceClosureHash":"dc87593c5c3b2e4859545de25b92702d93666e8d5c988f03e35fcf2df24c1ae4"}''')
INPUT_ROOT = Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-draft-g1yrsazc')
PHASE = 'VERIFY_DOWNLOADED_SOURCE_BYTES'
OUTPUT = None

def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def require(ok,reason):
    if not ok:raise ValueError(reason)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def read_exact(path,expected,private=False):
    path=Path(path)
    require(path.is_absolute() and '..' not in path.parts,'EXACT_ABSOLUTE_SOURCE_PATH_REQUIRED')
    require(path.resolve(strict=True)==path,'SOURCE_PATH_ALIAS_DENIED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=131072,'BOUNDED_SINGLE_SOURCE_FILE_REQUIRED')
        if private:
            require(before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==0o600,'EXISTING_PRIVATE_INPUT_CUSTODY_DRIFT')
            for parent in path.parents:
                info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'EXISTING_PRIVATE_INPUT_ANCESTOR_DRIFT')
        raw=os.read(fd,131073);after=os.fstat(fd)
        fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        require(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(path.lstat(),k) for k in fields),'SOURCE_CHANGED_DURING_READ')
        require(sha(raw)==expected,'SOURCE_OR_ACCEPTED_INPUT_HASH_DRIFT')
        return raw
    finally:os.close(fd)

def write(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())

def verify_download(directory):
    bindings={**SEED['files'],'intake-source-closure.json':SEED['manifestHash'],'provider_transaction_intake.py':SEED['entryHash']}
    return {name:read_exact(directory/name,expected) for name,expected in bindings.items()}

def sync_tree(directory):
    for parent in [*(p for p in directory.rglob('*') if p.is_dir()),directory,directory.parent]:
        fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)

def promote(directory,verified):
    for name,raw in verified.items():write(directory/name,raw)
    sync_tree(directory)
    # Load the exact verified entry without importing untrusted downloaded code.
    namespace={'__name__':'ouf_private_intake_source_validation','__file__':str(directory/'provider_transaction_intake.py')}
    exec(compile(verified['provider_transaction_intake.py'],namespace['__file__'],'exec'),namespace)
    sources,observer=namespace['load'](directory)
    require(len(sources)==29,'EXACT_REVIEWED_RUNTIME_SOURCE_COUNT_REQUIRED')
    closure={**{name:sha(raw) for name,raw in sources.items()},'frame-observer.py':sha(observer)}
    require(sha(encoded(closure))==SEED['sourceClosureHash'],'ACCEPTED_RUNTIME_OBSERVER_CLOSURE_DRIFT')
    return namespace

def main(download):
    global PHASE,OUTPUT
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_PREPARATION_REQUIRED')
    verified=verify_download(Path(download))
    PHASE='READ_EXISTING_ACCEPTED_INPUTS'
    records={role:{name:read_exact(INPUT_ROOT/role/(name+'.json'),expected,True)
        for name,expected in value['inputHashes'].items()} for role,value in SEED['roles'].items()}
    PHASE='PROMOTE_NEW_SEALED_INTAKE_SOURCE'
    OUTPUT=Path(tempfile.mkdtemp(prefix='semantic-provider-v2-transaction-source-',dir='/etc/ouf/deploy-snapshots'))
    os.chmod(OUTPUT,0o700);loader=promote(OUTPUT,verified)
    PHASE='PURE_COMPLETE_PAIR_PREFLIGHT'
    from authenticate_provider_transaction import preflight_input_pair
    checked=preflight_input_pair(records)
    # Re-read the sixteen existing private inputs after pure compilation.
    for role,value in SEED['roles'].items():
        for name,expected in value['inputHashes'].items():
            require(read_exact(INPUT_ROOT/role/(name+'.json'),expected,True)==records[role][name],'ACCEPTED_INPUT_CHANGED_AFTER_PREFLIGHT')
    report={'schema':'ouf.semantic-provider-intake-preparation.v1','status':'SEALED_SOURCE_AND_ACCEPTED_PAIR_PREFLIGHT_PASS',
        'directory':str(OUTPUT),'sourceFileCount':len(verified),'manifestHash':SEED['manifestHash'],
        'sourceClosureHash':SEED['sourceClosureHash'],'inputDirectory':str(INPUT_ROOT),
        'roles':{role:{'containerId':value['containerId'],'applicationHash':value['applicationHash'],
            'inputHashes':value['inputHashes']} for role,value in SEED['roles'].items()},
        'existingInputFilesReused':16,'newRoleMandates':0,'privateKeysRead':0,'signaturesIssued':0,
        'existingConfigurationWrites':0,'containerLifecycleOperations':0,'providerCalls':0,
        'startAuthorized':False,'notReleaseAcceptance':True}
    write(OUTPUT/'preparation-receipt.json',encoded(report));sync_tree(OUTPUT)
    print('OUF_PROVIDER_V2_INTAKE_PREPARATION='+json.dumps(report,sort_keys=True,separators=(',',':')))

if __name__=='__main__':
    try:
        require(len(sys.argv)==2,'EXACT_DOWNLOADED_PACKAGE_ARGUMENT_REQUIRED');main(sys.argv[1])
    except Exception as error:
        reason=str(error)
        if not re.fullmatch('[A-Z0-9_]{1,96}',reason):reason='PRIVATE_INTAKE_PREPARATION_UNPROVEN'
        report={'status':'BLOCKED','phase':PHASE,'reason':reason,'errorType':type(error).__name__,
            'directory':str(OUTPUT) if OUTPUT else None,'doNotRerunApply':OUTPUT is not None,
            'privateValuesPrinted':False,'privateKeysRead':0,'signaturesIssued':0,
            'existingConfigurationWrites':0,'containerLifecycleOperations':0,'startAuthorized':False,'notReleaseAcceptance':True}
        if isinstance(error,OSError):report['errno']=error.errno
        if OUTPUT:
            try:write(OUTPUT/'preparation-denial.json',encoded(report))
            except Exception:report['diagnosisSaved']=False
        print('OUF_PROVIDER_V2_INTAKE_PREPARATION='+json.dumps(report,sort_keys=True,separators=(',',':')));raise SystemExit(1)
