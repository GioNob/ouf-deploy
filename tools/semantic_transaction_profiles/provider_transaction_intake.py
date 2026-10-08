"""Root-private, source-sealed authenticated transaction intake/publication.

Default mode does not sign or change live configuration. Explicit approved
execution uses existing target policy/authority only.
Every uncertain attempt keeps its claim and safe stage-specific diagnosis.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

MANIFEST_SHA256 = '86fb90d3f224e3753e2117bc799c81a53391ce0d8209c29384e4dbaf9f172d2e'
AUTHORITY = {'path':'/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json',
             'sha256':'7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18'}
POLICY = {'path':'/etc/ouf/deploy-snapshots/semantic-trust-policy-preparation-20261004-172336/trust-policy.json',
          'sha256':'21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42'}
EMPTY_ADAPTER = {'path':'/etc/ouf/deploy-snapshots/semantic-v2-runtime-registration-krSL786w/adapter-configuration.json',
                 'sha256':'c3da65ad911e27836af7b0802ff464043d2354847ff21bbab0a1a3476134bf16'}
PYTHON = {'path':'/usr/bin/python3.13','sha256':'889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9'}
OPENSSL = {'path':'/usr/bin/openssl','sha256':'acc10176d038aeb7b2a77d9ec972ac2985857a7191f7aecb7c54ef0e2c7e9549'}
STAGE = 'VERIFY_INTAKE_CUSTODY'
SAVED = {}


class IntakeDenied(ValueError):pass


def require(ok, reason):
    if not ok:raise IntakeDenied(reason)


def digest(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def parse(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'DUPLICATE_INTAKE_JSON_KEY');value[key]=item
        return value
    try:return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
    except (UnicodeError,RecursionError,json.JSONDecodeError):raise IntakeDenied('INVALID_PRIVATE_INTAKE_JSON') from None


def attributes(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def read(path, executable=False):
    path=Path(path)
    require(path.is_absolute() and '..' not in path.parts,'EXPLICIT_PRIVATE_INTAKE_PATH_REQUIRED')
    for parent in (path.parent,*path.parent.parents):
        info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'ROOT_INTAKE_ANCESTOR_REQUIRED')
    limit=64000000 if executable else 131072
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
                and before.st_size<=limit and (before.st_mode&0o111 and not before.st_mode&0o022
                if executable else stat.S_IMODE(before.st_mode)==0o600),'ROOT_PRIVATE_INTAKE_FILE_REQUIRED')
        chunks=[];size=0
        while True:
            chunk=os.read(fd,min(65536,limit+1-size))
            if not chunk:break
            size+=len(chunk);require(size<=limit,'INTAKE_INPUT_UNBOUNDED');chunks.append(chunk)
        require(size==before.st_size and attributes(before)==attributes(os.fstat(fd))==attributes(path.lstat()),'PRIVATE_INTAKE_INPUT_CHANGED')
        return b''.join(chunks)
    finally:os.close(fd)


def bound(record, executable=False):
    require(type(record) is dict and set(record)=={'path','sha256'}
            and type(record['sha256']) is str and re.fullmatch('[0-9a-f]{64}',record['sha256']), 'EXACT_INTAKE_BINDING_REQUIRED')
    raw=read(record['path'],executable)
    require(digest(raw)==record['sha256'],'PRIVATE_INTAKE_HASH_DRIFT')
    SAVED[(record['path'],executable)]=raw
    return raw


def load(package):
    manifest_raw=bound({'path':str(package/'intake-source-closure.json'),'sha256':MANIFEST_SHA256})
    manifest=parse(manifest_raw)
    require(set(manifest)=={'sourceHashes','modules','utilities'},'EXACT_INTAKE_SOURCE_MANIFEST_REQUIRED')
    verified={name:bound({'path':str(package/name),'sha256':sha}) for name,sha in manifest['sourceHashes'].items()}
    require(all(Path(p).as_posix()==p and not Path(p).is_absolute() and '..' not in Path(p).parts for p in verified),
            'SEALED_SOURCE_PATH_REQUIRED')
    tool_package=types.ModuleType('tools');tool_package.__path__=[];sys.modules['tools']=tool_package
    for name in manifest['modules']:
        relative='source/tools/'+name+'.py';full='tools.'+name
        module=types.ModuleType(full);module.__package__='tools';module.__file__=str(package/relative)
        sys.modules[full]=module;setattr(tool_package,name,module)
        exec(compile(verified[relative],module.__file__,'exec'),module.__dict__)
    for name in manifest['utilities']:
        relative='utility/'+name+'.py';module=types.ModuleType(name);module.__file__=str(package/relative)
        sys.modules[name]=module;exec(compile(verified[relative],module.__file__,'exec'),module.__dict__)
    return {name.removeprefix('source/'):raw for name,raw in verified.items() if name.startswith('source/')},verified['frame-observer.py']


def operate(package, configuration, expected_configuration_hash, sources, observer):
    global STAGE
    from authenticate_provider_transaction import DOCUMENTS, TARGETS, AUTHORITIES, build_install_plan
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator, VerificationBudget
    from tools.semantic_provider_deployment_protocol import window
    from publish_provider_transaction import publish_plan, publish_once
    raw=bound({'path':str(configuration),'sha256':expected_configuration_hash});cfg=parse(raw)
    fields={'schema','authorityProfileBinding','runtimeAdapterBinding','pythonBinding','opensslBinding',
            'signatureDirectory','recordsByRole','outputRoot'}
    require(set(cfg)==fields and cfg['schema']=='ouf.semantic-provider-transaction-intake.v1','EXACT_TRANSACTION_INTAKE_REQUIRED')
    require(cfg['authorityProfileBinding']==AUTHORITY and cfg['runtimeAdapterBinding']==EMPTY_ADAPTER
            and cfg['pythonBinding']==PYTHON and {k:cfg['opensslBinding'][k] for k in ('path','sha256')}==OPENSSL,
            'EXISTING_TARGET_CUSTODY_BINDINGS_REQUIRED')
    require(Path(sys.executable).absolute()==Path(PYTHON['path']),'TARGET_INTAKE_INTERPRETER_DRIFT')
    bound(PYTHON,True);bound(OPENSSL,True)
    output=Path(cfg['outputRoot'])
    require(output.parent==Path('/etc/ouf/deploy-snapshots') and re.fullmatch('semantic-provider-v2-transaction-[A-Za-z0-9_-]+',output.name)
            and not os.path.lexists(output),'NEW_PRIVATE_TRANSACTION_ROOT_REQUIRED')
    claim={'schema':'ouf.semantic-provider-transaction-intake-claim.v1','configurationHash':digest(raw),
           'state':'READING','targetRuntimeChanged':False,'startAuthorized':False}
    publish_once(package/'intake-claim.json',encoded(claim))
    STAGE='READ_EXISTING_AUTHORITY_AND_COMPLETE_INPUTS'
    profile=parse(bound(AUTHORITY))
    require(profile['schema']=='ouf.semantic-existing-installation-authority-bindings.v1'
            and profile['authorities']==AUTHORITIES and profile['policyBinding']==POLICY,'EXISTING_AUTHORITY_PROFILE_DRIFT')
    authority={k:profile[k] for k in ('authorities','keyBindings','keyRefs')}
    # Key bindings are metadata only: bound/read is deliberately never called
    # on either installation-authority private key path.
    bound(POLICY);adapter=parse(bound(EMPTY_ADAPTER))
    require(set(cfg['recordsByRole'])==set(TARGETS),'EXACT_TWO_TARGET_INPUT_ROLES_REQUIRED')
    records={}
    key_paths={b['path'] for b in authority['keyBindings'].values()}
    for role,bindings in cfg['recordsByRole'].items():
        require(set(bindings)==DOCUMENTS,'COMPLETE_TARGET_INPUT_BINDINGS_REQUIRED')
        require(all(value['path'] not in key_paths and Path(value['path']).suffix=='.json'
                    and Path(value['path']).is_relative_to('/etc/ouf/deploy-snapshots')
                    for value in bindings.values()),'PRIVATE_AUTHORITY_KEY_OR_FOREIGN_INPUT_FORBIDDEN')
        records[role]={name:bound(record) for name,record in bindings.items()}
    for role,values in records.items():
        for name,signature_role in (('review','FINAL_DEPLOYMENT_APPROVAL'),('intent','DEPLOYMENT_INTENT'),
                                   ('liveAuthorization','CREATION_ATTESTATION'),('finalMandate','FINAL_DEPLOYMENT_APPROVAL')):
            path=Path(cfg['signatureDirectory'])/(digest(values[name])+'.'+signature_role+'.json')
            try:signature=read(path)
            except FileNotFoundError:
                from authenticate_provider_transaction import TransactionDenied
                raise TransactionDenied(STAGE,'SIGNED_TARGET_RECORD_MISSING',role,[name]) from None
            SAVED[(str(path),False)]=signature
    STAGE='AUTHENTICATE_COMPLETE_TARGET_TRANSACTION'
    budget=VerificationBudget(18)
    verifier=DetachedAuthenticator(POLICY,cfg['signatureDirectory'],cfg['opensslBinding'],budget=budget)
    crypto={'policyBinding':POLICY,'signatureDirectory':cfg['signatureDirectory'],'opensslBinding':cfg['opensslBinding']}
    plan=build_install_plan(str(output),str(output/'source'),records,authority,sources,observer,PYTHON,crypto,verifier,adapter)
    STAGE='RECHECK_AUTHENTICATED_INPUT_CUSTODY'
    budget.check()
    for (path,executable),prior in SAVED.items():require(read(path,executable)==prior,'AUTHENTICATED_INPUT_CUSTODY_CHANGED')
    for role,values in records.items():
        for name in ('review','intent','liveAuthorization','finalMandate'):window(parse(values[name]),__import__('time').time())
    STAGE='PUBLISH_PRIVATE_TRANSACTION'
    report=publish_plan(output,plan,sources,observer)
    # Only hashes and custody paths are returned; no private OCI/env/mount data.
    report={k:v for k,v in report.items() if k!='fileHashes'}
    publish_once(package/'intake-receipt.json',encoded(report))
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration',type=Path,required=True)
    parser.add_argument('--configuration-sha256',required=True)
    parser.add_argument('--execute-approved-transaction',action='store_true',
                        help='Consume explicit two-role root mandates, publish, switch and request controlled cohort admission')
    args=parser.parse_args();package=Path(__file__).absolute().parent
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_INTAKE_REQUIRED')
        require(package.parent==Path('/etc/ouf/deploy-snapshots')
                and re.fullmatch('semantic-provider-v2-transaction-source-[A-Za-z0-9_-]+',package.name),'EXACT_TRANSACTION_SOURCE_SNAPSHOT_REQUIRED')
        info=package.lstat();require(stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==info.st_gid==0,'PRIVATE_INTAKE_PACKAGE_REQUIRED')
        sources,observer=load(package)
        operation=execute_transaction if args.execute_approved_transaction else operate
        report=operation(package,args.configuration,args.configuration_sha256,sources,observer)
        print('OUF_PROVIDER_TRANSACTION_INTAKE='+encoded(report).decode());return 0
    except Exception as error:
        if type(getattr(error,'diagnosis',None)) is dict:diagnosis=error.diagnosis.copy()
        else:
            reason=str(error) if isinstance(error,IntakeDenied) and re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(error)) else 'PRIVATE_TARGET_INTAKE_UNPROVEN'
            diagnosis={'status':'BLOCKED','stage':STAGE,'reason':reason,'secretValuesPrinted':False,'startAuthorized':False}
        # Execution may have signed/published/switched or requested lifecycle.
        # Unknown counters are never rewritten to zero by the outer intake.
        attempted=os.path.lexists(package/'execution-claim.json')
        diagnosis.update(evidenceDirectory=str(package),doNotRerunApply=attempted or os.path.lexists(package/'intake-claim.json'))
        if args.execute_approved_transaction and attempted:
            diagnosis.update(containerLifecycleOperations=None,privateKeysRead=None,targetRuntimeChanged=None)
        else:diagnosis.update(containerLifecycleOperations=0,privateKeysRead=0,targetRuntimeChanged=False)
        try:
            from publish_provider_transaction import publish_once
            publish_once(package/'intake-denial.json',encoded(diagnosis))
        except Exception:diagnosis['diagnosisSaved']=False
        print('OUF_PROVIDER_TRANSACTION_INTAKE='+encoded(diagnosis).decode());return 1


def execute_transaction(package,configuration,expected_configuration_hash,sources,observer):
    """Explicit operator transaction; never manufacture missing target mandates.

    There is no target configuration/bootstrap supplied by this code. Complete
    independent records and already-approved root mandates must exist first.
    Policy/keys/Python/OpenSSL/Docker/guard/wrapper are fixed to this installation.
    """
    global STAGE
    from authenticate_provider_transaction import TARGETS,AUTHORITIES,build_install_plan
    from issue_provider_transaction_authority import issue_role_authority,INPUTS
    from publish_provider_transaction import publish_plan,publish_once
    from guarded_runtime_switch import custody,wrapper_bytes,switch_existing_wrapper
    from authenticated_runtime_switch import make_locked_switch_verifier
    from docker_cohort_activation import activate
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,VerificationBudget
    STAGE='VERIFY_EXPLICIT_EXECUTION_CONFIGURATION'
    raw=bound({'path':str(configuration),'sha256':expected_configuration_hash});cfg=parse(raw)
    fields={'schema','authorityProfileBinding','runtimeAdapterBinding','pythonBinding','opensslBinding',
        'recordsByRole','mandatesByRole','outputRoot','guardPointerBinding','commandBindings'}
    require(set(cfg)==fields and cfg['schema']=='ouf.semantic-provider-approved-transaction.v1',
            'EXACT_APPROVED_TARGET_TRANSACTION_REQUIRED')
    require(cfg['authorityProfileBinding']==AUTHORITY and cfg['runtimeAdapterBinding']==EMPTY_ADAPTER
        and cfg['pythonBinding']==PYTHON and {k:cfg['opensslBinding'][k] for k in ('path','sha256')}==OPENSSL,
        'EXISTING_TARGET_EXECUTION_BINDINGS_REQUIRED')
    require(Path(sys.executable).absolute()==Path(PYTHON['path']),'TARGET_EXECUTION_INTERPRETER_DRIFT')
    bound(PYTHON,True);bound(OPENSSL,True)
    profile=parse(bound(AUTHORITY));bound(POLICY);adapter=parse(bound(EMPTY_ADAPTER))
    require(profile['schema']=='ouf.semantic-existing-installation-authority-bindings.v1'
        and profile['authorities']==AUTHORITIES and profile['policyBinding']==POLICY,'TARGET_EXECUTION_AUTHORITY_DRIFT')
    authority={k:profile[k] for k in ('authorities','keyBindings','keyRefs')}
    output=Path(cfg['outputRoot'])
    require(output.parent==Path('/etc/ouf/deploy-snapshots') and re.fullmatch('semantic-provider-v2-transaction-[A-Za-z0-9_-]+',output.name)
        and not os.path.lexists(output),'NEW_APPROVED_TRANSACTION_ROOT_REQUIRED')
    require(set(cfg['recordsByRole'])==set(cfg['mandatesByRole'])==set(TARGETS),'EXACT_TWO_APPROVED_ROOT_ROLES_REQUIRED')
    key_paths={value['path'] for value in authority['keyBindings'].values()};records={}
    for role,bindings in cfg['recordsByRole'].items():
        require(set(bindings)==INPUTS,'EIGHT_COMPLETE_APPROVED_ROLE_INPUTS_REQUIRED')
        for value in [*bindings.values(),cfg['mandatesByRole'][role]]:
            require(value['path'] not in key_paths and Path(value['path']).suffix=='.json'
                and Path(value['path']).is_relative_to('/etc/ouf/deploy-snapshots'),'APPROVED_PRIVATE_ROLE_INPUT_PATH_REQUIRED')
        records[role]={name:bound(value) for name,value in bindings.items()}
        bound(cfg['mandatesByRole'][role])
    require(cfg['guardPointerBinding']['path']=='/etc/ouf/coordinated-boot-installation.json','EXISTING_GUARD_POINTER_REQUIRED')
    pointer=parse(bound(cfg['guardPointerBinding']))
    guard_root=Path('/etc/ouf/deploy-snapshots/semantic-coordinated-boot-install-v2-e4repg0a')
    require(set(pointer)=={'schema','receiptFile','receiptHash','observerFile','observerHash'}
        and pointer['schema']=='ouf.semantic-coordinated-boot-pointer.v1'
        and pointer['receiptFile']==str(guard_root/'installation-receipt.json')
        and pointer['observerFile']==str(guard_root/'transition-source.py'),'MIGRATED_GUARD_POINTER_SCOPE_DRIFT')
    receipt_binding={'path':pointer['receiptFile'],'sha256':pointer['receiptHash']}
    receipt=parse(bound(receipt_binding));bound({'path':pointer['observerFile'],'sha256':pointer['observerHash']})
    owner_hash='656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
    require(receipt['configurationHash']==owner_hash,'MIGRATED_TARGET_OWNER_SCOPE_DRIFT')
    owner=parse(bound({'path':str(guard_root/'coordinated-configuration.json'),'sha256':owner_hash}))
    require(set(cfg['commandBindings'])=={'nft','docker','systemctl'}
        and cfg['commandBindings']['docker']=={'path':'/usr/bin/docker','sha256':'7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40'}
        and cfg['commandBindings']['nft']=={'path':owner['nftPath'],'sha256':owner['nftSha256']}
        and cfg['commandBindings']['systemctl']['path']=='/usr/bin/systemctl','EXISTING_TARGET_NATIVE_COMMAND_SCOPE_REQUIRED')
    for value in cfg['commandBindings'].values():bound(value,True)
    wrapper=Path('/usr/local/sbin/ouf-semantic-admitted-v2')
    require(digest(custody(wrapper,0o755)[0])=='4956b05ec41fd54a27c00f2b6606d17be97dd84b3c09cff8b252d0fc886331bd',
            'ORIGINAL_EMPTY_TARGET_WRAPPER_REQUIRED')
    require(not os.path.lexists(package/'execution-claim.json'),'DO_NOT_REPLAY_APPROVED_TRANSACTION')
    STAGE='PREFLIGHT_BOTH_EXPLICIT_ROOT_MANDATES'
    from authenticate_provider_transaction import preflight_input_pair
    preflight_input_pair(records)
    signatures=package/'issued-signatures'
    crypto={'policyBinding':POLICY,'signatureDirectory':str(signatures),'opensslBinding':cfg['opensslBinding']}
    # No directory/claim/key mutation until both root approvals pass independently.
    for role in TARGETS:
        verifier=DetachedAuthenticator(POLICY,signatures,cfg['opensslBinding'],budget=VerificationBudget(18))
        mandate=cfg['mandatesByRole'][role]
        issue_role_authority(role,mandate,mandate['sha256'],records[role],authority,sources,observer,
                             verifier,package/'role-authority'/role,validate_only=True)
    for (path,executable),prior in SAVED.items():require(read(path,executable)==prior,'APPROVED_TRANSACTION_INPUT_CHANGED')
    publish_once(package/'execution-claim.json',encoded({'schema':'ouf.semantic-provider-execution-claim.v1',
        'configurationHash':digest(raw),'state':'ISSUING_APPROVED_ROLE_RECORDS','outputRoot':str(output),
        'mandateHashes':{role:value['sha256'] for role,value in cfg['mandatesByRole'].items()},'notReleaseAcceptance':True}))
    signatures.mkdir(mode=0o700);(package/'role-authority').mkdir(mode=0o700)
    STAGE='ISSUE_EXPLICIT_TARGET_ROLE_RECORDS'
    for role in TARGETS:
        directory=package/'role-authority'/role;directory.mkdir(mode=0o700)
        verifier=DetachedAuthenticator(POLICY,signatures,cfg['opensslBinding'],budget=VerificationBudget(18))
        mandate=cfg['mandatesByRole'][role]
        issued=issue_role_authority(role,mandate,mandate['sha256'],records[role],authority,sources,observer,verifier,directory)
        records[role].update({name:bound(value) for name,value in issued['records'].items()})
    for (path,executable),prior in SAVED.items():require(read(path,executable)==prior,'ISSUED_TRANSACTION_INPUT_CHANGED')
    STAGE='PUBLISH_AUTHENTICATED_TARGET_PROFILES'
    verifier=DetachedAuthenticator(POLICY,signatures,cfg['opensslBinding'],budget=VerificationBudget(18))
    plan=build_install_plan(str(output),str(output/'source'),records,authority,sources,observer,PYTHON,crypto,verifier,adapter)
    publish_plan(output,plan,sources,observer)
    STAGE='SWITCH_AUTHENTICATED_TARGET_RUNTIME'
    proposed=wrapper_bytes(PYTHON['path'],output/'source',output/'runtime-configuration-proposal.json')
    locked=make_locked_switch_verifier(output,records,authority,sources,observer,PYTHON,crypto,adapter,
        receipt_binding,owner_hash,cfg['commandBindings'])
    switch_existing_wrapper(wrapper,'4956b05ec41fd54a27c00f2b6606d17be97dd84b3c09cff8b252d0fc886331bd',proposed,
        output,owner['commonLockFile'],custody(owner['commonLockFile'],0o600)[1],locked)
    STAGE='CONTROLLED_TARGET_DOCKER_COHORT'
    report=activate(output,records,authority,sources,observer,PYTHON,crypto,adapter,
                    receipt_binding,owner_hash,cfg['commandBindings'])
    publish_once(package/'execution-receipt.json',encoded(report));return report


if __name__=='__main__':raise SystemExit(main())
