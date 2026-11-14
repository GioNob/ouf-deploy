#!/usr/bin/env python3
"""Prepare unsigned inputs only; never create/sign/publish/start a runtime."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import tempfile
import traceback
import types
from datetime import datetime, timezone

BOOT_SCRIPT = 'activate-discovery-coordinator-boot-20261109.py'
BOOT_SHA = '3538db93c67b230cf5aacdb45250df6c39da5f9727528859b8a91c0bfff2ae48'
BOOT_RESULT = Path('/var/lib/ouf-storage-migration/discovery-boot-activation-f_9dwjoh/result.json')
BOOT_RESULT_SHA = 'ffd4362f54b766a25c7afa0dc9f62129284a72b616cfdf518c39a79f64fea585'
INSTALLATION = Path('/etc/ouf/deploy-snapshots/semantic-coordinated-boot-install-successor-b3c3uwwt')
CLAIM = Path('/var/lib/ouf-storage-migration/discovery-generation-inputs-20261109')
COORDINATION = ('kernel','dns','coordinationBinding','coordinationJournal','lockFile')
TEMPLATE_FIELDS = {'schema','pythonPath','pythonHash','commands','commandHashes','candidate',
                   *COORDINATION,'budgetSeconds','hostNetworkNamespace'}


def need(value, reason):
    if not value: raise RuntimeError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'


def boot_module():
    path=Path(__file__).with_name(BOOT_SCRIPT);raw=path.read_bytes()
    need(sha(raw)==BOOT_SHA,'PINNED_BOOT_HELPER_CHANGED')
    ns={'__name__':'generation_boot_dependency','__file__':str(path)}
    exec(compile(raw,str(path),'exec'),ns)
    return types.SimpleNamespace(**ns)


def verify_boot_result(raw):
    need(sha(raw)==BOOT_RESULT_SHA,'EXACT_COMPLETED_BOOT_RECEIPT_REQUIRED')
    value=json.loads(raw)
    need(value['status']=='DISCOVERY_SUCCESSOR_BOOT_BOUND' and value['phase']=='COMPLETE'
         and value['installationDirectory']==str(INSTALLATION)
         and value['installedObserverPassed'] is True and value['activeInstallationPointerChanged'] is True
         and value['newGenerationAdmitted'] is False,'COMPLETED_QUIESCED_BOOT_REQUIRED')


def owner_selection(owner):
    return {'kernel':owner['kernel'],'dns':owner['dns'],'coordinationBinding':owner['binding'],
            'coordinationJournal':owner['journalFile'],'lockFile':owner['commonLockFile']}


def identity_paths(value, path=''):
    """List identity locations without treating historical values as new inputs."""
    result=[]
    if isinstance(value,dict):
        for key,item in value.items():
            child=path+'/'+key.replace('~','~0').replace('/','~1')
            if 'containerid' in key.lower() or key=='transactionId': result.append(child)
            result.extend(identity_paths(item,child))
    elif isinstance(value,list):
        for i,item in enumerate(value): result.extend(identity_paths(item,path+'/'+str(i)))
    return sorted(set(result))


def prepare_role(role, old_cid, template, old_owner, new_owner):
    need(role in ('adapter','southbound') and re.fullmatch('[0-9a-f]{64}',old_cid), 'EXACT_HISTORICAL_ROLE_REQUIRED')
    need(set(template)==TEMPLATE_FIELDS and template['schema']=='ouf.semantic-admission-preparer-template.v1',
         'EXACT_PREPARER_TEMPLATE_REQUIRED')
    need(type(template['candidate']) is dict and template['candidate'].get('containerId')==old_cid,
         'BOUND_HISTORICAL_CANDIDATE_REQUIRED')
    old,new=owner_selection(old_owner),owner_selection(new_owner)
    need({k:template[k] for k in COORDINATION}==old,'HISTORICAL_COORDINATOR_TEMPLATE_MISMATCH')
    need(all(old[k]==new[k] for k in ('kernel','dns','lockFile'))
         and old['coordinationJournal']!=new['coordinationJournal']
         and old['coordinationBinding']['transactionId']!=new['coordinationBinding']['transactionId'],
         'EXACT_SUCCESSOR_COORDINATION_DELTA_REQUIRED')
    # No executable preparer, runtime config or mandate is emitted. The complete
    # historical template is custody evidence, explicitly separate from selection.
    return {'schema':'ouf.discovery-role-generation-inputs.v1','role':role,
            'state':'UNSIGNED_INPUTS_ONLY','historicalTemplate':copy.deepcopy(template),
            'successorCoordination':copy.deepcopy(new),
            'historicalIdentityPaths':identity_paths(template),
            'requiredFreshInputs':['containerId','transactionId','currentPeerBindings',
                'independentExpectedOciAndRootfs','currentReviewedAuthority','initialMandates'],
            'historicalIdentityReuseAllowed':False,'runtimeConfigurationProduced':False,
            'signaturesProduced':0,'leaseAuthorized':False,'startAuthorized':False}


def write_inputs(save, root, plan, roles):
    need(set(roles)=={'adapter','southbound'},'EXACT_TWO_ROLE_INPUTS_REQUIRED')
    files={role+'-inputs.private.json':encoded(body) for role,body in roles.items()}
    files['generation-plan.private.json']=encoded(plan)
    for name,raw in files.items(): save(root/name,raw)
    for name,raw in files.items(): need((root/name).read_bytes()==raw,'PREPARED_INPUT_READBACK_FAILED')
    return {name:sha(raw) for name,raw in files.items()}


def main():
    report={'schema':'ouf.discovery-generation-input-preparation.v1','status':'HELD',
        'observedAt':datetime.now(timezone.utc).isoformat(),'operationIntentPresent':False,
        'containerCreates':0,'serviceStarts':0,'serviceStops':0,'daemonReloads':0,'nftWrites':0,
        'runtimeWrapperChanged':False,'activeInstallationPointerChanged':False,'historicalJournalWrites':0,
        'credentialFileContentsRead':0,'signaturesProduced':0,'providerRequests':0,'databaseRequests':0,
        'tokenRequests':0,'dnsQueries':0,'s3Requests':0,'businessRequestsIssued':0,
        'newGenerationAdmitted':False,'providerReady':False,'leaseAuthorized':False,'startAuthorized':False,
        'automaticReplayAllowed':False}
    work=None;c=None
    def deadline(*_): raise RuntimeError('GENERATION_INPUT_DEADLINE')
    signal.signal(signal.SIGALRM,deadline);signal.alarm(180)
    try:
        need(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
        os.umask(0o077);b=boot_module();c=b.dependency()
        need(not os.path.lexists(CLAIM),'EXISTING_GENERATION_PREPARATION_PRESERVED')
        verify_boot_result(c.p.read_private(BOOT_RESULT))
        need(c.p.read_private(b.CLAIM/'complete.json')==c.p.read_private(BOOT_RESULT),'BOOT_COMPLETION_CHANGED')
        pointer_raw=c.p.read_private(b.POINTER);pointer=c.l.parse(pointer_raw)
        need(pointer['receiptFile']==str(INSTALLATION/'installation-receipt.json')
             and pointer['observerFile']==str(INSTALLATION/'transition-source.py')
             and pointer['observerHash']==BOOT_SHA,'EXACT_ACTIVE_BOOT_INSTALLATION_REQUIRED')
        receipt=c.l.parse(b.sealed(c,INSTALLATION/'installation-receipt.json',pointer['receiptHash']))
        b.sealed(c,INSTALLATION/'transition-source.py',BOOT_SHA)
        old=b.sealed(c,INSTALLATION/'previous/active-pointer.json',receipt['previousPointerSha256'])
        ctx=b.context(c,old)
        work=Path(tempfile.mkdtemp(prefix='discovery-generation-inputs-',dir=CLAIM.parent))
        report['privateEvidenceDirectory']=str(work)
        with b.locks(c,ctx):
            report['phase']='VERIFY_CURRENT_BOOT_AND_TERMINAL_PROVIDERS'
            for name,path in b.UNITS.items(): b.sealed(c,path,receipt['artifactHashes'][name])
            need(receipt['guardCommand']==b.command_for(b.STAGED,b.PROFILE_SHA),'SUCCESSOR_COMMAND_CHANGED')
            before=b.loaded(receipt['guardCommand']);b.native_guard(c,ctx,work)
            bindings={};roles={}
            def read(path,digest):
                raw=b.sealed(c,path,digest);bindings[str(path)]=digest;return c.l.parse(raw)
            cfg=read(c.s.exact_path(ctx.cfg_path),c.l.CONFIG_SHA)
            for role in ('adapter','southbound'):
                cid=c.s.PINS[role][0];root=ctx.registry/cid
                entry=cfg['candidates'][cid]
                need(entry['admissionConfiguration']==str(root/'broker.json'),'BOUND_BROKER_PATH_REQUIRED')
                broker=read(root/'broker.json',entry['admissionConfigurationHash'])
                ref=broker['preparerTemplate'];template=read(c.s.exact_path(ref['path']),ref['sha256'])
                roles[role]=prepare_role(role,cid,template,ctx.old_owner,ctx.owner)
            plan={'schema':'ouf.discovery-generation-input-plan.v1','state':'UNSIGNED_INPUTS_ONLY',
                'bootResultSha256':BOOT_RESULT_SHA,'activePointerSha256':sha(pointer_raw),
                'bootInstallation':str(INSTALLATION),'successorOwnerSha256':b.OWNER_SHA,
                'sourceBindings':bindings,'roles':['adapter','southbound'],
                'authorityIssued':False,'creationRequestProduced':False,'runtimeConfigurationProduced':False,
                'requiresCurrentSemanticPeerReview':True,'historicalAuthorityReusable':False}
            for path,digest in bindings.items(): b.sealed(c,c.s.exact_path(path),digest)
            need(c.p.read_private(b.POINTER)==pointer_raw,'BOOT_POINTER_CHANGED')
            need(b.loaded(receipt['guardCommand'])==before,'LOADED_BOOT_CHANGED')
            report['phase']='WRITE_PRIVATE_UNSIGNED_INPUTS'
            os.mkdir(CLAIM,0o700);report['operationIntentPresent']=True
            c.p.save(CLAIM/'intent.json',encoded({'bootResultSha256':BOOT_RESULT_SHA,'evidenceDirectory':str(work)}))
            root=Path(tempfile.mkdtemp(prefix='discovery-generation-inputs-',dir=c.m.SNAPSHOTS))
            report['preparationDirectory']=str(root)
            hashes=write_inputs(c.p.save,root,plan,roles)
            b.native_guard(c,ctx,work,terminal=False)
            need(c.p.read_private(b.POINTER)==pointer_raw,'BOOT_POINTER_CHANGED')
            for path,digest in bindings.items(): b.sealed(c,c.s.exact_path(path),digest)
            need(b.loaded(receipt['guardCommand'])==before,'LOADED_BOOT_CHANGED')
            report.update(status='DISCOVERY_GENERATION_INPUTS_PREPARED',phase='COMPLETE',
                fileHashes=hashes,rolesPrepared=2,activeCoordinationState='QUIESCED',
                historicalIdentityReferenceCounts={role:len(body['historicalIdentityPaths']) for role,body in roles.items()},
                pendingFreshIdentityAndAuthority=True,inputsAreNotRuntimeProfiles=True)
            c.p.save(root/'preparation-receipt.json',encoded(report));c.p.save(CLAIM/'complete.json',encoded(report))
    except Exception as exc:
        reason=str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(exc)) else type(exc).__name__
        report.update(status='HELD',reason=reason,errorLocation=[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}
            for f in traceback.extract_tb(exc.__traceback__)[-3:]])
    finally:
        signal.alarm(0)
        if work is not None and c is not None:c.p.save(work/'result.json',encoded(report))
    print(json.dumps(report,sort_keys=True));return 0 if report['status']=='DISCOVERY_GENERATION_INPUTS_PREPARED' else 1


if __name__=='__main__':sys.exit(main())
