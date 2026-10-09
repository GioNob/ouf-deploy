"""Compute exact proposed context changes from retained private R3 inputs; no writes."""
import hashlib
import json
import os
from pathlib import Path
import sys
import traceback

OLD='/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby'
NEW='/run/containerd/io.containerd.runtime.v2.task/moby'
PACKAGE=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n')
CONTEXT=PACKAGE.parent/'semantic-provider-v2-approved-context-rsj9dtwr'

def proposed_context(value):
    assert value['bundleParent']==OLD
    changed=dict(value,bundleParent=NEW)
    assert [k for k in value if value[k]!=changed[k]]==['bundleParent']
    return changed

def main():
    report={'schema':'ouf.semantic-corrected-bundle-context-review.v1',
        'privateKeysRead':0,'signaturesIssued':0,'containerLifecycleOperations':0,
        'existingConfigurationWrites':0,'newPrivateInputFiles':0,'privateValuesPrinted':False,
        'acceptanceGranted':False,'startAuthorized':False,'notReleaseAcceptance':True}
    phase='READ_RETAINED_R3_INPUTS'
    try:
        assert os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode
        p=PACKAGE/'provider_transaction_intake.py'
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        try:raw=os.read(fd,131073)
        finally:os.close(fd)
        assert hashlib.sha256(raw).hexdigest()=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5'
        entry={'__name__':'context_review','__file__':str(p)}
        exec(compile(raw,str(p),'exec'),entry)
        entry['load'](PACKAGE)
        from compile_creation_frame_policy import compile_policy,canonical
        from authenticate_provider_transaction import TARGETS
        approval=entry['parse'](entry['read'](CONTEXT/'human-approval-binding.json'))
        assert approval['approvalRef']=='OUF_PROVIDER_V2_POST_SIGNATURE_RECOVERY_HUMAN_APPROVAL_20261009_093008'
        cfg=entry['parse'](entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
        assert set(cfg['recordsByRole'])==set(TARGETS)
        phase='COMPILE_EXACT_TWO_PROPOSED_CONTEXTS'
        report['roles']={}
        for role,bindings in cfg['recordsByRole'].items():
            raws={k:entry['bound'](v) for k,v in bindings.items()}
            values={k:entry['parse'](v) for k,v in raws.items()}
            assert values['context']['containerId']==TARGETS[role]['containerId']
            original=compile_policy(values['template'],values['launch'],values['context'])
            assert canonical(original)==raws['framePolicy']
            changed=proposed_context(values['context'])
            policy=compile_policy(values['template'],values['launch'],changed)
            # A rootfs relocation would need a separate full-frame review.
            assert canonical(policy)==raws['framePolicy']
            report['roles'][role]={'containerId':TARGETS[role]['containerId'],
                'previousContextHash':hashlib.sha256(raws['context']).hexdigest(),
                'proposedContextHash':hashlib.sha256(canonical(changed)).hexdigest(),
                'differentFields':['bundleParent'],'previousBundleParent':OLD,'proposedBundleParent':NEW,
                'completeCompiledPolicyUnchanged':True,
                'framePolicyHash':hashlib.sha256(raws['framePolicy']).hexdigest(),
                'applicationHash':hashlib.sha256(canonical(policy['expectedOci'])).hexdigest(),
                'unchangedInputHashes':{k:hashlib.sha256(v).hexdigest() for k,v in raws.items() if k!='context'}}
        report.update(status='EXACT_CONTEXT_CHANGE_REVIEW_PASS',phase=phase)
    except Exception as error:
        report.update(status='CONTEXT_REVIEW_BLOCKED',phase=phase,errorType=type(error).__name__,
            exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno}
                for t in traceback.extract_tb(error.__traceback__)[-4:]])
    print('OUF_CORRECTED_BUNDLE_CONTEXT_REVIEW='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='EXACT_CONTEXT_CHANGE_REVIEW_PASS' else 1

if __name__=='__main__':sys.exit(main())
