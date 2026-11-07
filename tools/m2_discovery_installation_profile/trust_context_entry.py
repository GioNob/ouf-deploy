"""One fresh preparation scope; no installation or runtime authority."""
import os,re
from pathlib import Path
from .custody_capture import decode,digest,attrs,require,Stop
from .trust_preparation import TrustPreparation,prepare,MATERIAL_ROOT,MATERIAL_HASH
from .native_context import collect

SCOPE=Path('/etc/ouf/deploy-snapshots/m2-discovery-trust-context-68daa9c9-20261029-v1')


def main():
    c=None
    try:
        c=TrustPreparation(SCOPE);trust=prepare(c)
        p=MATERIAL_ROOT/'prepared-inputs.private.json';before=list(c.seals[str(p)])
        material=decode(c.read(p,0,0,0o600,2097152,'metadataReads'))
        require(digest(material)==MATERIAL_HASH and attrs(p.lstat())==before,
                'SAME_EXACT_MATERIAL_RECORD_REQUIRED_FOR_CONTEXT')
        context=collect(c,material=material,trust_result=trust)
        result={**trust,'schema':'ouf.m2-discovery-trust-context-preparation-result.v1',
            'status':'PUBLIC_TRUST_AND_NATIVE_CONTEXT_PREPARED_NOT_ADMITTED',
            'counts':dict(c.counts),'nativeContextHash':context['nativeContextHash'],
            'currentPeerCount':context['currentPeerCount'],'nativeNodesObserved':2,
            'nativeContextIsExpectedPolicy':False,'currentTlsOrIamAdmissionProven':False}
        c.put('result.json',result);code=0
    except Exception as error:
        reason=str(error)
        result={'schema':'ouf.m2-discovery-trust-context-preparation-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason if isinstance(error,(Stop,ValueError)) and re.fullmatch('[A-Z][A-Z0-9_]{0,160}',reason)
                         else 'PUBLIC_TRUST_AND_NATIVE_CONTEXT_UNPROVEN',
            'complete':False,'scope':str(SCOPE),'scopeConsumed':os.path.lexists(SCOPE),
            'counts':dict(c.counts) if c else {},
            'partialPublicStorePreserved':bool(c and c.counts['publicTrustStoresPrepared']),
            'rawCredentialOrKeyValuesPrinted':False,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False,
            'automaticReplayAllowed':False,'budgetReset':False}
        if c:
            try:c.put('result.json',result)
            except Exception:pass
        code=1
    print(__import__('json').dumps(result,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
