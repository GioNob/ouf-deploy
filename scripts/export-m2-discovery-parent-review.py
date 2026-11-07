"""Export the isolated six-part offline review compiler; no execution mode."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.m2_discovery_installation_profile.parent_review_capsule import build

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('root','source-revision','gateway-root','onboarding-root','output'):p.add_argument('--'+name,required=True)
    a=p.parse_args();raw,manifest=build(a.root,a.source_revision,a.gateway_root,a.onboarding_root)
    with Path(a.output).open('xb') as stream:stream.write(raw)
    print(json.dumps({'capsuleSha256':hashlib.sha256(raw).hexdigest(),'capsuleBytes':len(raw),
        'sourceModules':len(manifest['sources']),'publicHelperFiles':sum(map(len,manifest['publicationSourceHashes'].values())),
        'signaturesIssued':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'publisherTrustAccepted':False,'releaseAcceptance':False}))
