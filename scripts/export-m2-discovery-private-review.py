"""Export the exact closed review compiler. Packaging does not grant execution."""
import argparse,hashlib,json,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.m2_discovery_installation_profile.private_review_capsule import build

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True);parser.add_argument('--source-revision',required=True)
    parser.add_argument('--output',required=True);args=parser.parse_args()
    raw,manifest=build(args.root,args.source_revision)
    with Path(args.output).open('xb') as stream:stream.write(raw)
    print(json.dumps({'capsuleSha256':hashlib.sha256(raw).hexdigest(),'capsuleBytes':len(raw),
        'sourceModules':len(manifest['sources']),'completeParentReview':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'publisherTrustAccepted':False}))
