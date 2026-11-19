#!/usr/bin/env python3
"""Export a source-sealed current parent review compiler; never execute it."""
import argparse,hashlib,json,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.m2_discovery_installation_profile.current_review_capsule import build


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for arg in ('root','source-revision','gateway-root','onboarding-root','output'):parser.add_argument('--'+arg,required=True)
    args=parser.parse_args();raw,manifest=build(args.root,args.source_revision,args.gateway_root,args.onboarding_root)
    path=Path(args.output)
    # Exclusive creation: an old or ambiguous compiler must never be overwritten.
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    print(json.dumps({'schema':'ouf.discovery-current-parent-review-export.v1','compilerSha256':hashlib.sha256(raw).hexdigest(),
        'sourceCount':len(manifest['sources']),'payloadSha256':manifest['payloadSha256'],
        'sourceRevisionClaim':args.source_revision,'sourceRevisionClaimAuthenticated':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False},sort_keys=True))


if __name__=='__main__':main()
