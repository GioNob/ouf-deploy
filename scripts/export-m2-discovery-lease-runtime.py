"""Export exact worker code, not an installer or runtime authority."""
import argparse,hashlib,importlib.util,json
from pathlib import Path

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args(argv);root=Path(args.root)
    spec=importlib.util.spec_from_file_location('lease_capsule_builder',root/'tools/m2_discovery_installation_profile/lease_capsule.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    raw,manifest=module.build(root)
    with Path(args.output).open('xb') as stream:stream.write(raw)
    print(json.dumps({'schema':'ouf.discovery-lease-runtime-export.v1','sourceCommit':module.SOURCE,
        'capsuleSha256':hashlib.sha256(raw).hexdigest(),'capsuleBytes':len(raw),
        'sourceManifest':manifest,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False},sort_keys=True))

if __name__=='__main__':main()
