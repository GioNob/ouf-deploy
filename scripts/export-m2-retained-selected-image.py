#!/usr/bin/env python3
"""Export sealed selected-runtime byte verification of diagnosed archives; create-only public source."""
import argparse, hashlib, json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.m2_discovery_installation_profile.retained_selected_image_capsule import build

def main():
    p = argparse.ArgumentParser(); p.add_argument('--root', required=True)
    p.add_argument('--source-revision', required=True); p.add_argument('--output', required=True)
    a = p.parse_args(); raw, manifest = build(a.root, a.source_revision)
    fd = os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(os.dup(fd), 'wb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally: os.close(fd)
    print(json.dumps({'schema':manifest['schema'],'capsuleSha256':hashlib.sha256(raw).hexdigest(),
        'sourceMapSha256':manifest['sourceMapSha256'],'sourceRevisionClaim':a.source_revision,
        'sourceCount':len(manifest['sources']),'publisherTrustAccepted':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False},sort_keys=True))
    return 0

if __name__ == '__main__': raise SystemExit(main())
