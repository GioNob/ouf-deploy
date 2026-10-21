"""CI-only signed preapproved-frame authority; never install on a target."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import time


def private(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    path.write_bytes(raw); path.chmod(0o600); return raw


def main():
    parser = argparse.ArgumentParser()
    for name in ('configuration', 'container-id', 'bundle', 'runtime-root', 'mode'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(); root = Path(args.configuration).parent
    cfg = json.loads(Path(args.configuration).read_bytes())
    state = json.loads(sys.stdin.buffer.read(16385)) if args.mode != 'cleanup' else {}
    sys.path.insert(0, cfg['sourceRoot'])
    try:
        if args.mode == 'prepare':
            from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
            from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
            from tools.semantic_provider_preexec import digest
            intent = json.loads(Path(cfg['intentBinding']['path']).read_bytes())
            approved = json.loads((root / 'ci-preapproved-frame.json').read_bytes())
            frame = json.loads((root / 'frame-policy.json').read_bytes())
            actual = json.loads((Path(state['bundle']) / 'config.json').read_bytes())
            assert state['status'] == 'created' and state['id'] == intent['containerId']
            assert digest(actual) == approved['applicationHash'] == digest(frame['expectedOci'])
            assert intent['artifactHash'] == approved['policyHash']
            node = json.loads((root / 'attestation-producer.json').read_bytes())
            verifier = DetachedAuthenticator(cfg['policyBinding'], cfg['signatureDirectory'], cfg['opensslBinding'])
            scope = {'role': 'CREATION_ATTESTATION', 'issuerRef': cfg['authorities']['attestorRef'],
                     'installationRef': intent['installationRef'], 'entityRef': intent['entityRef']}
            signer = ExistingEd25519Signer(node['signingKeyBinding'], node['keyRef'], verifier, scope)
            value = {'schema': 'ouf.semantic-node-live-acceptance-authorization.v1',
                **{k: intent[k] for k in ('installationRef', 'entityRef', 'containerId', 'transactionId',
                    'artifactHash', 'deploymentConstraintsHash', 'transportHash', 'runtimeExecutableHash')},
                'issuerRef': scope['issuerRef'], 'intentHash': cfg['intentBinding']['sha256'],
                'applicationHash': approved['applicationHash'], 'rootfsSeal': approved['rootfsSeal'],
                'generationBinding': 'OBSERVED_CREATED', 'issuedAt': int(time.time()), 'expiresAt': intent['expiresAt'],
                'state': 'ACTIVE', 'mandateIssuanceAuthorized': True, 'attestationAuthorized': True,
                'completeCreationAccepted': True}
            raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
            signature = signer.sign(raw)
            path = Path(cfg['signatureDirectory']) / (hashlib.sha256(raw).hexdigest() + '.CREATION_ATTESTATION.json')
            assert not path.exists()
            path.write_bytes(signature); path.chmod(0o600)
            assert not Path(node['liveAcceptanceAuthorizationPath']).exists()
            private(Path(node['liveAcceptanceAuthorizationPath']), value)
        path = Path(cfg['sourceRoot']) / 'scripts/semantic_provider_deployment_broker.py'
        spec = importlib.util.spec_from_file_location('ci_production_broker', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        loaded, raw = module.load(args.configuration)
        module.Broker(loaded, raw, args.configuration, args).operate(state)
        return 0
    except Exception as error:
        reason = str(error)
        if not re.fullmatch('[A-Z0-9_]{1,96}', reason): reason = 'CI_FRAME_PROFILE_OPERATION_UNPROVEN'
        diagnosis = {'stage': args.mode, 'reason': reason, 'errorClass': type(error).__name__,
                     'secretValuesPrinted': False}
        private(root / 'ci-broker-denial.json', diagnosis)
        print('FRAME_PROFILE_DIAGNOSIS=' + json.dumps(diagnosis), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
