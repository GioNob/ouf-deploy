"""Project a reviewable Semantic profile or extend a pinned v24 input index."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_provider_r3 import compose as C, install_common as I
from tools.semantic_provider_r3 import semantic_identity_v25 as S


V25_ARGUMENTS = ('profile', 'profile_sha256', 'source_sha256', 'lease_renewal', 'lease_renewal_sha256')


def candidate(reader, index):
    def document(name):
        return C.document(reader.bound(index['files'][name]))
    installation = document('installationProfile')
    role = installation['roles']['semantic']
    idp = document('identityProviderPeer')
    network = idp['southbound']
    peer = idp['peer']
    flow = document('semanticPeer')['proposedIngress']
    template = document('southbound/historicalTemplate')
    commands = {'socket': peer['dockerSocket'], 'docker': peer['dockerBinding'],
                **{k: {'path': template['commands'][k], 'sha256': template['commandHashes'][k]}
                   for k in ('ip', 'nsenter')}}
    row, = json.loads(S.semantic_command(commands['docker'], ['--host', 'unix://' + commands['socket'],
                              'container', 'inspect', role['containerName']]))
    profile = dict(role='semantic', containerName=role['containerName'], image=row['Image'],
                   configurationSha256=S.semantic_configuration(row), direction='semantic-to-southbound',
                   ipv4=role['networks'][network['network']]['ipv4'], destination=network['ipv4'],
                   protocol=flow['protocol'], port=flow['destinationPort'],
                   **{k: network[k] for k in ('network', 'networkId', 'bridge')})
    S.semantic_check(installation['networks'][network['network']]['bridge'] == profile['bridge']
                     and (flow['sourceIpv4'], flow['destinationIpv4']) == (profile['ipv4'], profile['destination']))
    first, _ = S.semantic_observe(profile, commands)
    second, _ = S.semantic_observe(profile, commands)
    S.semantic_check(first == second, 'R3_SEMANTIC_EPOCH_CHANGED')
    return profile


def prepare(args, reader):
    index = C.document(reader.read(args.v24_inputs, args.v24_inputs_sha256))
    S.semantic_check(set(index) == {'schema', 'files', 'sources'} and index['schema'] == 'ouf.semantic-provider-r3-inputs.v1'
                     and set(index['files']) == C.DATA_INPUTS_V24 and set(index['sources']) == C.SOURCE_INPUTS_V24)
    sequence = getattr(args, 'sequence', None)
    if sequence is not None:
        S.semantic_check(sequence >= 24)
        settings = C.document(reader.bound(index['files']['settings']))
        version = C.composition_version(sequence, settings)
        if version == 24:
            S.semantic_check(args.mode == 'inputs' and all(getattr(args, k, None) is None for k in V25_ARGUMENTS))
            return index
    if args.mode == 'profile':
        return candidate(reader, index)
    S.semantic_check(all(getattr(args, k, None) for k in V25_ARGUMENTS))
    profile = {'path': args.profile, 'sha256': args.profile_sha256}
    S.semantic_profile(C.document(reader.bound(profile)))
    renewal = {'path': args.lease_renewal, 'sha256': args.lease_renewal_sha256}
    timing = C.document(reader.bound(renewal))
    S.semantic_check(set(timing) == set(C.document(reader.bound(index['files']['leaseRenewal']))) |
                     {'semanticTickBudgetSeconds', 'semanticCloseReserveSeconds', 'semanticFullObservationSeconds'})
    source = {'path': str(I.ROOT / C.SEMANTIC_IDENTITY), 'sha256': args.source_sha256}
    reader.bound(source)
    return {**index, 'files': {**index['files'], 'semanticProfile': profile, 'leaseRenewal': renewal},
            'sources': {**index['sources'], C.SEMANTIC_IDENTITY: source}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--v24-inputs', required=True)
    parser.add_argument('--v24-inputs-sha256', required=True)
    parser.add_argument('--sequence', type=int, default=C.CURRENT_COMPOSITION_VERSION,
                        help='Select the input shape using the proposed sequence and the bound settings.')
    modes = parser.add_subparsers(dest='mode', required=True)
    modes.add_parser('profile')
    inputs = modes.add_parser('inputs')
    for name in V25_ARGUMENTS:
        inputs.add_argument('--' + name.replace('_', '-'))
    args = parser.parse_args()
    try:
        reader = I.Reader()
        value = prepare(args, reader)
        reader.verify()
        sys.stdout.buffer.write(C.canonical(value))
        return 0
    except Exception:
        print('R3_V25_INPUTS_UNPROVEN', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
