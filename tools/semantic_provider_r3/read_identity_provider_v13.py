#!/usr/bin/env python3
"""Read-only Docker/recipe reader; stdout is one public canonical R3 input.

No persistent files created, no container/network writes, no full Config/Env inspect.
The operator redirects stdout into a private new file and binds its hash.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.semantic_provider_r3 import compose as C, install_common as I
from tools.semantic_provider_r3 import identity_provider_v13 as P


def bound_docker(binding, argv, limit):
    """Only used with the fixed inspect argv below, without inherited context."""
    binary = I.V.executable_hash(binding['path'], binding['sha256'])
    try:
        with tempfile.TemporaryFile() as output:
            child = subprocess.run([binary, *argv], stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.DEVNULL, timeout=5,
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'DOCKER_API_VERSION': '1.44'})
            output.seek(0)
            raw = output.read(limit + 1)
        P.identity_require(child.returncode == 0 and len(raw) <= limit, 'R3_IDENTITY_PROVIDER_READ_DENIED')
        return raw
    finally:
        I.V.executable_hash(binding['path'], binding['sha256'])


def observe(args, reader, run):
    P.identity_require(all(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', s)
                           for s in (args.container, args.network))
                       and re.fullmatch('[0-9a-f]{64}', args.southbound_id)
                       and re.fullmatch('/[A-Za-z0-9_./-]+', args.docker_socket)
                       and '..' not in args.docker_socket.split('/'),
                       'R3_IDENTITY_PROVIDER_INPUT_INVALID')
    owner = C.document(reader.read(args.coordinator, args.coordinator_sha256))
    template = C.document(reader.read(args.historical_template, args.historical_template_sha256))
    candidate = template['candidate'].copy()
    candidate['containerId'] = args.southbound_id
    alias, port = P.issuer_endpoint(owner['kernel'], candidate)
    binding = {'path': args.docker, 'sha256': args.docker_sha256}
    base = ['--host', 'unix://' + args.docker_socket]
    def inspect(selector):
        raw = run(binding, base + ['inspect', '--format', P.INSPECT_FORMAT, selector], 131072)
        return raw, P.identity_json(raw)
    first_raw, first = inspect(args.container)
    network_raw = run(binding, base + ['network', 'inspect', '--format', P.NETWORK_FORMAT, args.network], 131072)
    network = P.identity_json(network_raw)
    endpoint = first['Networks'][args.network]
    peer = {'containerId': first['Id'], 'containerName': args.container, 'network': args.network,
            'networkId': network['Id'], 'bridge': (network.get('Options') or {}).get(
                'com.docker.network.bridge.name', 'br-' + network['Id'][:12]),
            'ipv4': endpoint['IPAddress'], 'mac': endpoint['MacAddress'], 'alias': alias,
            'aliases': sorted(endpoint['Aliases']), 'port': port,
            'dockerBinding': binding, 'dockerSocket': args.docker_socket}
    P.identity_projection(first, peer)
    P.identity_network(network, peer)
    own_raw, own = inspect(args.southbound_id)
    own_endpoint = own['Networks'][args.network]
    P.identity_require(own['Id'] == args.southbound_id and own_endpoint['NetworkID'] == peer['networkId'],
                       'R3_IDENTITY_PROVIDER_NETWORK_NOT_SHARED')
    value = {'schema': 'ouf.semantic-identity-provider-peer.v1', 'peer': peer,
             'southbound': {'containerId': own['Id'], 'ipv4': own_endpoint['IPAddress'],
                           'network': args.network, 'networkId': own_endpoint['NetworkID'], 'bridge': peer['bridge']},
             'observationHashes': {'identityProvider': C.sha(first_raw), 'southbound': C.sha(own_raw), 'network': C.sha(network_raw)}}
    P.identity_flow(value, candidate, owner['kernel'])
    P.identity_require(P.identity_observe(peer, run) == (first_raw, network_raw), 'R3_IDENTITY_PROVIDER_LIVE_DRIFT')
    P.identity_require(inspect(args.southbound_id)[0] == own_raw,
                       'R3_IDENTITY_PROVIDER_LIVE_DRIFT')
    reader.verify()
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('docker', 'docker-sha256', 'docker-socket', 'container', 'network', 'southbound-id',
                 'coordinator', 'coordinator-sha256', 'historical-template', 'historical-template-sha256'):
        parser.add_argument('--' + flag, required=True)
    args = parser.parse_args()
    try:
        P.identity_require(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0,
                           'R3_IDENTITY_PROVIDER_LINUX_ROOT_REQUIRED')
        value = observe(args, I.Reader(), bound_docker)
        sys.stdout.buffer.write(C.canonical(value) + b'\n')
        return 0
    except Exception:
        # No native output, config, paths or secret material in denial reports.
        print('R3_IDENTITY_PROVIDER_READ_DENIED', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
