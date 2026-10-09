"""Read existing Docker metadata and host bridge topology without lifecycle actions.

No exec, private key/file reads, environment values, network calls, or mutations.
"""
import hashlib
import json
from pathlib import Path
import socket
import subprocess

TARGETS = {'adapter': 'f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67',
           'southbound': '1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916',
           'semantic': 'ouf-semantic', 'mcp': 'ouf-mcp', 'gateway': 'ouf-apisix'}

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def inspect(name):
    result = subprocess.run(['docker', 'inspect', '--type', 'container', name],
                            capture_output=True, timeout=20, check=True)
    if len(result.stdout) > 2097152:
        raise ValueError('DOCKER_METADATA_BOUND_EXCEEDED')
    return json.loads(result.stdout)[0]

def project(raw):
    config, state, host = raw['Config'], raw['State'], raw['HostConfig']
    # Environment contents are never copied into evidence, hashed, or printed.
    mounts = [dict(type=m['Type'], destination=m['Destination'], readOnly=not m['RW'],
                   sourcePathSha256=hashlib.sha256(m['Source'].encode()).hexdigest())
              for m in raw['Mounts']]
    networks = {n: dict(networkId=v['NetworkID'], ipAddress=v['IPAddress'], macAddress=v['MacAddress'])
                for n, v in raw['NetworkSettings']['Networks'].items()}
    return dict(containerId=raw['Id'], imageId=raw['Image'], running=state['Running'],
                status=state['Status'], pid=state['Pid'], startedAt=state['StartedAt'],
                restartCount=raw['RestartCount'], health=state.get('Health', {}).get('Status'),
                runtime=host['Runtime'], restartPolicy=host['RestartPolicy'], user=config['User'],
                readOnlyRoot=host['ReadonlyRootfs'], mountBindings=mounts, networks=networks,
                portBindings=host['PortBindings'], applicationHealthProven=False)

def main():
    report = dict(schema='ouf.discovery.rollout-topology-read-only.v1',
                  containerLifecycleOperations=0, configurationWrites=0, privateKeysRead=0,
                  privateValuesPrinted=False, providerCalls=0, dockerExecCalls=0,
                  acceptanceGranted=False, rolloutAuthorized=False, roles={})
    for role, name in TARGETS.items():
        report['roles'][role] = project(inspect(name))
    interface = Path('/sys/class/net/vethca2111d')
    index = socket.if_nametoindex('vethca2111d') if interface.exists() else None
    master = (interface / 'master').resolve(strict=True).name if interface.exists() else None
    semantic_networks = report['roles']['semantic']['networks'].values()
    report['existingSignedSemanticIngress'] = dict(
        expectedHostIfindex=1377, actualHostIfindex=index, actualBridge=master,
        expectedBridgeMatches=master == 'br-113b5f0a3c53',
        expectedNetworkAddressMatches=any(v['ipAddress'] == '172.18.0.6' and
                                         v['macAddress'] == 'b2:96:a1:e2:c1:8d'
                                         for v in semantic_networks),
        exactPortIndexMatches=index == 1377,
        changedPeerPortRequiresNewGovernedBinding=True)
    report['status'] = 'EXISTING_ROLLOUT_TOPOLOGY_CAPTURED'
    print('OUF_DISCOVERY_ROLLOUT_TOPOLOGY=' + json.dumps(report, sort_keys=True))

if __name__ == '__main__':
    main()
