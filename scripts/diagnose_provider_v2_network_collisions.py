"""Read public endpoint identities only; never mutate the existing claim."""
import json
from pin_provider_v2_networks import API, PLAN, CANDIDATES

def main():
    api = API(); wanted = {(name, v[0], v[1]) for nets in PLAN.values() for name, v in nets.items()}
    known = {v[0] for v in CANDIDATES.values()}; collisions = []
    for item in api.request('GET', '/containers/json?all=1'):
        if item['Id'] in known: continue
        row = api.inspect(item['Id'])
        for name, endpoint in row['NetworkSettings']['Networks'].items():
            for network, ip, mac in sorted(wanted):
                if name != network: continue
                if (endpoint.get('IPAMConfig') or {}).get('IPv4Address') == ip or endpoint.get('IPAddress') == ip or endpoint.get('MacAddress') == mac:
                    state = row['State']
                    collisions.append({'containerId': row['Id'], 'name': row['Name'], 'network': name,
                        'declaredIpv4': (endpoint.get('IPAMConfig') or {}).get('IPv4Address'),
                        'allocatedIpv4': endpoint.get('IPAddress'), 'mac': endpoint.get('MacAddress'),
                        'status': state['Status'], 'pid': state['Pid'], 'running': state['Running'],
                        'neverStarted': state['StartedAt'].startswith('0001-'), 'runtime': row['HostConfig']['Runtime']})
    print('OUF_PROVIDER_V2_NETWORK_COLLISIONS=' + json.dumps({'status': 'READ_ONLY', 'collisions': collisions,
        'networkAttachmentOperations': 0, 'containerLifecycleOperations': 0, 'privateKeysRead': 0, 'startAuthorized': False}, sort_keys=True))
if __name__ == '__main__':
    try: main()
    except Exception: print('OUF_PROVIDER_V2_NETWORK_COLLISIONS=BLOCKED NO_RAW_OUTPUT=true'); raise SystemExit(1)
