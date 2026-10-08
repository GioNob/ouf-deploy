"""Release five declarations from exact never-started predecessor candidates.

Retain their containers, images, files and state; pin the reviewed v2 NICs.
One durable transaction; no automatic replay/rollback after any API failure.
"""
import os
from pathlib import Path
import re
import stat
import pin_provider_v2_networks as p

PREDECESSORS = {
 'adapter': ('10a6237447b83c6e67e134e9266a74f5247fb1fa1fbe2c4528ff92fd663f767b', 'ouf-semantic-provider'),
 'southbound': ('0e636c96b81da5ed500cee114f1b0c83d5c4ed8e2741eb0a34865f8da8e38307', 'ouf-semantic-southbound')}
def predecessor(row, role):
    cid, name = PREDECESSORS[role]; s = row['State']; h = row['HostConfig']
    p.require(row['Id'] == cid and row['Name'] == '/' + name and h['Runtime'] == 'runc', 'PREDECESSOR_IDENTITY_DRIFT')
    p.require(s['Status'] == 'created' and s['Pid'] == 0 and s['Running'] is False and s['Restarting'] is False
        and s['StartedAt'].startswith('0001-'), 'PREDECESSOR_NOT_NEVER_STARTED')
    p.require(set(row['NetworkSettings']['Networks']) == set(p.PLAN[role]), 'PREDECESSOR_NETWORK_DRIFT')
    for network, (ip, _, _) in p.PLAN[role].items():
        n = row['NetworkSettings']['Networks'][network]
        p.require(n['NetworkID'] in ('', p.NETWORKS[network][0]) and n['IPAMConfig'] == {'IPv4Address': ip}
            and n['Aliases'] == [name] and not n.get('Links') and n.get('GwPriority', 0) == 0
            and not n.get('DriverOpts') and not n['MacAddress'] and not n['IPAddress'] and not n['EndpointID'], 'PREDECESSOR_ENDPOINT_DRIFT')
def handover(api, write):
    rows = {}; originals = []
    for role, (cid, _) in PREDECESSORS.items():
        row = api.inspect(cid); predecessor(row, role); rows[cid] = row
        originals.append({'containerId': cid, 'role': role, 'networks': row['NetworkSettings']['Networks'],
            'immutableHash': p.immutable(row)})
        new = api.inspect(p.CANDIDATES[role][0]); p.candidate(new, role)
        for network in p.PLAN[role]: p.endpoint(role, network, new, False)
    # Complete collision preflight by excluding only these exact predecessors.
    # Existing pin helper validates the fleet and all network identities without
    # mutating: its first durable-claim callback aborts before the first POST.
    class ExcludingPredecessorDeclarations:
        def inspect(self, cid):
            row = api.inspect(cid)
            if cid in rows:
                predecessor(row, next(role for role, v in PREDECESSORS.items() if v[0] == cid))
                row['NetworkSettings']['Networks'] = {}
            return row
        def request(self, method, path, value=None):
            p.require(method == 'GET', 'READ_ONLY_PREFLIGHT_REQUIRED')
            return api.request(method, path, value)
    class Ready(Exception): pass
    def ready(_): raise Ready()
    try: p.apply(ExcludingPredecessorDeclarations(), ready)
    except Ready: pass
    else: raise ValueError('PREFLIGHT_DID_NOT_STOP')
    history = [{'state': 'CLAIMED', 'predecessors': originals}]
    write(history)
    for role, (cid, _) in PREDECESSORS.items():
        current = api.inspect(cid); predecessor(current, role)
        p.require(p.immutable(current) == p.immutable(rows[cid]), 'PREDECESSOR_CONFIGURATION_DRIFT')
        for name in p.PLAN[role]:
            api.request('POST', '/networks/' + p.NETWORKS[name][0] + '/disconnect', {'Container': cid, 'Force': False})
            current = api.inspect(cid)
            p.require(p.immutable(current) == p.immutable(rows[cid]), 'PREDECESSOR_CONFIGURATION_DRIFT')
            history.append({'state': 'PREDECESSOR_ENDPOINT_RELEASED', 'containerId': cid, 'network': name}); write(history)
        p.require(not current['NetworkSettings']['Networks'], 'PREDECESSOR_ENDPOINT_RETAINED')
    def claim(value): history.append(value); write(history)
    report = p.apply(api, claim)
    for cid, row in rows.items():
        current = api.inspect(cid)
        p.require(p.immutable(current) == p.immutable(row) and not current['NetworkSettings']['Networks'], 'PREDECESSOR_FINAL_DRIFT')
    report.update(predecessorCount=2, predecessorStatesUnchanged=True, predecessorEndpointReleases=5,
        totalNetworkAttachmentOperations=15, predecessorContainersRetained=True)
    history.append({'state': 'HANDOVER_COMPLETED', 'report': report}); write(history)
    return report
def main():
    os.umask(0o077)
    try:
        p.require(os.getuid() == 1000 and os.environ.get('USER') == 'oufadmin', 'RUNNER_IDENTITY_DRIFT')
        old_claim = Path.home() / '.ouf-v2-network-declarations.claim'
        s = old_claim.lstat()
        p.require(stat.S_ISREG(s.st_mode) and s.st_uid == 1000 and stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == 0, 'PRIOR_MUTATION_NOT_PROVEN_EMPTY')
        path = Path.home() / '.ouf-v2-network-handover.claim'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as f:
            def write(value):
                f.seek(0); f.truncate(); f.write(p.encoded(value)); f.flush(); os.fsync(f.fileno())
            report = handover(p.API(), write)
            print('OUF_PROVIDER_V2_NETWORK_HANDOVER=' + p.encoded(report).decode())
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, ValueError) and re.fullmatch('[A-Z_]+', str(error)) else 'CLAIM_EXISTS_OR_BOUNDED_OPERATION_FAILED'
        print('OUF_PROVIDER_V2_NETWORK_HANDOVER=BLOCKED REASON=' + code + ' DO_NOT_RERUN_APPLY=true NO_RAW_OUTPUT=true'); return 1
if __name__ == '__main__': raise SystemExit(main())
