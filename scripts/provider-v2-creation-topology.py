"""Bounded read-only topology for a new provider transaction; no secret reads."""
import json
import re
import subprocess

CID = re.compile(r'[0-9a-f]{64}')
NAME = re.compile(r'[A-Za-z0-9_.-]{1,128}')
OLD_SOUTHBOUND = '0e636c96b81da5ed500cee114f1b0c83d5c4ed8e2741eb0a34865f8da8e38307'
FORMAT = '{{json .Id}} {{json .Name}} {{json .Image}} {{json .State}} {{json .NetworkSettings.Networks}} {{json .HostConfig.NetworkMode}} {{json .HostConfig.RestartPolicy}} {{json .Config.User}}'
NET_FORMAT = '{{json .Id}} {{json .Name}} {{json .Driver}} {{json .Internal}} {{json .EnableIPv6}} {{json .IPAM.Config}} {{json .Containers}} {{json .Options}}'

def require(ok, why):
    if not ok: raise RuntimeError(why)

def docker(*args):
    p = subprocess.run(['/usr/bin/docker', *args], stdin=subprocess.DEVNULL,
        capture_output=True, timeout=15, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    require(p.returncode == 0 and len(p.stdout) <= 1048576, 'DOCKER_READ_UNAVAILABLE')
    return p.stdout.decode()

def values(raw, count):
    decoder = json.JSONDecoder(); out = []; pos = 0
    for _ in range(count):
        while pos < len(raw) and raw[pos].isspace(): pos += 1
        item, pos = decoder.raw_decode(raw, pos); out.append(item)
    require(not raw[pos:].strip(), 'DOCKER_READ_SHAPE_DRIFT')
    return out

def role(name):
    row = values(docker('inspect','--type','container','--format',FORMAT,name),8)
    cid, actual_name, image, state, networks, mode, restart, user = row
    require(CID.fullmatch(cid) and actual_name == '/'+name, 'LEGACY_ROLE_IDENTITY_DRIFT')
    if name == 'ouf-semantic-southbound': require(cid == OLD_SOUTHBOUND, 'LEGACY_SOUTHBOUND_DRIFT')
    require(state['Status'] == 'created' and state['Running'] is False
        and state['StartedAt'].startswith('0001-01-01'), 'LEGACY_ROLE_ALREADY_EXECUTED')
    require(restart['Name'] in ('','no'), 'LEGACY_RESTART_POLICY_DRIFT')
    require(isinstance(networks,dict) and 1 <= len(networks) <= 8, 'LEGACY_TOPOLOGY_UNBOUNDED')
    result = []
    for netname, record in sorted(networks.items()):
        require(NAME.fullmatch(netname), 'EXACT_NETWORK_NAME_REQUIRED')
        resolved = docker('network','inspect','--format','{{.Id}}',netname).strip()
        require(CID.fullmatch(resolved) and record['NetworkID'] in ('',None,resolved), 'EXACT_NETWORK_BINDING_REQUIRED')
        result.append({key:record.get(key) for key in ('NetworkID','EndpointID','IPAddress','IPPrefixLen',
            'GlobalIPv6Address','GlobalIPv6PrefixLen','IPAMConfig','Aliases')})
        result[-1]['name'] = netname
        result[-1]['NetworkID'] = resolved
        result[-1]['liveEndpointProven'] = False
    return dict(name=name,containerId=cid,imageId=image,runtimeUser=user,neverStarted=True,
        restartPolicy=restart['Name'],networkMode=mode,networks=result)

def network(nid):
    row=values(docker('network','inspect','--format',NET_FORMAT,nid),8)
    actual,name,driver,internal,ipv6,ipam,endpoints,options=row
    require(actual == nid and NAME.fullmatch(name) and driver == 'bridge', 'NETWORK_BINDING_DRIFT')
    require(isinstance(endpoints,dict) and len(endpoints) <= 128, 'NETWORK_MEMBERSHIP_UNBOUNDED')
    selected=[]
    for cid, item in sorted(endpoints.items()):
        require(CID.fullmatch(cid) and NAME.fullmatch(item['Name']), 'NETWORK_MEMBER_BINDING_DRIFT')
        selected.append({key:item.get(key) for key in ('Name','EndpointID','IPv4Address','IPv6Address')})
        selected[-1]['containerId']=cid
    # Options are filtered: never emit arbitrary Docker extension values.
    return dict(networkId=nid,name=name,driver=driver,internal=internal,ipv6Enabled=ipv6,
        ipam=ipam,members=selected,bridgeName=options.get('com.docker.network.bridge.name'))

def main():
    try:
        before=[role(name) for name in ('ouf-semantic-provider','ouf-semantic-southbound')]
        ids=sorted({net['NetworkID'] for item in before for net in item['networks']})
        topology=[network(nid) for nid in ids]
        names=('ouf-semantic-provider-v2','ouf-semantic-southbound-v2')
        available={name:not docker('ps','-aq','--filter','name=^/'+name+'$').strip() for name in names}
        require(all(available.values()), 'NEW_ROLE_NAME_ALREADY_OCCUPIED')
        after=[role(name) for name in ('ouf-semantic-provider','ouf-semantic-southbound')]
        require(before == after and topology == [network(nid) for nid in ids], 'TOPOLOGY_CHANGED_DURING_READ')
        print('OUF_PROVIDER_V2_CREATION_TOPOLOGY='+json.dumps(dict(
            schema='ouf.semantic-provider-v2-creation-topology.v1',status='READ_ONLY_TOPOLOGY_OBSERVED',
            legacyRoles=before,networks=topology,newRoleNamesAvailable=available,
            containerLifecycleOperations=0,networkWrites=0,secretValuesPrinted=False,
            privateFilesRead=False,runtimeRegistrationPerformed=False,startAuthorized=False,
            globallyAtomicSnapshotProven=False,notReleaseAcceptance=True),sort_keys=True))
        return 0
    except Exception as error:
        reason=str(error)
        if not re.fullmatch('[A-Z_]{1,80}',reason): reason='TOPOLOGY_READ_UNPROVEN'
        print('OUF_PROVIDER_V2_CREATION_TOPOLOGY=BLOCKED REASON='+reason+' NO_RAW_OUTPUT=true')
        return 1

if __name__ == '__main__': raise SystemExit(main())
