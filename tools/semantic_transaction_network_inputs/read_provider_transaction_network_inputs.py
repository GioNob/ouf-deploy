"""Capture missing network-plan inputs once; no runtime or acceptance mutation.

Only three fixed installation files are opened. Private key/environment/TLS
files, containers and networking commands are not accessed. URL credentials,
queries and fragments are rejected before a bounded endpoint is returned.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from urllib.parse import urlsplit

FILES = {
    'binding': ('/etc/ouf/deploy-snapshots/semantic-provider-v2-inputs-XE7IwlGm/binding.json',
        '3f1872a332da691667a306db11d0749065ec2149080437853eada820ff7ec47a'),
    'plan': ('/etc/ouf/deploy-snapshots/semantic-provider-v2-inputs-XE7IwlGm/runtime-plan.json',
        '1e85ab77fdd8b1e439cf92542652d65b5ea044cfed50ef2214c89a16170645a2'),
    'coordination': ('/etc/ouf/deploy-snapshots/semantic-coordinated-boot-install-yt5p6huw/coordinated-configuration.json',
        'be76f56598ef3d7e91e773351b6a04f8a4595c4fb6ef1d70986d47ddb350ad04'),
}

class InputDenied(ValueError): pass

def require(ok, code):
    if not ok: raise InputDenied(code)

def read_bound(path, expected):
    path = Path(path)
    for parent in (path.parent, *path.parent.parents):
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
            'PRIVATE_INPUT_ANCESTOR_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)==(0,0,0o600,1)
            and s.st_size <= 131072, 'PRIVATE_INPUT_FILE_REQUIRED')
        raw = os.read(fd, 131073)
        require(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==expected,
            'SEALED_NETWORK_INPUT_CHANGED')
        return json.loads(raw)
    finally: os.close(fd)

def endpoint(value):
    require(type(value) is str and len(value)<=2048, 'BOUNDED_ENDPOINT_REQUIRED')
    u = urlsplit(value)
    require(u.scheme=='https' and u.hostname and not (u.username or u.password or u.query or u.fragment),
        'CREDENTIAL_FREE_HTTPS_ENDPOINT_REQUIRED')
    return {'hostname':u.hostname, 'port':u.port or 443, 'path':u.path or '/'}

def projection(binding, plan, coordination):
    require(plan['schema']=='ouf.semantic-provider-runtime-plan.v1'
        and coordination['schema']=='ouf.semantic-coordinated-owner-runtime.v1', 'EXPECTED_NETWORK_PLAN_REQUIRED')
    routes = binding['routes']; adapter = binding['adapter']; kernel = coordination['kernel']
    require(adapter==plan['adapterConfiguration'], 'ADAPTER_NETWORK_PLAN_DRIFT')
    static = []
    for flow in kernel['staticFlows']:
        require(set(flow)=={'purpose','source','destination','protocol','port'}, 'EXACT_STATIC_FLOW_REQUIRED')
        static.append(dict(flow))
    provider = []
    for flow in kernel['providerFlows']:
        provider.append({'endpointRef':flow['endpointRef'], 'endpoint':endpoint(flow['endpoint']),
            'source':flow['source'], 'leaseSeconds':flow['leaseSeconds'],
            'resolutionEvidenceRef':flow['resolutionEvidenceRef'],
            'allowedPrivateAddresses':flow['allowedPrivateAddresses']})
    dns = coordination['dns']
    allowed_dns = {'resolvers','resolverPort','timeoutSeconds','maxLeaseSeconds','applyBudgetSeconds'}
    require(set(dns)<=allowed_dns and {'resolvers','resolverPort'}<=set(dns), 'EXACT_DNS_PROFILE_REQUIRED')
    binding_scope = coordination['binding']
    require(set(binding_scope)=={'transactionId','configurationHash','leaseStructureHash'}, 'EXACT_COORDINATION_SCOPE_REQUIRED')
    return {'schema':'ouf.semantic-provider-transaction-network-inputs.v1', 'status':'NETWORK_INPUTS_CAPTURED',
        'providerEndpoint':endpoint(adapter['provider']['endpoint']), 'oidcIssuerEndpoint':endpoint(routes['issuer']),
        'tlsIdentities':plan['tlsIdentities'], 'adapterListener':{'address':adapter['listenAddress'],'port':adapter['listenPort']},
        'dns':{k:dns[k] for k in sorted(dns)}, 'kernel':{'tableName':kernel['tableName'],
            'guardedInterfaces':kernel['guardedInterfaces'], 'existingInterfaces':kernel['existingInterfaces'],
            'staticFlows':static,'providerFlows':provider}, 'coordinationBinding':dict(binding_scope),
        'expectedStructureHash':coordination['expectedStructureHash'],
        'journalFile':coordination['journalFile'], 'commonLockFile':coordination['commonLockFile'],
        'inputHashes':{name:sha for name,(_,sha) in FILES.items()},
        'configurationWrites':0, 'containerLifecycleOperations':0, 'firewallWrites':0,
        'providerCalls':0, 'privateKeysRead':0, 'environmentFilesRead':0,
        'secretValuesPrinted':False, 'startAuthorized':False, 'acceptanceGranted':False}

def main():
    stage = 'ROOT_ACCESS'; selected = None; result_dir = None
    try:
        require(os.geteuid()==0 and sys.flags.isolated, 'ROOT_ISOLATED_READER_REQUIRED')
        os.umask(0o077)
        result_dir = Path(tempfile.mkdtemp(prefix='ouf-transaction-network-',dir='/tmp'))
        inputs = {}
        for selected,(path,sha) in FILES.items():
            stage = 'READ_'+selected.upper()
            inputs[selected] = read_bound(path,sha)
        stage = 'PROJECT_NETWORK_INPUTS'; selected = None
        report = projection(inputs['binding'],inputs['plan'],inputs['coordination'])
        (result_dir/'report.json').write_text(json.dumps(report,sort_keys=True)+'\n')
        print('OUF_TRANSACTION_NETWORK_INPUTS='+json.dumps(report,sort_keys=True))
        print('OUF_TRANSACTION_NETWORK_REPORT='+str(result_dir))
        return 0
    except Exception as error:
        reason = str(error) if isinstance(error,InputDenied) else {
            FileNotFoundError:'REQUIRED_NETWORK_INPUT_NOT_FOUND',PermissionError:'NETWORK_INPUT_NOT_READABLE',
            KeyError:'REQUIRED_NETWORK_FIELD_MISSING',json.JSONDecodeError:'NETWORK_INPUT_JSON_INVALID'
        }.get(type(error),'NETWORK_INPUT_PROJECTION_FAILED')
        diagnosis = {'status':'BLOCKED','stage':stage,'input':selected,'reason':reason,
            'errorClass':type(error).__name__,'configurationWrites':0,'containerLifecycleOperations':0,
            'privateKeysRead':0,'secretValuesPrinted':False,'startAuthorized':False}
        if result_dir:
            (result_dir/'diagnosis.json').write_text(json.dumps(diagnosis,sort_keys=True)+'\n')
            print('OUF_TRANSACTION_NETWORK_REPORT='+str(result_dir))
        print('OUF_TRANSACTION_NETWORK_INPUTS='+json.dumps(diagnosis,sort_keys=True))
        return 1

if __name__=='__main__': raise SystemExit(main())
