"""Prepare new private startup inputs from sealed existing bindings; never create/start runtime."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import types

TRUST = Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-trust-vf7B4SM5')
TRUST_HASH = 'bb158aa0eda6c767f6bdf6f4ac6e0f8eefd93cfe6f0ee48196d0f9bf7f521458'
HELPER_HASH = 'a724becfa3dbcb60052b9cb38a5479372747adb32bc54a7f6cb7b2eb4c3b1226'
OLD = Path('/etc/ouf/deploy-snapshots/semantic-provider-runtime-20261002-222530')
OLD_STAGE_HASH = '768f37067b94b851f3e83ee224955c434dcd083c96717f4618f5675f0b7ae503'
SOURCE_COMMIT = 'ace683b1019f79adaace86796b67e463b93ec12e'
SOURCE_HASHES = {"tools/southbound_security.py":"5953e6143fb7141b62a2d5cc26d8cf85ee74147d9eefaa923460f8e1706eb0ec","tools/semantic_provider_boundary.py":"cae2b1d5970349ce1ebc95fb44ca4dd1bd67d93e43900ad4cbeabb3d5fbd6e69","tools/semantic_provider_admission.py":"dca670d1f0ced678db6af9810199da07419901a21523385e0ebea623b608bbfc","tools/semantic_provider_relay.py":"04b33da9b3d599872c19ea20d3775141ef99c5989c7fb7175be6926b74cc7f6f","tools/semantic_provider_adapter.py":"718f031cd4116d233c3075ee74da2f28170b5ed4efcac1a77deef154f7fd320c","tools/materialize_semantic_provider.py":"d9ed454412988dddf1737a6b425830a99047ad5764f0574f7fb74bc4b52f8a78","tools/materialize_semantic_provider_runtime.py":"3a44570e5b2e4e9bfafb11be8f053d2a1d608d959bed64fe4b826c9943b7b056","tools/materialize_semantic_provider_tls.py":"5b2ad608307455efb8f39802d2264325e1debe76ba774ff78e264551028d0963","tools/lua/admit_semantic_provider.lua":"ab3d286a1ac7c59e5e34ce4617fc3ba9c79070f60df859e5e8a60d88ed92ca3d"}
ORDER = ('southbound_security', 'semantic_provider_boundary', 'semantic_provider_admission',
         'semantic_provider_relay', 'semantic_provider_adapter', 'materialize_semantic_provider',
         'materialize_semantic_provider_runtime', 'materialize_semantic_provider_tls')
STAGE = 'ARGUMENT_VALIDATION'

def require(ok):
    if not ok:
        raise ValueError('PROVIDER_V2_STARTUP_INPUTS_UNPROVEN')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()

def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)

def raw_source(filename, expected):
    fd = os.open(filename, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 0 and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size <= 1048576)
        raw = os.read(fd, 1048577); require(digest(raw) == expected)
        return raw
    finally:
        os.close(fd)

def load_compilers(root, read):
    require('tools' not in sys.modules)
    files = {name: read(root/name) for name in SOURCE_HASHES}
    require(all(digest(raw) == SOURCE_HASHES[name] for name, raw in files.items()))
    package = types.ModuleType('tools'); package.__path__ = []
    sys.modules['tools'] = package
    for name in ORDER:
        module_name = 'tools.'+name
        module = types.ModuleType(module_name)
        module.__file__ = str(root/'tools'/(name+'.py')); module.__package__ = 'tools'
        sys.modules[module_name] = module
        exec(compile(files['tools/'+name+'.py'], module.__file__, 'exec'), module.__dict__)
        setattr(package, name, module)
    return package, files

def rebind(binding, hosts):
    updated = copy.deepcopy(binding)
    updated['tlsIdentities'] = copy.deepcopy(hosts)
    host = hosts['adapterHostname']; port = updated['adapter']['listenPort']
    updated['routes']['upstream']['upstream_host'] = host
    updated['routes']['upstream']['nodes'] = {host+':'+str(port): 1}
    return updated

def selected_environment(env, binding, receipt_key):
    require(type(env) is list and len(env) <= 512)
    values = {}
    for item in env:
        require(type(item) is str and '=' in item)
        name, value = item.split('=', 1)
        require(name not in values); values[name] = value
    ref = binding['routes']['oidcSecretRef']
    require(re.fullmatch(r'\$ENV://[A-Z][A-Z0-9_]{1,127}', ref))
    oidc = ref.removeprefix('$ENV://')
    mac = binding['routes']['receiptKeyEnvironment']
    require(re.fullmatch(r'[A-Z][A-Z0-9_]{1,127}', mac) and oidc != mac and not {oidc,mac} & {'PATH','HOME','LD_PRELOAD','PYTHONPATH'})
    secret = values.get(oidc)
    require(type(secret) is str and 16 <= len(secret) <= 1024 and not any(c in secret for c in '\r\n\x00'))
    require(re.fullmatch(b'[0-9a-f]{64}', receipt_key))
    return oidc.encode()+b'='+secret.encode()+b'\n'+mac.encode()+b'='+receipt_key+b'\n'

def stopped_southbound():
    template = '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"State":{{json .State}},"Mounts":{{json .Mounts}},"Env":{{json .Config.Env}}}'
    r = subprocess.run(['/usr/bin/docker','inspect','--type','container','--format',template,'ouf-semantic-southbound'], capture_output=True, timeout=30)
    require(r.returncode == 0 and len(r.stdout) <= 1048576)
    row = decode(r.stdout)
    require(row['Name'] == '/ouf-semantic-southbound' and re.fullmatch(r'[0-9a-f]{64}', row['Id']))
    require(row['Image'] == 'sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d')
    require(row['State']['Status'] == 'created' and row['State']['Running'] is False and row['State']['StartedAt'] == '0001-01-01T00:00:00Z')
    mounts = [m for m in row['Mounts'] if m['Destination'] == '/usr/local/apisix/conf/config.yaml']
    require(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and mounts[0]['RW'] is False)
    source = Path(mounts[0]['Source'])
    require(source.is_absolute() and '..' not in source.parts and source.is_relative_to('/etc/ouf/deploy-snapshots'))
    return row, source

def prepare(root):
    global STAGE
    require(os.geteuid() == os.getegid() == 0)
    require(root.parent == Path('/etc/ouf/deploy-snapshots') and re.fullmatch(r'semantic-provider-v2-inputs-[A-Za-z0-9]+', root.name))
    STAGE = 'TRUST_HELPER_SOURCE'
    helper = raw_source(TRUST/'prepare-provider-v2-trust.py', HELPER_HASH)
    ns = {'__name__':'ouf_private_input_helpers', '__file__':str(TRUST/'prepare-provider-v2-trust.py')}
    exec(compile(helper, ns['__file__'], 'exec'), ns)
    read, write = ns['read'], ns['write']
    ns['ancestors'](root); require(stat.S_IMODE(root.lstat().st_mode) == 0o700)
    own = read(root/'prepare-provider-v2-inputs.py')
    STAGE = 'FRESH_TRUST_RECEIPT'
    trust_raw = read(TRUST/'trust-receipt.json'); require(digest(trust_raw) == TRUST_HASH)
    trust = decode(trust_raw)
    require(trust['status'] == 'PRIVATE_TRUST_PREPARED' and trust['startAuthorized'] is False and trust['mountsInstalled'] is False)
    roles = {r['role']:r for r in trust['roles']}
    require(set(roles) == {'adapter','southbound'})
    require((roles['adapter']['uid'],roles['adapter']['gid']) == (10006,10006) and (roles['southbound']['uid'],roles['southbound']['gid']) == (636,636))
    openssl = ns['verified_executable'](ns['OPENSSL'], ns['OPENSSL_HASH'])
    STAGE = 'SEALED_COMPILER_CLOSURE'
    package, sources = load_compilers(root/'source', read)
    STAGE = 'EXISTING_RUNTIME_BINDING'
    possible = [p for p in (OLD, OLD/'prepared') if all((p/n).is_file() for n in ('stage-receipt.json','binding.json','runtime-plan.json'))]
    require(len(possible) == 1); old_root = possible[0]
    stage_raw = read(old_root/'stage-receipt.json'); require(digest(stage_raw) == OLD_STAGE_HASH)
    old_stage = decode(stage_raw)
    expected_old = {name: sha for name,sha in SOURCE_HASHES.items() if name != 'tools/materialize_semantic_provider_tls.py'}
    require(old_stage['sourceHashes'] == expected_old and old_stage['notReleaseAcceptance'] is True and old_stage['runtimeFilesMounted'] is False)
    binding_raw = read(old_root/'binding.json'); plan_raw = read(old_root/'runtime-plan.json')
    require(digest(binding_raw) == old_stage['bindingHash'] and digest(plan_raw) == old_stage['planHash'])
    original = decode(binding_raw); require(package.materialize_semantic_provider_runtime.compile_plan(original) == decode(plan_raw))
    binding = rebind(original, {'adapterHostname':roles['adapter']['hostname'], 'southboundHostname':roles['southbound']['hostname']})
    plan = package.materialize_semantic_provider_runtime.compile_plan(binding)
    STAGE = 'STOPPED_ROLE_CONFIGURATION'
    old_container, old_config_path = stopped_southbound()
    old_config_raw = read(old_config_path, 636, 636)
    old_tls_receipt_raw = read(old_config_path.parent/'tls-runtime-receipt.json')
    old_tls_receipt = decode(old_tls_receipt_raw)
    require(old_tls_receipt['intent']['stageReceiptHash'] == OLD_STAGE_HASH and old_tls_receipt['outputHashes']['config.yaml'] == digest(old_config_raw))
    old_config = decode(old_config_raw)
    listeners = old_config['apisix']['ssl']['listen']
    require(old_config['apisix']['node_listen'] == [] and old_config['apisix']['enable_admin'] is False and old_config['apisix']['enable_control'] is False and len(listeners) == 1)
    transport = {'listenAddress':listeners[0]['ip'],'listenPort':listeners[0]['port'],'serverHostname':roles['southbound']['hostname'],'sslResourceId':'semantic-provider-v2'}
    STAGE = 'PRIVATE_RUNTIME_TLS_FILES'
    runtime = {}
    for role in ('adapter','southbound'):
        uid,gid = roles[role]['uid'],roles[role]['gid']
        for name in ('server.crt','server.key','provider-receipt.key'):
            filename = role+'/'+name; value = read(TRUST/filename, uid, gid)
            require(digest(value) == trust['artifactHashes'][filename]); runtime[filename] = value
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(TRUST/role/'server.crt', TRUST/role/'server.key')
        ns['command'](ns['OPENSSL'],'verify','-CAfile',TRUST/'ca.crt','-purpose','sslserver','-verify_hostname',roles[role]['hostname'],TRUST/role/'server.crt')
        ns['command'](ns['OPENSSL'],'x509','-in',TRUST/role/'server.crt','-checkend','86400','-noout')
    require(runtime['adapter/provider-receipt.key'] == runtime['southbound/provider-receipt.key'])
    for name in ('ca.crt','trust-bundle.pem'):
        value = read(TRUST/name, private=(name == 'ca.crt'))
        require(digest(value) == trust['artifactHashes'][name] and b'PRIVATE KEY' not in value)
        runtime[name] = value
    bootstrap = package.materialize_semantic_provider_tls.materialize_tls(binding['routes'],transport,certificate_pem=runtime['southbound/server.crt'].decode('ascii'),private_key_pem=runtime['southbound/server.key'].decode('ascii'))
    environment = selected_environment(old_container['Env'], binding, runtime['southbound/provider-receipt.key'])
    files = {'binding.json':(encoded(binding),0,0), 'runtime-plan.json':(encoded(plan),0,0),
        'adapter.json':(encoded(binding['adapter']),10006,10006),
        'config.yaml':(encoded(bootstrap['runtimeConfiguration']),636,636),
        'apisix.yaml':(encoded(bootstrap['resources'])+b'#END\n',636,636),
        'southbound.env':(environment,0,0)}
    def stable():
        require(read(TRUST/'trust-receipt.json') == trust_raw and read(TRUST/'prepare-provider-v2-trust.py') == helper)
        require(read(root/'prepare-provider-v2-inputs.py') == own)
        require(all(read(root/'source'/n) == raw for n,raw in sources.items()))
        require(read(old_root/'stage-receipt.json') == stage_raw and read(old_root/'binding.json') == binding_raw and read(old_root/'runtime-plan.json') == plan_raw)
        row, path = stopped_southbound()
        require(row == old_container and path == old_config_path and read(path,636,636) == old_config_raw and read(path.parent/'tls-runtime-receipt.json') == old_tls_receipt_raw)
        require(ns['verified_executable'](ns['OPENSSL'],ns['OPENSSL_HASH']) == openssl)
        for name,value in runtime.items():
            role = name.split('/')[0]; ids = (roles[role]['uid'],roles[role]['gid']) if role in roles else (0,0)
            require(read(TRUST/name,*ids,private=(name != 'trust-bundle.pem')) == value)
    STAGE = 'INPUT_STABILITY'
    stable()
    require(all(not os.path.lexists(root/n) for n in (*files,'preparation-claim.json','runtime-input-receipt.json')))
    STAGE = 'PRIVATE_OUTPUT_PUBLICATION'
    write(root/'preparation-claim.json',encoded({'schema':'ouf.semantic-provider-v2-inputs-claim.v1','state':'PREPARING_PRIVATE_INPUTS','trustReceiptHash':TRUST_HASH,'oldStageReceiptHash':OLD_STAGE_HASH,'sourceHash':digest(own),'startAuthorized':False}))
    output_hashes = {}
    for name,(raw,uid,gid) in files.items():
        write(root/name,raw,uid,gid); require(read(root/name,uid,gid) == raw)
        output_hashes[name] = digest(raw)
    stable()
    report = {'schema':'ouf.semantic-provider-v2-startup-inputs.v1','status':'PRIVATE_STARTUP_INPUTS_PREPARED','directory':str(root),'sourceHash':digest(own),'sourceCommit':SOURCE_COMMIT,'sourceHashes':SOURCE_HASHES,'trustDirectory':str(TRUST),'trustReceiptHash':TRUST_HASH,'oldStageReceiptHash':OLD_STAGE_HASH,'oldSouthboundId':old_container['Id'],'oldTlsReceiptHash':digest(old_tls_receipt_raw),'outputHashes':output_hashes,'roleImages':{name:row['imageId'] for name,row in roles.items()},'runtimeUsers':{name:row['runtimeUser'] for name,row in roles.items()},'hostnames':binding['tlsIdentities'],'southboundListenerPort':transport['listenPort'],'environmentNames':[binding['routes']['oidcSecretRef'].removeprefix('$ENV://'),binding['routes']['receiptKeyEnvironment']],'originalProviderBindingPreserved':True,'existingOidcCredentialReused':True,'oldInputsModified':False,'offlineCaKeyRead':False,'installationAuthorityKeysRead':0,'imageImportPerformed':False,'containerLifecycleOperations':0,'mountsInstalled':False,'providerCalls':0,'rulesChanged':False,'serviceChanges':0,'secretValuesPrinted':False,'notReleaseAcceptance':True,'acceptanceGranted':False,'startAuthorized':False}
    write(root/'runtime-input-receipt.json',encoded(report)); require(read(root/'runtime-input-receipt.json') == encoded(report))
    return report

def main():
    p=argparse.ArgumentParser();p.add_argument('--package-root',type=Path,required=True);p.add_argument('--prepare-private-startup-inputs-only',action='store_true');args=p.parse_args()
    try:
        require(args.prepare_private_startup_inputs_only)
        print('OUF_PROVIDER_V2_INPUTS='+json.dumps(prepare(args.package_root),sort_keys=True));return 0
    except Exception as error:
        kind=type(error).__name__; allowed={'ValueError','OSError','PermissionError','FileNotFoundError','SSLError','KeyError','TypeError','TimeoutExpired'}
        print('OUF_PROVIDER_V2_INPUTS=BLOCKED STAGE='+STAGE+' ERROR_CLASS='+(kind if kind in allowed else 'OTHER')+' PARTIAL_EVIDENCE_RETAINED=true DO_NOT_RERUN_APPLY=true NO_RAW_OUTPUT=true');return 1

if __name__ == '__main__':
    raise SystemExit(main())
