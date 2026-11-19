#!/usr/bin/env python3
"""Read the sealed generation recipe lineage. Never invoke an installed producer.

The original independent drafts and the installed policy are distinct inputs.
Differences are reported by JSON path only. Historical rootfs seals remain
historical; this reader neither verifies their signatures nor grants authority.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import sys
import tempfile
import traceback
import types
from datetime import datetime, timezone

PREPARER = 'prepare-discovery-generation-inputs-20261109.py'
PREPARER_SHA = '7a3d618aa933c42cfcdac3eb5965e97521a64934dd778aa1c66b244f7d4f99a0'
COMPILER = 'compile_creation_frame_policy.py'
COMPILER_SHA = '36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d'
ROOT = Path('/etc/ouf/deploy-snapshots/discovery-generation-inputs-99d46y_j')
RESULT = Path('/var/lib/ouf-storage-migration/discovery-generation-inputs-cv_hy837/result.json')
RESULT_SHA = '8c6d8eb8ae5dd47b9a12d304f53d02ad1e09afad61dfa28282ccda482182af15'
INPUT_HASHES = {
    'adapter-inputs.private.json':'896117c1df0cff8e89eb46a38f380770127752766032cb76862b7234232f3ed1',
    'southbound-inputs.private.json':'a4024aaf0e8ae89ee35fdd0a7aae244fde4611ae22b79611432e7a59647ed98d',
    'generation-plan.private.json':'53a6f06a58133779654eebb9fbfd302d2ce4160f5262e0fb0e8d37610c7394fb'}
LAUNCH_ROOT = Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-launch-inputs-7g1du3a6')
FRAME_ROOT = Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-frame-policies-5m18tpzh')
RECIPES = {
    'adapter':{
        'launch':'061e2bd245d45d7e435ff86e07a6897413ae6c164d2d2c9ade2d455d80846943',
        'template':'bf536f60c1d511f4cdbeb8546e84f46d426f693019938a0a9b4dbf76b3308e01',
        'context':'ede2f4ee4de3b869d11e125cad094cbc5bad900bdb365a10d5d365d3104853ca',
        'policy':'e8047e92e8b3938abe67dc8e57f385fced9de1218db348b4723eb3c6d34867fd'},
    'southbound':{
        'launch':'cbc1f30c200a6a27e92b8055aa5542df30f7d124d08004d6f3bfe7dfb9ed2a39',
        'template':'0ef8aa503bfb6a5c789000cd73de6e987d1a55688894475e555f4d566581ad05',
        'context':'e515366dbe8412bf261711ea98bcaac3e6d9e9d8bc3f77109829613ec166f4eb',
        'policy':'f49155fa412bb76d529713cb4ac2c253105884e9e72f7d2d74dfc5ccf9c5c822'}}


def need(ok, reason):
    if not ok: raise RuntimeError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
def hashed(value): return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None
def token(value, maximum=128):
    need(type(value) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,'+str(maximum-1)+'}',value),
         'PUBLIC_IDENTIFIER_SHAPE_REQUIRED')
    return value


def module(name, digest):
    p=Path(__file__).with_name(name);raw=p.read_bytes()
    need(sha(raw)==digest,'PINNED_SOURCE_CHANGED')
    namespace={'__name__':'generation_source_dependency','__file__':str(p)}
    exec(compile(raw,str(p),'exec'),namespace)
    return types.SimpleNamespace(**namespace)


class Documents:
    """Only explicit metadata paths; no directory walking or signing-key reads."""
    def __init__(self, read, parse): self.read=read;self.parse=parse;self.original={}

    def raw(self,path,digest=None):
        path=Path(path)
        need(path.is_absolute() and '..' not in path.parts and
             any(path.is_relative_to(p) for p in ('/etc/ouf','/var/lib/ouf-storage-migration')),
             'EXACT_METADATA_PATH_REQUIRED')
        need(len(self.original)<64 or str(path) in self.original,'METADATA_READ_BOUND')
        raw=self.read(path)
        need(digest is None or hashed(digest) and sha(raw)==digest,'SEALED_METADATA_HASH_CHANGED')
        need(str(path) not in self.original or self.original[str(path)]==raw,'METADATA_CHANGED_BETWEEN_READS')
        self.original[str(path)]=raw
        return raw

    def value(self,path,digest=None): return self.parse(self.raw(path,digest))

    def binding(self,binding):
        need(type(binding) is dict and set(binding)=={'path','sha256'} and hashed(binding['sha256']),
             'EXACT_METADATA_BINDING_REQUIRED')
        return self.value(binding['path'],binding['sha256'])

    def recheck(self):
        for path,raw in self.original.items():
            need(self.read(Path(path))==raw,'METADATA_CHANGED_DURING_READ')


def differences(left,right,path=''):
    if type(left) is not type(right): return [path or '/']
    if isinstance(left,dict):
        out=[]
        for k in sorted(set(left)|set(right)):
            child=path+'/'+k.replace('~','~0').replace('/','~1')
            out.extend([child] if k not in left or k not in right else differences(left[k],right[k],child))
        return out
    if isinstance(left,list):
        if len(left)!=len(right): return [path+'/length']
        return [p for i,(a,b) in enumerate(zip(left,right)) for p in differences(a,b,path+'/'+str(i))]
    return [] if left==right else [path or '/']


def nic_summary(nic):
    required={'interface','bridge','mac','ipv4','workloadRef','bindingRef'}
    need(type(nic) is dict and set(nic) in (required,required|{'leaseGuard'}),'EXACT_NIC_METADATA_REQUIRED')
    out={k:token(nic[k],15 if k in ('interface','bridge') else 128)
         for k in ('interface','bridge','workloadRef','bindingRef')}
    mac=nic['mac'];need(type(mac) is str and re.fullmatch('[0-9a-f]{2}(:[0-9a-f]{2}){5}',mac)
        and not int(mac[:2],16)&1 and mac!='00:00:00:00:00:00','EXACT_ENDPOINT_MAC_REQUIRED')
    ip=ipaddress.ip_address(nic['ipv4']);need(ip.version==4,'IPV4_METADATA_REQUIRED')
    out.update(mac=mac,ipv4=str(ip))
    if 'leaseGuard' in nic:
        guard=nic['leaseGuard'];need(set(guard)=={'configurationHash','tableName'} and hashed(guard['configurationHash']),
                                   'EXACT_LEASE_GUARD_METADATA_REQUIRED')
        out['leaseGuard']={'configurationHash':guard['configurationHash'],'tableName':token(guard['tableName'],32)}
    return out


def candidate_summary(candidate):
    need(type(candidate) is dict and set(candidate)=={'containerId','transactionId','networkBindings','transport',
         'tableName','runtimeBinding'} and hashed(candidate['containerId']),'EXACT_CANDIDATE_METADATA_REQUIRED')
    nics=candidate['networkBindings'];flows=candidate['transport']
    need(type(nics) is list and 1<=len(nics)<=8 and type(flows) is list and 1<=len(flows)<=128,
         'BOUNDED_CANDIDATE_METADATA_REQUIRED')
    peers={};kinds={};transport=[]
    for flow in flows:
        need(type(flow) is dict and set(flow)=={'purpose','authorityRef','source','destination','protocol','port','peerIngress'},
             'EXACT_TRANSPORT_METADATA_REQUIRED')
        addresses={}
        for name in ('source','destination'):
            address=ipaddress.ip_address(flow[name]);need(address.version==4,'IPV4_TRANSPORT_REQUIRED')
            addresses[name]=str(address)
        need(flow['protocol'] in ('tcp','udp') and type(flow['port']) is int and 1<=flow['port']<=65535,
             'EXACT_TRANSPORT_PORT_REQUIRED')
        item_flow={'purpose':token(flow['purpose']),**addresses,'protocol':flow['protocol'],'port':flow['port']}
        peer=flow['peerIngress'];kind=peer['kind'];need(kind in ('CREATED_CANDIDATE','HOST','ROUTED','BRIDGE_PORT'),
                                                     'KNOWN_PEER_KIND_REQUIRED')
        kinds[kind]=kinds.get(kind,0)+1
        if kind=='CREATED_CANDIDATE':
            need(set(peer)=={'kind','declaration','bindingRef'},'EXACT_PEER_METADATA_REQUIRED')
            d=peer['declaration'];need(set(d)=={'containerId','applicationHash','networkBindings'}
                and hashed(d['containerId']) and hashed(d['applicationHash']),'EXACT_PEER_IDENTITY_REQUIRED')
            need(type(d['networkBindings']) is list and 1<=len(d['networkBindings'])<=8,'BOUNDED_PEER_NICS_REQUIRED')
            item={'containerId':d['containerId'],'applicationHash':d['applicationHash'],
                  'networkBindings':[nic_summary(n) for n in d['networkBindings']]}
            need(d['containerId'] not in peers or peers[d['containerId']]==item,'INCONSISTENT_HISTORICAL_PEER')
            peers[d['containerId']]=item
            item_flow['peerIngress']={'kind':kind,'containerId':d['containerId'],'bindingRef':token(peer['bindingRef'])}
        else:
            need(set(peer)=={'kind','ifindex'} and type(peer['ifindex']) is int
                 and (peer['ifindex']==0 if kind=='HOST' else 1<peer['ifindex']<2147483647),
                 'EXACT_HISTORICAL_PEER_INDEX_REQUIRED')
            item_flow['peerIngress']={'kind':kind,'ifindex':peer['ifindex']}
        transport.append(item_flow)
    return {'historicalContainerId':candidate['containerId'],'networkBindings':[nic_summary(n) for n in nics],
            'transportKinds':kinds,'transport':transport,'peers':[peers[k] for k in sorted(peers)],
            'tableName':token(candidate['tableName'],32),'transportSha256':sha(encoded(flows).rstrip(b'\n'))}


def read_role(role,inputs,cfg,docs,compiler):
    need(inputs.get('schema')=='ouf.discovery-role-generation-inputs.v1' and inputs.get('role')==role
         and inputs.get('state')=='UNSIGNED_INPUTS_ONLY' and inputs.get('runtimeConfigurationProduced') is False,
         'UNSIGNED_PREPARED_ROLE_REQUIRED')
    template=inputs['historicalTemplate'];candidate=template['candidate'];cid=candidate['containerId']
    summary=candidate_summary(candidate);root=Path(cfg['registryRoot'])/cid;entry=cfg['candidates'][cid]
    need(entry['admissionConfiguration']==str(root/'broker.json'),'EXACT_HISTORICAL_BROKER_REQUIRED')
    broker=docs.value(root/'broker.json',entry['admissionConfigurationHash'])
    need(docs.binding(broker['preparerTemplate'])==template,'PREPARED_TEMPLATE_LINEAGE_CHANGED')
    node_binding=broker['producers']['attestation']['configuration']
    need(node_binding['path']==str(root/'attestation-producer.json'),'EXACT_ATTESTOR_METADATA_REQUIRED')
    node=docs.binding(node_binding)
    need(node['schema']=='ouf.semantic-node-attestor.v4','V4_ATTESTOR_METADATA_REQUIRED')
    policy_binding=node['creationFrameObserverBinding']['configuration'];installed=docs.binding(policy_binding)
    need(installed['schema']=='ouf.semantic-configured-creation-frame-policy.v1','INSTALLED_FRAME_POLICY_REQUIRED')
    documents={}
    for name,digest in RECIPES[role].items():
        path=(LAUNCH_ROOT if name=='launch' else FRAME_ROOT)/(role+'.'+name+'.json')
        documents[name]=docs.value(path,digest)
    need(documents['context']['containerId']==cid,'HISTORICAL_RECIPE_CID_CHANGED')
    compiled=compiler.compile_policy(documents['template'],documents['launch'],documents['context'])
    need(compiled==documents['policy'],'INDEPENDENT_RECIPE_RECOMPILATION_FAILED')
    delta=differences(compiled,installed)
    # Only schema field/index paths escape. Values, argv, env and source bodies never do.
    need(len(delta)<=256 and all(re.fullmatch(r'/[A-Za-z0-9_~/.-]{0,512}',p) for p in delta),
         'BOUNDED_FRAME_DIFFERENCE_PATHS_REQUIRED')
    auth_path=Path(node['liveAcceptanceAuthorizationPath'])
    need(auth_path==root/'live-authorization.json','EXACT_HISTORICAL_AUTHORIZATION_METADATA_REQUIRED')
    auth=docs.value(auth_path);seal=auth['rootfsSeal']
    need(auth['containerId']==cid and type(seal) is dict and set(seal)=={'schema','sha256','entries','bytes'}
         and seal['schema']=='ouf.semantic-rootfs-seal.v1' and hashed(seal['sha256'])
         and type(seal['entries']) is int and 1<=seal['entries']<=100000
         and type(seal['bytes']) is int and 0<=seal['bytes']<=8589934592,'HISTORICAL_FULL_V1_SEAL_REQUIRED')
    summary.update(independentRecipeRecompiled=True,originalDraftMatchesInstalledPolicy=not delta,
        installedPolicyBinding=policy_binding,originalDraftDifferencePaths=delta,
        installedApplicationHash=sha(compiler.canonical(installed['expectedOci'])),
        historicalRootfsSeal=seal,historicalAuthorityReused=False,signaturesVerified=False,
        historicalAuthorizationSha256=sha(docs.original[str(auth_path)]),
        launchSourceCount=len(documents['launch']['sources']),mountSourceContentsRead=0)
    return summary


def collect(p,b,c,compiler,docs):
    receipt=docs.value(RESULT,RESULT_SHA)
    need(receipt['status']=='DISCOVERY_GENERATION_INPUTS_PREPARED' and receipt['phase']=='COMPLETE'
         and receipt['preparationDirectory']==str(ROOT) and receipt['fileHashes']==INPUT_HASHES,
         'EXACT_COMPLETED_INPUT_PREPARATION_REQUIRED')
    need(docs.raw(p.CLAIM/'complete.json')==docs.original[str(RESULT)],'PREPARATION_COMPLETION_CHANGED')
    data={name:docs.value(ROOT/name,digest) for name,digest in INPUT_HASHES.items()}
    plan=data['generation-plan.private.json']
    need(plan['schema']=='ouf.discovery-generation-input-plan.v1' and plan['state']=='UNSIGNED_INPUTS_ONLY'
         and plan['authorityIssued'] is False and plan['runtimeConfigurationProduced'] is False,
         'UNSIGNED_PLAN_REQUIRED')
    docs.raw(b.POINTER,plan['activePointerSha256'])
    bindings=plan['sourceBindings'];need(type(bindings) is dict and len(bindings)==5,'EXACT_FIVE_SOURCE_BINDINGS_REQUIRED')
    selected=[path for path,digest in bindings.items() if digest==c.l.CONFIG_SHA]
    need(len(selected)==1,'EXACT_HISTORICAL_RUNTIME_CONFIGURATION_REQUIRED')
    for path,digest in bindings.items():docs.raw(path,digest)
    cfg=docs.value(selected[0],c.l.CONFIG_SHA)
    roles={role:read_role(role,data[role+'-inputs.private.json'],cfg,docs,compiler) for role in ('adapter','southbound')}
    docs.recheck()
    return roles


def main():
    report={'schema':'ouf.discovery-generation-source-read.v1','status':'HELD',
        'observedAt':datetime.now(timezone.utc).isoformat(),'runtimeObserved':False,
        'credentialFileContentsRead':0,'mountSourceContentsRead':0,'credentialValuesEmitted':False,
        'engineRequests':0,'databaseRequests':0,'providerRequests':0,'tokenRequests':0,'dnsQueries':0,
        's3Requests':0,'businessRequestsIssued':0,'containerCreates':0,'serviceStarts':0,'serviceStops':0,
        'daemonReloads':0,'nftWrites':0,'signaturesProduced':0,'historicalJournalWrites':0,
        'activeInstallationPointerChanged':False,'runtimeWrapperChanged':False,
        'newGenerationAdmitted':False,'providerReady':False,'leaseAuthorized':False,'startAuthorized':False,
        'automaticReplayAllowed':False}
    work=None;c=None
    def deadline(*_):raise RuntimeError('GENERATION_SOURCE_READ_DEADLINE')
    signal.signal(signal.SIGALRM,deadline);signal.alarm(90)
    try:
        need(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
        os.umask(0o077);p=module(PREPARER,PREPARER_SHA);b=p.boot_module();c=b.dependency()
        compiler=module(COMPILER,COMPILER_SHA)
        work=Path(tempfile.mkdtemp(prefix='discovery-generation-sources-',dir=RESULT.parent.parent))
        report['privateEvidenceDirectory']=str(work)
        docs=Documents(c.p.read_private,c.l.parse)
        report['phase']='READ_SEALED_RECIPE_LINEAGE'
        roles=collect(p,b,c,compiler,docs)
        c.p.save(work/'source-bindings.private.json',encoded({path:sha(raw) for path,raw in docs.original.items()}))
        docs.recheck()
        report.update(status='DISCOVERY_GENERATION_SOURCES_READ',phase='COMPLETE',roles=roles,
            metadataFilesRead=len(docs.original),sourceFilesStableDuringRead=True,snapshotAtomic=False,
            currentSemanticPeerStillRequiresIndependentReview=True,
            historicalRootfsSealsAreNotNewGenerationExpectations=True)
    except Exception as exc:
        reason=str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(exc)) else type(exc).__name__
        report.update(status='HELD',reason=reason,errorLocation=[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}
            for f in traceback.extract_tb(exc.__traceback__)[-3:]])
    finally:
        signal.alarm(0)
        if work is not None and c is not None:c.p.save(work/'result.json',encoded(report))
    print(json.dumps(report,sort_keys=True));return 0 if report['status']=='DISCOVERY_GENERATION_SOURCES_READ' else 1


if __name__=='__main__':sys.exit(main())
