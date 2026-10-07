"""Install pinned issuer source and bind existing authority; no signing or runtime action."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

MODULES = ('materialize_southbound_kernel','materialize_southbound_lease_refresh','semantic_provider_dns',
    'semantic_provider_lease_nft','semantic_provider_lease_owner','materialize_semantic_shared_faces',
    'semantic_provider_lease_coordination','semantic_provider_preexec','semantic_provider_preexec_native',
    'semantic_provider_deployment_admission','semantic_provider_deployment_protocol',
    'semantic_provider_deployment_consumption','semantic_provider_deployment_authentication',
    'semantic_provider_deployment_reauthorization','semantic_provider_deployment_producer',
    'semantic_provider_deployment_signing','semantic_provider_installer_approval','semantic_provider_creation_intent')
NAMES = ('scripts/semantic_provider_creation_intent.py', *('tools/'+n+'.py' for n in MODULES))
CUSTODY = Path('/etc/ouf/deploy-snapshots/semantic-authority-provisioning-20261004-164654')
POLICY = Path('/etc/ouf/deploy-snapshots/semantic-trust-policy-preparation-20261004-172336/trust-policy.json')
CUSTODY_HASH = 'a134c4c8e8487860e6a8ed3a672520935a5de753d02507c4005a0475570b2d49'
POLICY_HASH = '21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42'
BINDINGS = {'installation_ref':'ouf-lab-netcup-01','entity_ref':'ouf-lab',
    'installer_issuer_ref':'ouf-lab-infrastructure-installer','installer_key_ref':'ouf-lab-installer-ed25519-1',
    'attestor_issuer_ref':'ouf-lab-node-attestor','attestor_key_ref':'ouf-lab-attestor-ed25519-1'}

def require(ok):
    if not ok: raise ValueError('INPUT_OR_READBACK_UNPROVEN')

def encoded(v): return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(b): return hashlib.sha256(b).hexdigest()
def decode(raw):
    def unique(items):
        out = {}
        for k, v in items:
            require(k not in out); out[k] = v
        return out
    value = json.loads(raw,object_pairs_hook=unique)
    require(type(value) is dict); return value

def ancestors(path):
    require(path.is_absolute() and '..' not in path.parts)
    for p in (path.parent,*path.parent.parents):
        s=p.lstat(); require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022)

def metadata(path):
    ancestors(path); s=path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=131072)
    return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def read(path):
    before=metadata(path); fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        raw=os.read(fd,131073); require(len(raw)==before[6] and metadata(path)==before)
        s=os.fstat(fd); require(tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))==before)
        return raw
    finally: os.close(fd)

def publish(path, raw):
    ancestors(path); fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=False) as f: f.write(raw); f.flush(); os.fsync(fd)
    finally: os.close(fd)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
    require(read(path)==raw)

def install(root, manifest_hash):
    require(os.geteuid()==0 and root.is_absolute() and re.fullmatch('[0-9a-f]{64}',manifest_hash))
    for p in (root,root/'source',root/'source/scripts',root/'source/tools'):
        ancestors(p/'placeholder'); s=p.lstat(); require(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700)
    require({p.name for p in root.iterdir()}=={'source','sources.json','install-creation-issuer.py'})
    manifest_raw=read(root/'sources.json'); require(digest(manifest_raw)==manifest_hash)
    manifest=decode(manifest_raw); require(set(manifest)=={'sourceCommit','sourceHashes'} and re.fullmatch('[0-9a-f]{40}',manifest['sourceCommit']) and set(manifest['sourceHashes'])==set(NAMES))
    source={n:read(root/'source'/n) for n in NAMES}
    for n, raw in source.items():
        require(digest(raw)==manifest['sourceHashes'][n]); compile(raw,str(root/'source'/n),'exec')
    require({str(p.relative_to(root/'source')) for p in (root/'source').rglob('*') if not p.is_dir()}==set(NAMES))
    for p in (root/'source').rglob('*'):
        s=p.lstat()
        if stat.S_ISDIR(s.st_mode):
            require(str(p.relative_to(root/'source')) in ('scripts','tools') and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700)
        else: metadata(p)
    installer_raw=read(root/'install-creation-issuer.py')
    custody_raw=read(CUSTODY/'key-custody-receipt.json'); policy_raw=read(POLICY)
    require(digest(custody_raw)==CUSTODY_HASH and digest(policy_raw)==POLICY_HASH)
    custody, policy=decode(custody_raw),decode(policy_raw)
    require(custody['schema']=='ouf.semantic-authority-key-custody-receipt.v1' and custody['bindings']==BINDINGS)
    require(policy['schema']=='ouf.semantic-deployment-trust-policy.v1' and policy['installationRef']==BINDINGS['installation_ref'] and policy['entityRef']==BINDINGS['entity_ref'] and len(policy['keys'])==2)
    now=int(time.time()); key_bindings={}; public_inputs={}; key_metadata={}
    for role, roles in (('installer',{'DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'}),('attestor',{'CREATION_ATTESTATION'})):
        grants=[k for k in policy['keys'] if k['keyRef']==BINDINGS[role+'_key_ref'] and k['issuerRef']==BINDINGS[role+'_issuer_ref']]
        require(len(grants)==1); grant=grants[0]
        require(set(grant['roles'])==roles and grant['state']=='ACTIVE' and type(grant['notBefore']) is int and type(grant['expiresAt']) is int and grant['notBefore']<=now<grant['expiresAt'])
        pub=read(CUSTODY/(role+'.der')); public_inputs[role]=pub
        require(len(pub)==44 and pub[:12]==bytes.fromhex('302a300506032b6570032100') and digest(pub)==custody['outputHashes'][role+'.der'] and pub[12:].hex()==grant['publicKey'])
        key=CUSTODY/(role+'.pem'); key_metadata[role]=metadata(key)
        sha=custody['outputHashes'][role+'.pem']; require(re.fullmatch('[0-9a-f]{64}',sha))
        key_bindings[role]={'path':str(key),'sha256':sha}
    require(public_inputs['installer']!=public_inputs['attestor'])
    profile={'schema':'ouf.semantic-existing-installation-authority-bindings.v1','sourceCommit':manifest['sourceCommit'],
        'sourceRoot':str(root/'source'),'sourceHashes':manifest['sourceHashes'],
        'authorities':{'installationRef':BINDINGS['installation_ref'],'entityRef':BINDINGS['entity_ref'],
            'intentIssuerRef':BINDINGS['installer_issuer_ref'],'approvalIssuerRef':BINDINGS['installer_issuer_ref'],'attestorRef':BINDINGS['attestor_issuer_ref']},
        'keyRefs':{r:BINDINGS[r+'_key_ref'] for r in key_bindings},'keyBindings':key_bindings,
        'policyBinding':{'path':str(POLICY),'sha256':POLICY_HASH},'custodyReceiptBinding':{'path':str(CUSTODY/'key-custody-receipt.json'),'sha256':CUSTODY_HASH}}
    def stable():
        require(read(root/'install-creation-issuer.py')==installer_raw)
        require(read(root/'sources.json')==manifest_raw and all(read(root/'source'/n)==b for n,b in source.items()))
        require(read(CUSTODY/'key-custody-receipt.json')==custody_raw and read(POLICY)==policy_raw)
        require(all(metadata(CUSTODY/(r+'.pem'))==s and read(CUSTODY/(r+'.der'))==public_inputs[r] for r,s in key_metadata.items()))
    stable()
    claim={'schema':'ouf.semantic-creation-issuer-installation-claim.v1','state':'INSTALLING_SOURCE','manifestHash':manifest_hash}
    publish(root/'installation-claim.json',encoded(claim))
    stable(); publish(root/'installation-authority-profile.json',encoded(profile)); stable()
    receipt={'schema':'ouf.semantic-creation-issuer-source-installation.v1','status':'SOURCE_INSTALLED_EXISTING_AUTHORITY_BOUND',
        'directory':str(root),'sourceCommit':manifest['sourceCommit'],'sourceCount':len(NAMES),'manifestHash':manifest_hash,
        'installerSourceHash':digest(installer_raw),
        'authorityProfileHash':digest(encoded(profile)),'privateKeysRead':0,'keysGenerated':0,'signaturesIssued':0,
        'policyConsumerLinked':False,'roleSigningAuthorized':False,'startAuthorized':False,'transactionConfigured':False,
        'generalSudoGranted':False,'containerLifecycleOperations':0,'rulesChanged':False,'notReleaseAcceptance':True}
    publish(root/'installation-receipt.json',encoded(receipt)); stable(); return receipt

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--package-root',type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True); p.add_argument('--install-source-and-bind-existing-authority',action='store_true'); a=p.parse_args()
    try:
        require(a.install_source_and_bind_existing_authority is True and os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode)
        print('OUF_CREATION_ISSUER_INSTALLATION='+json.dumps(install(a.package_root,a.manifest_sha256),sort_keys=True)); return 0
    except Exception:
        print('OUF_CREATION_ISSUER_INSTALLATION=BLOCKED EVIDENCE_RETAINED=true DO_NOT_RERUN=true NO_RAW_OUTPUT=true'); return 1

if __name__=='__main__': raise SystemExit(main())
