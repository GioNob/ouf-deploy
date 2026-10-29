#!/usr/bin/env python3
"""Operator-only migration of the owned empty provider/OIDC guard and boot state.

No image/rootfs preparation, application start, authority-key file read, signed admission,
Docker daemon restart or general privilege grant is performed.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

POINTER=Path('/etc/ouf/coordinated-boot-installation.json')
OLD_OWNER_HASH='be76f56598ef3d7e91e773351b6a04f8a4595c4fb6ef1d70986d47ddb350ad04'
NETWORK_REPORT=Path('/tmp/ouf-transaction-network-979dcbgd/report.json')
CLAIM=Path('/etc/ouf/provider-v2-network-guard-migration.claim')
SNAPSHOT_PARENT=Path('/etc/ouf/deploy-snapshots')
NETWORK_BOUND_FILES={'binding':Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-inputs-XE7IwlGm/binding.json'),
 'plan':Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-inputs-XE7IwlGm/runtime-plan.json')}
UNIT_PATHS={'guard.service':Path('/etc/systemd/system/ouf-semantic-boot-guard.service'),
 'docker-drop-in.conf':Path('/etc/systemd/system/docker.service.d/90-ouf-semantic-boot-guard.conf')}
PACKAGE_NAMES={'extend_empty_lease_guard.py','build_guard_profiles.py','publish_guard_files.py',
 'build_target_network_policy.py','read_gateway_peer_port.py','install_provider_network_guard.py','captured-network-inputs.json'}
STAGE='ROOT_ACCESS';SNAPSHOT=None

class MigrationDenied(ValueError):
 def __init__(self,reason,**details):
  self.diagnosis={'status':'BLOCKED','stage':STAGE,'reason':reason,**details,'secretValuesPrinted':False}
  super().__init__(reason)
def require(ok,reason):
 if not ok:raise MigrationDenied(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def unique(pairs):
 v={}
 for k,x in pairs:
  require(k not in v,'DUPLICATE_JSON_KEY');v[k]=x
 return v
def parsed(raw):return json.loads(raw,object_pairs_hook=unique)
def private(path,expected=None):
 require(path.is_absolute() and '..' not in path.parts,'SAFE_PRIVATE_PATH_REQUIRED')
 for parent in (path.parent,*path.parent.parents):
  s=parent.lstat();temporary_ancestor=path==NETWORK_REPORT and parent==Path('/tmp') and bool(s.st_mode & stat.S_ISVTX)
  require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and (not s.st_mode & 0o022 or temporary_ancestor),'ROOT_PRIVATE_ANCESTOR_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)==(0,0,0o600,1) and s.st_size<=2000000,'ROOT_PRIVATE_FILE_REQUIRED')
  raw=os.read(fd,2000001);require(len(raw)==s.st_size,'PRIVATE_FILE_CHANGED')
  if expected is not None and sha(raw)!=expected:raise MigrationDenied('SEALED_INPUT_HASH_CHANGED',inputName=path.name,expectedSha256=expected,actualSha256=sha(raw))
  return raw
 finally:os.close(fd)
def module(path,expected,name):
 raw=private(path,expected);spec=importlib.util.spec_from_file_location(name,path)
 m=importlib.util.module_from_spec(spec);exec(compile(raw,str(path),'exec'),m.__dict__);return m
def command(argv,raw=None,limit=2000000):
 try:r=subprocess.run(argv,input=raw,capture_output=True,text=True,timeout=25)
 except subprocess.TimeoutExpired:raise MigrationDenied('COMMAND_BUDGET_EXCEEDED',executable=Path(argv[0]).name,budgetSeconds=25) from None
 if r.returncode:raise MigrationDenied('BOUNDED_COMMAND_FAILED',executable=Path(argv[0]).name,exitCode=r.returncode)
 require(len(r.stdout)<=limit,'COMMAND_OUTPUT_BOUND_EXCEEDED')
 return r.stdout
def executable(path,expected):
 for parent in (path.parent,*path.parent.parents):
  info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode & 0o022,'EXECUTABLE_ANCESTOR_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode & 0o022 and info.st_mode & 0o111 and info.st_size<=16777216,'ROOT_EXECUTABLE_REQUIRED')
  require(sha(os.read(fd,16777217))==expected,'NFT_EXECUTABLE_CHANGED')
 finally:os.close(fd)

def selected(root,hashes):
 require(set(hashes)==PACKAGE_NAMES,'INSTALLER_SOURCE_CLOSURE_REQUIRED')
 for name,expected in hashes.items():private(root/name,expected)
 require(not (root/'__init__.py').exists(),'UNSEALED_INITIALIZER_DENIED')
 sys.path.insert(0,str(root))
 import extend_empty_lease_guard as core
 import build_guard_profiles as profiles
 import publish_guard_files as files
 import build_target_network_policy as network
 return core,profiles,files,network

def loaded(guard_command):
 # Verify the command loaded by systemd, not just files on disk. Paths and
 # hashes are installation metadata; no environment or credential output.
 for unit,prop in [('ouf-semantic-boot-guard.service','ExecStart'),('docker.service','ExecStartPre')]:
  actual=command(['/usr/bin/systemctl','show',unit,'--property='+prop,'--value'],limit=16384)
  if guard_command not in actual:raise MigrationDenied('LOADED_BOOT_COMMAND_CHANGED',systemdUnit=unit,propertyName=prop,expectedCommandSha256=sha(guard_command.encode()),actualPropertySha256=sha(actual.encode()))
def rewriter(raw,directive,cmd):
 rows=raw.decode().splitlines(keepends=True)
 found=[i for i,x in enumerate(rows) if x.startswith(directive+'=')]
 require(len(found)==1 and rows[found[0]].strip()!=directive+'=','SINGLE_BOOT_COMMAND_REQUIRED')
 rows[found[0]]=directive+'='+cmd+'\n';return ''.join(rows).encode()

def inspect_candidates():
 facts=[]
 for cid in ('f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67','1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'):
  state=parsed(command(['/usr/bin/docker','inspect','--format','{{json .State}}',cid],limit=16384))
  require(state['Status']=='created' and state['Running'] is False and state['Pid']==0 and state['StartedAt'].startswith('0001-'),'CANDIDATE_ALREADY_STARTED')
  facts.append({'containerId':cid,'neverStarted':True})
 return facts

def observe(receipt,legacy=None):
 root=Path(receipt['directory']);require(root.parent==SNAPSHOT_PARENT and root.name.startswith('semantic-coordinated-boot-install-'),'SELECTED_INSTALLATION_REQUIRED')
 core,profiles,files,network=selected(root/'migration',receipt['transitionSourceHashes'])
 require(private(root/'transition-source.py',receipt['observerHash'])==private(root/'migration/install_provider_network_guard.py',receipt['observerHash']),'OBSERVER_SOURCE_CHANGED')
 for name,expected in receipt['sourceHashes'].items():private(root/'source'/name,expected)
 owner=parsed(private(root/'coordinated-configuration.json',receipt['configurationHash']))
 boot=parsed(private(root/'boot-configuration.json',receipt['bootConfigurationHash']))
 profile=parsed(private(root/'boot-profile.json',receipt['bootProfileHash']))
 require(owner['kernel']==boot['kernel'] and owner['commonLockFile']==boot['lockFile'] and profile['coordinatedConfigurationHash']==receipt['configurationHash'] and profile['bootConfigurationHash']==receipt['bootConfigurationHash'],'INSTALLED_COHORT_DRIFT')
 private(Path(boot['compilerFile']),boot['compilerHash']);private(Path(profile['bootGuardFile']),profile['bootGuardHash'])
 executable(Path(owner['nftPath']),owner['nftSha256'])
 boot_journal=parsed(private(Path(boot['journalFile'])))
 require(boot_journal=={'schema':'ouf.semantic-runtime-transition.v1','state':'RUNTIME_EMPTY','transactionId':boot['transactionId'],
  'configurationHash':receipt['bootConfigurationHash'],'leaseStructureHash':owner['expectedStructureHash'],'startAuthorized':False},'EMPTY_BOOT_JOURNAL_DRIFT')
 for name,path in UNIT_PATHS.items():private(path,receipt['artifactHashes'][name])
 loaded(receipt['guardCommand'])
 # Source closures were sealed before introducing their namespace packages.
 require(not (root/'source/tools/__init__.py').exists() and not(root/'source/scripts/__init__.py').exists(),'UNSEALED_RUNTIME_INITIALIZER')
 sys.path.insert(0,str(root/'source'))
 from tools.semantic_provider_lease_coordination import hold_common_lock
 from tools.semantic_provider_lease_nft import NftBackend
 backend=NftBackend([owner['nftPath']],owner['kernel'],owner['expectedStructureHash'],owner['readBudgetSeconds'])
 with hold_common_lock(Path(owner['commonLockFile'])):
  backend.verify_ownership(owner['kernel']);core.require_empty(backend.tables())
  journal=parsed(private(Path(owner['journalFile'])))
  require(journal=={'schema':'ouf.semantic-lease-coordination.v1',**owner['binding'],'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[] for _ in owner['kernel']['providerFlows']]},'EMPTY_COORDINATION_JOURNAL_DRIFT')
 candidates=inspect_candidates()
 return {'schema':'ouf.semantic-runtime-readiness.v3','runtimeState':'RUNTIME_PROVIDER_OIDC_EMPTY',
  'runtimeCustodyVerified':True,'candidateCount':len(candidates),'candidatesNeverStarted':True,
  'configurationHash':receipt['configurationHash'],'guardProfile':'COORDINATED_EMPTY_RESTORE',
  'providerFlowCount':len(owner['kernel']['providerFlows']),'providerSetsEmpty':True,'dnsResolvers':owner['dns']['resolvers'],
  'stableAcrossReads':False,'startupReady':False,'startAuthorized':False,'leaseAuthorized':False,
  'realRebootProven':False,'notReleaseAcceptance':True,'readOnly':True,'providerCalls':0,'noSecretsPrinted':True}

def install(package,expected_manifest):
 global STAGE,SNAPSHOT
 require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ROOT_ISOLATED_NO_BYTECODE_REQUIRED')
 os.umask(0o077)
 STAGE='INSTALLER_PACKAGE'
 manifest=parsed(private(package/'sources.json',expected_manifest))
 require(set(manifest)=={'schema','sourceRef','hashes'} and manifest['schema']=='ouf.provider-network-guard-source.v1','EXACT_INSTALLER_MANIFEST_REQUIRED')
 core,profiles,files,network=selected(package,manifest['hashes'])
 STAGE='INSTALLED_BOOT_POINTER'
 pointer_raw=private(POINTER);pointer=parsed(pointer_raw)
 require(set(pointer)=={'schema','receiptFile','receiptHash','observerFile','observerHash'} and pointer['schema']=='ouf.semantic-coordinated-boot-pointer.v1','OLD_BOOT_POINTER_REQUIRED')
 oldroot=Path(pointer['receiptFile']).parent
 require(oldroot.parent==SNAPSHOT_PARENT and oldroot.name.startswith('semantic-coordinated-boot-install-') and Path(pointer['observerFile'])==oldroot/'transition-source.py','OLD_INSTALLED_COHORT_REQUIRED')
 receipt=parsed(private(Path(pointer['receiptFile']),pointer['receiptHash']))
 if receipt.get('schema')=='ouf.semantic-provider-network-guard-installation.v1':
  observed=module(Path(pointer['observerFile']),pointer['observerHash'],'installed_network_observer').observe(receipt)
  return {'status':'ALREADY_INSTALLED_AND_READBACK_VERIFIED','snapshotDirectory':str(oldroot),'runtimeReadiness':observed,'startAuthorized':False}
 private(Path(pointer['observerFile']),pointer['observerHash'])
 if CLAIM.exists():
  previous=parsed(private(CLAIM));location=Path(previous['snapshotDirectory'])
  require(location.parent==SNAPSHOT_PARENT and location.name.startswith('semantic-coordinated-boot-install-v2-'),'MIGRATION_CLAIM_INVALID')
  SNAPSHOT=location;raise ValueError('APPLY_ALREADY_CLAIMED_READ_RETAINED_DIAGNOSIS')
 require(receipt['configurationHash']==OLD_OWNER_HASH,'ORIGINAL_COORDINATION_CHANGED')
 STAGE='ORIGINAL_BOOT_COHORT'
 owner=parsed(private(oldroot/'coordinated-configuration.json',OLD_OWNER_HASH))
 executable(Path(owner['nftPath']),owner['nftSha256'])
 oldprofile=parsed(private(oldroot/'boot-profile.json',receipt['bootProfileHash']))
 boot=parsed(private(Path(oldprofile['bootConfiguration']),oldprofile['bootConfigurationHash']))
 require(owner['kernel']==boot['kernel'] and owner['commonLockFile']==boot['lockFile'] and owner['nftPath']==boot['nftPath'],'ORIGINAL_BOOT_SCOPE_DRIFT')
 oldjournal=parsed(private(Path(owner['journalFile'])))
 require(oldjournal=={'schema':'ouf.semantic-lease-coordination.v1',**owner['binding'],'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[] for _ in owner['kernel']['providerFlows']]},'ORIGINAL_JOURNAL_NOT_QUIESCED')
 sources={name:private(oldroot/'source'/name,expected) for name,expected in {**owner['sourceHashes'],**oldprofile['sourceHashes']}.items()}
 restorer=module(Path(oldprofile['bootGuardFile']),oldprofile['bootGuardHash'],'frozen_boot_restorer')
 restorer.validate(boot)
 oldunit={name:private(path,receipt['artifactHashes'][name]) for name,path in UNIT_PATHS.items()}
 oldcmd=next(x.split('=',1)[1].strip() for x in oldunit['guard.service'].decode().splitlines() if x.startswith('ExecStart='))
 loaded(oldcmd);inspect_candidates()
 STAGE='INSTALLATION_NETWORK_SCOPE'
 try:report=parsed(private(NETWORK_REPORT));input_origin='ROOT_READER_REPORT'
 except FileNotFoundError:
  # The completed operator read must not be repeated just because /tmp was
  # cleaned. This sealed metadata copy is bound again to the actual root files.
  report=parsed(private(package/'captured-network-inputs.json',manifest['hashes']['captured-network-inputs.json']));input_origin='SEALED_CAPTURED_METADATA'
 for name,path in NETWORK_BOUND_FILES.items():private(path,report['inputHashes'][name])
 require(report['inputHashes']['coordination']==OLD_OWNER_HASH and report['dns']==owner['dns'] and report['commonLockFile']==owner['commonLockFile'],'CAPTURED_NETWORK_PROFILE_DRIFT')
 peer_script=package/'read_gateway_peer_port.py'
 peer_output=command(['/usr/bin/python3','-I','-B',str(peer_script)],limit=16384)
 require(peer_output.startswith('OUF_SEMANTIC_PEER_PORT='),'BOUNDED_GATEWAY_PEER_REQUIRED')
 peer=parsed(peer_output.split('=',1)[1]);plan=network.assemble(report,owner['kernel'],peer)
 STAGE='INDEPENDENT_COMPILER_TEMPLATE'
 template={**boot,'kernel':plan['kernel'],'parentNetworkNamespace':os.stat('/proc/self/ns/net').st_ino}
 native=parsed(command(['/usr/bin/unshare','--net','/usr/bin/python3','-I','-B',oldprofile['bootGuardFile'],'--native-template'],encoded(template).decode()))
 footprint=core.digest(core.stable(native))
 SNAPSHOT=Path(tempfile.mkdtemp(prefix='semantic-coordinated-boot-install-v2-',dir=SNAPSHOT_PARENT));SNAPSHOT.chmod(0o700)
 files.create(CLAIM,encoded({'snapshotDirectory':str(SNAPSHOT),'sourceRef':manifest['sourceRef'],'applyClaimed':True,'startAuthorized':False}))
 for name in ('migration','source','source/scripts','source/tools','previous'):(SNAPSHOT/name).mkdir(mode=0o700)
 for name,raw in sources.items():files.create(SNAPSHOT/'source'/name,raw)
 for name,expected in manifest['hashes'].items():files.create(SNAPSHOT/'migration'/name,private(package/name,expected))
 self_raw=private(package/'install_provider_network_guard.py',manifest['hashes']['install_provider_network_guard.py'])
 files.create(SNAPSHOT/'transition-source.py',self_raw)
 journal_path=SNAPSHOT/'transition-journal.json';files.create(journal_path,encoded({'state':'PREPARED','startAuthorized':False}))
 def record(value):files.replace(journal_path,files.read(journal_path),encoded(value))
 from importlib import invalidate_caches
 invalidate_caches();sys.path.insert(0,str(SNAPSHOT/'source'))
 require(not (SNAPSHOT/'source/tools/__init__.py').exists(),'UNSEALED_INITIALIZER')
 from tools.semantic_provider_lease_coordination import hold_common_lock
 from tools.semantic_provider_lease_nft import NftBackend
 backend=NftBackend([owner['nftPath']],owner['kernel'],owner['expectedStructureHash'],owner['readBudgetSeconds'])
 entries=[];new_receipt={};new_command=[None]
 def publish(actual):
  global STAGE
  STAGE='MATCHING_PROFILE_GENERATION'
  compiled=profiles.assemble(str(SNAPSHOT),owner,boot,oldprofile,plan['kernel'],actual,footprint,sha(os.urandom(32)))
  for name,value in compiled.items():files.create(SNAPSHOT/name,encoded(value))
  cmd='/usr/bin/python3 -I -B '+str(SNAPSHOT/'source/scripts/run_semantic_coordinated_boot_guard.py')+' --configuration '+str(SNAPSHOT/'boot-profile.json')+' --configuration-sha256 '+sha(encoded(compiled['boot-profile.json']))
  new_command[0]=cmd
  newunits={name:rewriter(raw,'ExecStart' if name=='guard.service' else 'ExecStartPre',cmd) for name,raw in oldunit.items()}
  new_receipt.update(schema='ouf.semantic-provider-network-guard-installation.v1',state='INSTALLED',directory=str(SNAPSHOT),
   sourceRef=manifest['sourceRef'],sourceHashes={k:sha(v) for k,v in sources.items()},transitionSourceHashes=manifest['hashes'],observerHash=sha(self_raw),
   artifactHashes={k:sha(v) for k,v in newunits.items()},configurationHash=sha(encoded(compiled['coordinated-configuration.json'])),
   bootConfigurationHash=sha(encoded(compiled['boot-configuration.json'])),bootProfileHash=sha(encoded(compiled['boot-profile.json'])),
   guardCommand=cmd,oldDirectory=str(oldroot),networkInputOrigin=input_origin,startAuthorized=False,leaseAuthorized=False,daemonRestarted=False,containerLifecycleOperations=0,
   privateKeysRead=0,providerCalls=0,realRebootProven=False,notReleaseAcceptance=True)
  files.create(SNAPSHOT/'installation-receipt.json',encoded(new_receipt))
  newpointer=encoded({'schema':pointer['schema'],'receiptFile':str(SNAPSHOT/'installation-receipt.json'),'receiptHash':sha(encoded(new_receipt)),
   'observerFile':str(SNAPSHOT/'transition-source.py'),'observerHash':sha(self_raw)})
  for name in oldunit:files.create(SNAPSHOT/'previous'/name,oldunit[name])
  files.create(SNAPSHOT/'previous/active-pointer.json',pointer_raw)
  entries.extend([{'path':UNIT_PATHS[name],'old':oldunit[name],'new':newunits[name]} for name in oldunit])
  entries.append({'path':POINTER,'old':pointer_raw,'new':newpointer})
  STAGE='BOOT_FILES_AND_POINTER_PUBLICATION'
  files.publish(entries,lambda:command(['/usr/bin/systemctl','daemon-reload']),lambda:loaded(cmd))
 def restore():files.restore(entries,lambda:command(['/usr/bin/systemctl','daemon-reload']),lambda:loaded(oldcmd))
 STAGE='COMMON_LOCK_GUARD_TRANSITION'
 with hold_common_lock(Path(owner['commonLockFile'])):
  require(private(POINTER)==pointer_raw and parsed(private(Path(owner['journalFile'])))==oldjournal,'ORIGINAL_SCOPE_CHANGED_BEFORE_APPLY')
  result=core.transition(owner['kernel'],plan['kernel'],backend,footprint,publish,restore,record)
 STAGE='INSTALLED_READBACK'
 readiness=observe(new_receipt)
 files.create(SNAPSHOT/'report.json',encoded({**result,'runtimeReadiness':readiness,'snapshotDirectory':str(SNAPSHOT)}))
 return {**result,'snapshotDirectory':str(SNAPSHOT),'runtimeReadiness':readiness,'generalSudoGranted':False,'daemonRestarted':False,'privateKeysRead':0}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-directory',type=Path,required=True);p.add_argument('--manifest-sha256',required=True)
 args=p.parse_args()
 try:
  result=install(args.source_directory,args.manifest_sha256);print('OUF_PROVIDER_NETWORK_GUARD_MIGRATION='+json.dumps(result,sort_keys=True));return 0
 except Exception as error:
  diagnosis=getattr(error,'diagnosis',{'status':'BLOCKED','stage':STAGE,'reason':str(error) if isinstance(error,ValueError) and re.fullmatch('[A-Z0-9_]+',str(error)) else {FileNotFoundError:'REQUIRED_INSTALLATION_FILE_MISSING',PermissionError:'INSTALLATION_FILE_NOT_READABLE',json.JSONDecodeError:'INSTALLATION_JSON_INVALID',KeyError:'REQUIRED_INSTALLATION_FIELD_MISSING'}.get(type(error),'BOUNDED_MIGRATION_FAILED'),'errorClass':type(error).__name__,'secretValuesPrinted':False})
  diagnosis={**diagnosis,'snapshotDirectory':str(SNAPSHOT) if SNAPSHOT else None,'startAuthorized':False,'privateKeysRead':0,'doNotRerunApply':SNAPSHOT is not None}
  if SNAPSHOT:
   path=SNAPSHOT/('diagnosis-'+sha(os.urandom(16))[:12]+'.json')
   try:
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(encoded(diagnosis));f.flush();os.fsync(f.fileno())
   except OSError as save_error:diagnosis['diagnosisSaveError']=type(save_error).__name__
  print('OUF_PROVIDER_NETWORK_GUARD_MIGRATION='+json.dumps(diagnosis,sort_keys=True));return 1
if __name__=='__main__':raise SystemExit(main())
