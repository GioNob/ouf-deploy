"""Isolated CI integration of root installer; Docker/systemd metadata mocked.

The real nft transaction, private files, profile/hash publication, fixed pointer,
replay and helper observation are exercised. No target authorization is claimed.
"""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import install_provider_network_guard as installer
import publish_guard_files as files
from extend_empty_lease_guard import digest,stable
from build_target_network_policy import dns_flows

OWNER_FILES=('scripts/run_semantic_coordinated_lease_owner.py','tools/semantic_provider_coordinated_supervisor.py',
 'tools/semantic_provider_lease_coordination.py','tools/semantic_provider_lease_owner.py','tools/semantic_provider_lease_nft.py',
 'tools/semantic_provider_dns.py','tools/materialize_southbound_kernel.py','tools/materialize_southbound_lease_refresh.py')
BOOT_FILES=('scripts/run_semantic_coordinated_boot_guard.py','tools/semantic_provider_boot_coordination.py')
def private(path,body):files.create(path,installer.encoded(body) if isinstance(body,dict) else body)
def main():
 gateway=Path(sys.argv[1]).resolve();here=Path(__file__).resolve().parent;network=here.parent/'semantic_transaction_network'
 real_command=installer.command
 with tempfile.TemporaryDirectory(prefix='ouf-installer-integration-',dir='/root') as temporary:
  root=Path(temporary);root.chmod(0o700)
  for p in ('snapshots','package','units','inputs'):(root/p).mkdir(mode=0o700)
  oldroot=root/'snapshots/semantic-coordinated-boot-install-ci';oldroot.mkdir(mode=0o700)
  for p in ('source','source/scripts','source/tools'):(oldroot/p).mkdir(mode=0o700)
  source_hashes={}
  for relative in (*OWNER_FILES,*BOOT_FILES):
   raw=(gateway/relative).read_bytes();private(oldroot/'source'/relative,raw);source_hashes[relative]=installer.sha(raw)
  raw=(gateway/'scripts/restore_semantic_runtime_boot_guard.py').read_bytes();private(oldroot/'restore.py',raw)
  restorer=installer.module(oldroot/'restore.py',installer.sha(raw),'ci_old_restorer')
  kernel_compiler=installer.module(oldroot/'source/tools/materialize_southbound_kernel.py',source_hashes['tools/materialize_southbound_kernel.py'],'ci_old_compiler')
  dns={'resolvers':['10.8.0.53'],'resolverPort':53,'timeoutSeconds':2,'maxLeaseSeconds':30,'applyBudgetSeconds':1}
  kernel={'tableName':'ouf_sem_provider','guardedInterfaces':['oufsp-int','oufsp-egress'],
   'existingInterfaces':['br-113b5f0a3c53','docker0'],
   'staticFlows':[{'purpose':'GATEWAY_ADAPTER','source':'172.21.0.2','destination':'172.21.0.3','protocol':'tcp','port':9443}]+dns_flows(dns,['172.22.0.2','172.22.0.3']),
   'providerFlows':[{'endpointRef':'schema-gov','endpoint':'https://schema.gov.it/sparql','source':'172.22.0.3','addresses':[],
    'leaseSeconds':30,'resolutionEvidenceRef':'fresh-lease-owner','allowedPrivateAddresses':[]}]}
  real_command(['/usr/sbin/nft','-f','-'],kernel_compiler.materialize(kernel,empty_provider_sets=True)['nftRules'])
  try:
   tables={f:json.loads(real_command(['/usr/sbin/nft','-j','list','table',f,'ouf_sem_provider'])) for f in ('inet','bridge')}
   lock=root/'guard.lock';private(lock,b'')
   owner={'schema':'ouf.semantic-coordinated-owner-runtime.v1','kernel':kernel,'dns':dns,'expectedStructureHash':installer.sha(installer.encoded(restorer.stable(tables,True))),
    'nftPath':'/usr/sbin/nft','nftSha256':installer.sha(Path('/usr/sbin/nft').read_bytes()),'readBudgetSeconds':5,'pollSeconds':10,
    'commonLockFile':str(lock),'journalFile':str(oldroot/'coordination-journal.json'),'sourceHashes':{k:source_hashes[k] for k in OWNER_FILES}}
   owner['binding']={'transactionId':'a'*64,'configurationHash':digest(owner),'leaseStructureHash':owner['expectedStructureHash']}
   private(oldroot/'coordinated-configuration.json',owner)
   private(oldroot/'coordination-journal.json',{'schema':'ouf.semantic-lease-coordination.v1',**owner['binding'],'state':'QUIESCED',
    'leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[]]})
   boot={'schema':'ouf.semantic-runtime-boot-guard.v1','kernel':kernel,'nftPath':owner['nftPath'],
    'compilerFile':str(oldroot/'source/tools/materialize_southbound_kernel.py'),'compilerHash':source_hashes['tools/materialize_southbound_kernel.py'],
    'expectedFootprint':digest(stable(tables)),'lockFile':str(lock),'journalFile':str(oldroot/'boot-journal.json'),'transactionId':'a'*64}
   private(oldroot/'boot-configuration.json',boot)
   profile={'schema':'ouf.semantic-coordinated-boot-profile.v1','sourceHashes':{k:source_hashes[k] for k in BOOT_FILES},
    'coordinatedConfiguration':str(oldroot/'coordinated-configuration.json'),'coordinatedConfigurationHash':digest(owner),
    'bootConfiguration':str(oldroot/'boot-configuration.json'),'bootConfigurationHash':digest(boot),
    'bootGuardFile':str(oldroot/'restore.py'),'bootGuardHash':installer.sha(raw)}
   private(oldroot/'boot-profile.json',profile)
   old_command='/usr/bin/python3 -I -B /ci/old-boot.py'
   units={'guard.service':root/'units/guard.service','docker-drop-in.conf':root/'units/docker-drop-in.conf'}
   for name,path in units.items():private(path,('[Service]\n'+('ExecStart' if name=='guard.service' else 'ExecStartPre')+'='+old_command+'\n').encode())
   private(oldroot/'transition-source.py',b'# CI-only original observer\n')
   receipt={'schema':'ouf.semantic-coordinated-boot-installation.v1','configurationHash':digest(owner),
    'bootProfileHash':digest(profile),'artifactHashes':{k:installer.sha(v.read_bytes()) for k,v in units.items()}}
   private(oldroot/'installation-receipt.json',receipt)
   pointer=root/'active-pointer.json'
   private(pointer,{'schema':'ouf.semantic-coordinated-boot-pointer.v1','receiptFile':str(oldroot/'installation-receipt.json'),
    'receiptHash':digest(receipt),'observerFile':str(oldroot/'transition-source.py'),'observerHash':installer.sha((oldroot/'transition-source.py').read_bytes())})
   bound={k:root/'inputs'/k for k in ('binding','plan')}
   for path in bound.values():private(path,b'{}')
   projected=copy.deepcopy(kernel);projected['providerFlows'][0]['endpoint']={'hostname':'schema.gov.it','path':'/sparql','port':443};projected['providerFlows'][0].pop('addresses')
   report={'status':'NETWORK_INPUTS_CAPTURED','schema':'ouf.semantic-provider-transaction-network-inputs.v1','kernel':projected,'dns':dns,
    'providerEndpoint':{'hostname':'schema.gov.it','path':'/sparql','port':443},'oidcIssuerEndpoint':{'hostname':'auth.ouf-lab.it','path':'/realms/ouf','port':443},
    'commonLockFile':str(lock),'inputHashes':{'coordination':digest(owner),**{k:installer.sha(v.read_bytes()) for k,v in bound.items()}}}
   # Deliberately omit the /tmp report: completed captured metadata must remain
   # usable after cleanup, with its actual private input hashes rechecked.
   source_files={name:(network/name if name in ('build_target_network_policy.py','read_gateway_peer_port.py') else here/name).read_bytes()
    for name in installer.PACKAGE_NAMES if name!='captured-network-inputs.json'}
   source_files['captured-network-inputs.json']=installer.encoded(report)
   for name,body in source_files.items():private(root/'package'/name,body)
   manifest={'schema':'ouf.provider-network-guard-source.v1','sourceRef':'ci-fixture','hashes':{k:installer.sha(v) for k,v in source_files.items()}}
   private(root/'package/sources.json',manifest)
   peer={'status':'EXISTING_PEER_PORT_CAPTURED','container':'ouf-semantic','address':'172.18.0.6','mac':'b2:96:a1:e2:c1:8d',
    'bridge':'br-113b5f0a3c53','hostIfindex':1377}
   calls=[];real_module=installer.module
   def mock_command(argv,raw=None,limit=2000000):
    calls.append(argv)
    if argv[0]=='/usr/bin/systemctl':
     if argv[1]=='daemon-reload':return ''
     name='guard.service' if argv[2]=='ouf-semantic-boot-guard.service' else 'docker-drop-in.conf'
     return 'argv[]='+units[name].read_text().split('=',1)[1].strip()
    if argv[0]=='/usr/bin/docker':return json.dumps({'Status':'created','Running':False,'Pid':0,'StartedAt':'0001-01-01T00:00:00Z'})
    if argv[0]=='/usr/bin/python3' and argv[-1].endswith('read_gateway_peer_port.py'):return 'OUF_SEMANTIC_PEER_PORT='+json.dumps(peer)
    return real_command(argv,raw,limit)
   def mock_module(path,expected,name):
    result=real_module(path,expected,name)
    if name=='installed_network_observer':
     result.SNAPSHOT_PARENT=root/'snapshots';result.UNIT_PATHS=units;result.command=mock_command
    return result
   with patch.multiple(installer,POINTER=pointer,OLD_OWNER_HASH=digest(owner),UNIT_PATHS=units,
    SNAPSHOT_PARENT=root/'snapshots',NETWORK_BOUND_FILES=bound,NETWORK_REPORT=root/'absent-report.json',CLAIM=root/'migration.claim',command=mock_command,module=mock_module):
    result=installer.install(root/'package',digest(manifest))
    assert result['status']=='EMPTY_GUARD_EXTENDED' and result['runtimeReadiness']['runtimeCustodyVerified'],result
    assert result['runtimeReadiness']['dnsResolvers']==['10.8.0.53']
    assert result['runtimeReadiness']['providerFlowCount']==2 and not result['runtimeReadiness']['startupReady']
    replay=installer.install(root/'package',digest(manifest))
    assert replay['status']=='ALREADY_INSTALLED_AND_READBACK_VERIFIED'
    assert len([v for v in calls if v[:2]==['/usr/bin/systemctl','daemon-reload']])==1
   print('ROOT_GUARD_INSTALLER_INTEGRATION=PASS REAL_NFT_AND_PRIVATE_FILE_PUBLICATION=true ROOT_REPORT_CLEANUP_RECOVERED=true PRIVATE_DNS_PRESERVED=true REPLAY_PERFORMS_READBACK_ONLY=true MOCKED_DOCKER_AND_SYSTEMD=true NO_TARGET_ADMISSION_OR_START=true')
  finally:
   for family in ('inet','bridge'):real_command(['/usr/sbin/nft','delete','table',family,'ouf_sem_provider'])
if __name__=='__main__':main()
