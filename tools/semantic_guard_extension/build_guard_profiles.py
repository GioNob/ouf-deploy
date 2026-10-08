"""Build matching owner, boot and quiescent journals from authenticated inputs."""
import copy
import re
from pathlib import PurePosixPath
from extend_empty_lease_guard import extension, digest, require

def assemble(root,old_owner,old_boot,old_profile,new_kernel,new_tables,new_footprint,transaction_id):
 stage='BUILD_MATCHING_PROFILES';path=PurePosixPath(root)
 require(old_owner.get('schema')=='ouf.semantic-coordinated-owner-runtime.v1'
  and set(old_owner)=={'schema','kernel','dns','expectedStructureHash','nftPath','nftSha256','readBudgetSeconds','pollSeconds','commonLockFile','journalFile','binding','sourceHashes'},stage,'EXACT_OWNER_PROFILE_REQUIRED')
 require(old_boot.get('schema')=='ouf.semantic-runtime-boot-guard.v1'
  and set(old_boot)=={'schema','nftPath','kernel','compilerFile','compilerHash','expectedFootprint','journalFile','transactionId','lockFile'},stage,'EXACT_BOOT_PROFILE_REQUIRED')
 require(old_profile.get('schema')=='ouf.semantic-coordinated-boot-profile.v1'
  and set(old_profile)=={'schema','sourceHashes','coordinatedConfiguration','coordinatedConfigurationHash','bootConfiguration','bootConfigurationHash','bootGuardFile','bootGuardHash'},stage,'EXACT_BOOT_BINDING_REQUIRED')
 require(path.is_absolute() and '..' not in path.parts and re.fullmatch('/[A-Za-z0-9_./-]+',root) is not None,stage,'SAFE_INSTALLATION_ROOT_REQUIRED')
 require(re.fullmatch('[0-9a-f]{64}',transaction_id) is not None,stage,'TRANSACTION_ID_REQUIRED')
 require(old_owner['kernel']==old_boot['kernel'] and old_owner['commonLockFile']==old_boot['lockFile']
  and old_owner['nftPath']==old_boot['nftPath'],stage,'OLD_BOOT_OWNER_SCOPE_DRIFT')
 extension(old_owner['kernel'],new_kernel)
 require(old_profile['coordinatedConfigurationHash']==digest(old_owner)
  and old_profile['bootConfigurationHash']==digest(old_boot),stage,'OLD_PROFILE_BINDING_DRIFT')
 from extend_empty_lease_guard import stable,require_empty
 require_empty(new_tables)
 require(digest(stable(new_tables))==new_footprint,stage,'INDEPENDENT_COMPILER_FOOTPRINT_REQUIRED')
 # The production owner includes native handles in its structure seal. The
 # separate boot footprint deliberately excludes handles across real reboot.
 lease_tables=copy.deepcopy(new_tables)
 def lease_stable(value):
  if isinstance(value,list):return [lease_stable(v) for v in value]
  if isinstance(value,dict):
   if isinstance(value.get('set'),dict):return {'set':lease_stable({k:v for k,v in value['set'].items() if k!='elem'})}
   return {k:lease_stable(v) for k,v in value.items() if k not in ('packets','bytes','expires')}
  return value
 structure=digest(lease_stable(lease_tables))
 owner=copy.deepcopy(old_owner);owner['kernel']=copy.deepcopy(new_kernel);owner['expectedStructureHash']=structure
 owner['journalFile']=root+'/coordination-journal.json';owner.pop('binding')
 owner['binding']={'transactionId':transaction_id,'configurationHash':digest(owner),'leaseStructureHash':structure}
 boot=copy.deepcopy(old_boot);boot['kernel']=copy.deepcopy(new_kernel);boot['expectedFootprint']=new_footprint
 boot['journalFile']=root+'/boot-journal.json';boot['transactionId']=transaction_id
 profile=copy.deepcopy(old_profile)
 profile.update(coordinatedConfiguration=root+'/coordinated-configuration.json',coordinatedConfigurationHash=digest(owner),
  bootConfiguration=root+'/boot-configuration.json',bootConfigurationHash=digest(boot))
 return {'coordinated-configuration.json':owner,'boot-configuration.json':boot,'boot-profile.json':profile,
  'coordination-journal.json':{'schema':'ouf.semantic-lease-coordination.v1',**owner['binding'],
   'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[] for _ in new_kernel['providerFlows']]},
  'boot-journal.json':{'schema':'ouf.semantic-runtime-transition.v1','state':'RUNTIME_EMPTY',
   'transactionId':transaction_id,'configurationHash':digest(boot),'leaseStructureHash':structure,'startAuthorized':False}}
