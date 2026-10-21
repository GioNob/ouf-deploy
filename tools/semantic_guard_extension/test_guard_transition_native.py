"""Hosted CI only: real atomic nft extension, rollback and matching boot state."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import sys
import uuid

here=Path(__file__).resolve().parent
source=here.parent/'semantic_cohort_admission/cohort-draft'
if not source.exists():source=here.parent/'admission-integration/cohort-draft'
sys.path.insert(0,str(source))
from tools.materialize_southbound_kernel import materialize
from tools.semantic_provider_lease_nft import NftBackend,structure_hash
from extend_empty_lease_guard import transition,digest,stable,TransitionDenied
from build_guard_profiles import assemble
import publish_guard_files as publication

def run(args,raw=None):
 p=subprocess.run(args,input=raw,capture_output=True,text=True,timeout=10)
 if p.returncode:raise RuntimeError('CI_NFT_FAILED:'+p.stderr[:1000])
 return p.stdout
def tables(table):return {f:json.loads(run(['/usr/sbin/nft','-j','list','table',f,table])) for f in ('inet','bridge')}
def drop(table):
 for f in ('inet','bridge'):run(['/usr/sbin/nft','delete','table',f,table])
def main():
 suffix=uuid.uuid4().hex[:7];table='migrate_'+suffix;reference='reference_'+suffix
 old={'tableName':table,'guardedInterfaces':['ciint0','ciegress0'],'existingInterfaces':['cishared0'],
  'staticFlows':[{'purpose':'DNS','source':'198.19.60.3','destination':'10.8.0.53','protocol':'udp','port':53}],
  'providerFlows':[{'endpointRef':'schema','endpoint':'https://schema.example/sparql','source':'198.19.60.3',
   'addresses':[],'leaseSeconds':30,'resolutionEvidenceRef':'ci-owner','allowedPrivateAddresses':[]}]}
 new=copy.deepcopy(old);new['providerFlows'].append({**copy.deepcopy(old['providerFlows'][0]),'endpointRef':'identity',
  'endpoint':'https://identity.example/realms/ci','source':'198.19.60.2'})
 created=[]
 try:
  run(['/usr/sbin/nft','-f','-'],materialize(old,empty_provider_sets=True)['nftRules']);created.append(table)
  compiled=copy.deepcopy(new);compiled['tableName']=reference
  run(['/usr/sbin/nft','-f','-'],materialize(compiled,empty_provider_sets=True)['nftRules']);created.append(reference)
  # Normalize only the isolated reference's chosen table name. The remaining
  # compiler-generated JSON is independent of the active patch construction.
  expected=json.loads(json.dumps(tables(reference)).replace(reference,table));footprint=digest(stable(expected))
  backend=NftBackend(['/usr/sbin/nft'],old,structure_hash(tables(table)),5)
  records=[];events=[]
  temp=tempfile.TemporaryDirectory(prefix='ouf-publication-',dir='/root');directory=Path(temp.name);directory.chmod(0o700)
  entries=[]
  for name in ('guard.service','docker-drop-in.conf','pointer.json'):
   path=directory/name;publication.create(path,b'old-'+name.encode());entries.append({'path':path,'old':path.read_bytes(),'new':b'new-'+name.encode()})
  def failed_publish(actual):
   events.append('publication')
   def reject():raise RuntimeError('CI_INJECTED_PUBLICATION_FAILURE')
   publication.publish(entries,lambda:None,reject)
  def restore_files():
   events.append('restore');publication.restore(entries,lambda:None,lambda:None)
  try:transition(old,new,backend,footprint,failed_publish,restore_files,records.append)
  except TransitionDenied as error:
   assert error.diagnosis['rollback']=='OLD_HANDLES_AND_FILES_RESTORED',error.diagnosis
  else:raise AssertionError('CI_PUBLICATION_FAILURE_NOT_PROPAGATED')
  assert events==['publication','restore'];backend.verify_ownership(old)
  assert all(publication.read(e['path'])==e['old'] for e in entries)
  # A command may time out after the kernel accepted its atomic transaction.
  class TimeoutBackend(NftBackend):
   def run(self,arguments,raw=None,timeout=None):
    result=super().run(arguments,raw,timeout)
    if arguments==['-f','-'] and not getattr(self,'failed_once',False):
     self.failed_once=True;raise TimeoutError('CI_TIMEOUT_AFTER_COMMIT')
    return result
  timed=TimeoutBackend(['/usr/sbin/nft'],old,backend.expected,5)
  try:transition(old,new,timed,footprint,lambda actual:None,lambda:None,records.append)
  except TransitionDenied as error:assert error.diagnosis['rollback']=='OLD_HANDLES_AND_FILES_RESTORED',error.diagnosis
  else:raise AssertionError('CI_TIMEOUT_NOT_DIAGNOSED')
  backend.verify_ownership(old)
  # An external pointer write blocks recovery; it must not be overwritten.
  before_foreign=tables(table)
  def foreign_publish(actual):
   publication.publish(entries,lambda:None,lambda:None)
   publication.replace(entries[-1]['path'],entries[-1]['new'],b'foreign')
   raise RuntimeError('CI_FOREIGN_POINTER')
  try:transition(old,new,backend,footprint,foreign_publish,lambda:publication.restore(entries,lambda:None,lambda:None),records.append)
  except TransitionDenied as error:
   assert error.diagnosis['rollback']=='BLOCKED_FOREIGN_OR_UNPROVEN_STATE_PRESERVED',error.diagnosis
   assert publication.read(entries[-1]['path'])==b'foreign'
  else:raise AssertionError('CI_FOREIGN_POINTER_OVERWRITTEN')
  # Reset the isolated fixture for the successful profile assembly. Target
  # recovery never performs this reset or silently adopts unknown state.
  from extend_empty_lease_guard import rollback
  backend.run(['-f','-'],rollback(old,new,before_foreign,tables(table)))
  for e in entries:
   actual=publication.read(e['path'])
   if actual!=e['old']:publication.replace(e['path'],actual,e['old'])
  backend.verify_ownership(old);temp.cleanup()
  published={}
  old_owner={'schema':'ouf.semantic-coordinated-owner-runtime.v1','kernel':old,'dns':{'resolvers':['10.8.0.53'],'resolverPort':53,'timeoutSeconds':2,'maxLeaseSeconds':30,'applyBudgetSeconds':1},
   'expectedStructureHash':backend.expected,'nftPath':'/usr/sbin/nft','commonLockFile':'/run/ci/lock',
   'journalFile':'/ci/old-journal','binding':{},'sourceHashes':{},'readBudgetSeconds':5,'pollSeconds':10,'nftSha256':'b'*64}
  old_boot={'schema':'ouf.semantic-runtime-boot-guard.v1','kernel':old,'lockFile':'/run/ci/lock','nftPath':'/usr/sbin/nft',
   'compilerFile':'/ci/compiler.py','compilerHash':'c'*64,'expectedFootprint':digest(stable(tables(table))),
   'journalFile':'/ci/old-boot-journal','transactionId':'d'*64}
  old_profile={'schema':'ouf.semantic-coordinated-boot-profile.v1','coordinatedConfigurationHash':digest(old_owner),
   'bootConfigurationHash':digest(old_boot),'coordinatedConfiguration':'/ci/old-owner.json','bootConfiguration':'/ci/old-boot.json',
   'bootGuardFile':'/ci/restore.py','bootGuardHash':'e'*64,'sourceHashes':{}}
  def publish(actual):published.update(assemble('/ci/new',old_owner,old_boot,old_profile,new,actual,footprint,'a'*64))
  result=transition(old,new,backend,footprint,publish,lambda:None,records.append)
  assert result['originalHandlesPreserved'] and result['providerFlowCount']==2
  owner=published['coordinated-configuration.json'];boot=published['boot-configuration.json'];profile=published['boot-profile.json']
  assert owner['kernel']==boot['kernel']==new
  assert owner['dns']==old_owner['dns']
  assert owner['expectedStructureHash']==structure_hash(tables(table))
  assert profile['coordinatedConfigurationHash']==digest(owner) and profile['bootConfigurationHash']==digest(boot)
  assert published['coordination-journal.json']['leaseAddresses']==[[],[]]
  assert published['coordination-journal.json']['state']=='QUIESCED'
  # Active leases prohibit both extension and rollback. Test this before any
  # publication so a caller cannot flush another owner's in-flight authority.
  run(['/usr/sbin/nft','-f','-'],f'add element inet {table} provider_0 {{ 198.19.60.10 timeout 30s }}\n')
  from extend_empty_lease_guard import require_empty
  try:require_empty(tables(table))
  except TransitionDenied as error:assert error.diagnosis['reason']=='ACTIVE_LEASES_REQUIRE_QUIESCENCE'
  else:raise AssertionError('CI_ACTIVE_LEASE_ADOPTED')
  print('GUARD_EXTENSION_NATIVE=PASS OLD_HANDLES_SURVIVE_ROLLBACK=true THREE_FILES_RECOVERED=true TIMEOUT_AFTER_COMMIT_RECOVERED=true FOREIGN_POINTER_PRESERVED=true MATCHING_BOOT_AND_OWNER=true INSTALLATION_DNS_PRESERVED=true ACTIVE_LEASES_REJECTED=true TARGET_OPERATIONS=0 START_AUTHORIZED=false')
 finally:
  for name in reversed(created):drop(name)
if __name__=='__main__':main()
