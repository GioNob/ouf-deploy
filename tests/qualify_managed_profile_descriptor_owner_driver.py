"""CI only: actual current owner Java/PG17, synthetic trusted principal and PTY decisions."""
import copy,importlib.util,json,os,sys,tempfile,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('actual_owner_profile_publisher',Path(__file__).resolve().parents[1]/'scripts/publish-managed-profile-descriptor-20261028.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
fixture=json.loads(Path(sys.argv[1]).read_text());mode=sys.argv[2]
m.ADMIN=fixture['origin'];m.BASE_HASH=fixture['active']['contentHash'].removeprefix('sha256:');m.BASE_RESPONSE=m.digest(fixture['active'])
def normalize(rows):
 result={}
 for row in rows:
  descriptor=row['descriptor']
  if isinstance(descriptor,dict)and descriptor.get('type')=='jsonb':descriptor=descriptor['value']
  if isinstance(descriptor,str):descriptor=json.loads(descriptor)
  result[row['capability_id']]={'ownerRef':row['owner_ref'],'descriptor':descriptor}
 return result
catalogue=normalize(fixture['catalogue']);m.BASE_CATALOGUE=m.digest(catalogue)
with tempfile.TemporaryDirectory()as tmp:
 j=m.Journal(Path(tmp)/'one-ci-publication');t=m.Transport('CI_SYNTHETIC_PRINCIPAL_NOT_IAM',j)
 active=t.get('initial-active','/policies/active');m.baseline(active)
 assert m.registered(t,'initial-catalogue')==catalogue
 plan=m.prepare(active,catalogue,time.time()+180)
 master,slave=os.openpty()
 def emit(line):
  if line=='Conferma:':os.write(master,('APPROVO '+m.digest(plan)+(' extra'if mode=='decline'else'')+'\n').encode())
  if mode=='decline'and'Riga non valida:'in line:t.deadline=t.clock()-1
 try:
  try:
   m.approve(plan,j,t,fd=slave,emit=emit)
   result=m.execute(plan,catalogue,j,t)
  except m.Stop as error:
   assert mode in('decline','lost'),str(error)
   if mode=='decline':assert str(error)=='FINITE_HUMAN_WINDOW_EXPIRED',str(error)
  else:
   assert mode=='success';assert result['counts']['administrativeWrites']==3 and result['counts']['previewPosts']==2
   assert result['allGrantsPreserved']and result['newGrantsGranted']==0 and result['humanBudgetsGranted']==0
  if mode=='decline':assert t.counts['administrativeWrites']==0 and not j.row.get('humanReviewApproved')
  elif mode=='lost':
   assert j.row['effects']['PUBLISH_DRAFT']['state']=='CLAIMED'
   try:m.execute(plan,catalogue,j,t)
   except m.Stop:pass
   else:raise AssertionError('lost publication replayed')
  else:
   response=json.loads((j.path/'owner-create-response.json').read_text());assert response['etag']=='"0"'and json.loads(response['bodyUtf8'])['revision']==0
   response=json.loads((j.path/'owner-publish-response.json').read_text());assert response['etag']=='"1"'and json.loads(response['bodyUtf8'])['revision']==1
  print('ACTUAL_CURRENT_OWNER_PROFILE_DESCRIPTOR_'+mode.upper()+'_PASS',flush=True)
 finally:os.close(master);os.close(slave)
