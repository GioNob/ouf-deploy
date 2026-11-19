from pathlib import Path
import json,hashlib,shutil,os
S=Path(__file__).resolve().parent;R=S.parent;E=S/'evidence';P=S/'proposal';D=P/'evidence/seaweedfs-source32-integrated-local-20261103';D.mkdir(parents=True,exist_ok=True)
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
m=json.loads((E/'source-manifest.json').read_text());actual={str(p.relative_to(S/'source')):h(p)for p in (S/'source').rglob('*')if p.is_file()and'.git'not in p.relative_to(S/'source').parts};assert actual==m['files'];assert h(S/'weed32')==json.loads((E/'binary-first.json').read_text())['sha256'];assert json.loads((E/'patch-replay.json').read_text())['binaryRebuild']=='PASS';assert len(json.loads((E/'denied-tags-summary.json').read_text()))==9
for n in ['kafka-tidy-diff','iam-tidy-diff']:
 assert json.loads((E/(n+'.command.json')).read_text())['exitCode']==0 and (E/(n+'.stdout')).stat().st_size==0
for n in ['kafka-compile','iam-compile','storage','race','build-first','build-replay']:
 assert json.loads((E/(n+'.command.json')).read_text())['exitCode']==0
rows=json.loads((E/'compiled-module-rows.json').read_text());buildrows=[]
for line in (E/'build-info-first.stdout').read_text().splitlines():
 if line.startswith('\tdep\t'):
  a=line.split('\t');buildrows.append(a[2:4])
assert sorted(buildrows)==rows
for p in E.iterdir():
 if p.is_file():
  q=D/p.name
  if q.exists():assert h(q)==h(p)
  else:os.link(p,q)
for src,name in [('source32-integrated-review-stage/source-parity-review.json','independent-source-parity-review.json'),('source32-integrated-review-stage/observed-profiles-review.json','independent-observed-profiles-review.json')]:shutil.copyfile(R/src,D/name)
for name in ['run_checks.py','summarize_profiles.py','make_patch.py','replay_prepare.py','graph_summary.py','check_denied_tags.py','finalize.py']:shutil.copyfile(S/name,D/name)
raw={str(p.relative_to(P)):{'sha256':h(p),'bytes':p.stat().st_size}for p in D.rglob('*')if p.is_file()}
receipt={'schema':'ouf.seaweedfs-source32-integrated-local.v1','status':'LOCAL_SOURCE_QUALIFIED_HOSTED_AND_RUNTIME_PENDING','baseGeneration':31,'candidateGeneration':32,'patch':m['patch'],'sourceTree':m['tree'],'sourceFileCount':len(m['files']),'changedFiles':m['changedFrom31'],'binary':json.loads((E/'binary-first.json').read_text()),'replay':json.loads((E/'patch-replay.json').read_text()),'graph':json.loads((E/'graph-summary.json').read_text()),'profiles':{k:{a:v[a]for a in ('path','sha256','counts','packageCounts')}for k,v in json.loads((E/'observed-profiles.json').read_text())['profiles'].items()},'shellHostedRequirement':'REQUIRED_HOSTED_PASS_NOT_LOCALLY_OBSERVED','conditionalHostedPassRequired':{'server':['TestGuardedPeerHTTPClientUploadsOverTLS','TestGuardedPeerHTTPClientRejectsHTTPSDowngrade'],'storage':['TestSortedFileNeedleMap_HoldsNoDescriptors','TestRebuildIdx_UnwritableIdxDirSkipsOnlyThisVolume']},'nestedModules':{'test/kafka':'ACTUAL_TIDY_DIFF_EMPTY_AND_COMPILE_PASS','test/s3/iam':'ACTUAL_TIDY_DIFF_EMPTY_AND_COMPILE_PASS'},'unsupportedTagNegativeBuilds':9,'noRetainedRootPinOrH1Changes':True,'yamlLifecycle':'OPEN','targetOperations':False,'githubWrites':False,'admissionCredit':False,'normativeBoundary':'Original PET/Matrix and resilience policy apply; no change to HUMAN/THS, consumed scopes, Teatri/Farmacie or admission gates.','limitations':['No live MongoDB, replica set, protocol deduplication, durability or PITR qualification','Synthetic wire tests do not establish target MongoDB eligibility','Google legacy features are explicitly unavailable in this standard profile; target consumer binding remains open','Main integration skips remain unqualified; shell and conditional server/storage cases require hosted PASS','Uncompiled root legacy module edges and compiled legacy YAML remain; no blanket dependency-lifecycle closure','No hosted OCI/cohort/runtime qualification asserted'],'evidenceFiles':raw}
rp=P/'evidence/seaweedfs-source32-integrated-local-20261103.json';rp.write_text(json.dumps(receipt,indent=2)+'\n');files={str(p.relative_to(P)):{'sha256':h(p),'bytes':p.stat().st_size}for p in P.rglob('*')if p.is_file()};out={'files':files,'count':len(files),'totalBytes':sum(x['bytes']for x in files.values())};(S/'DELIVERY_FILES.json').write_text(json.dumps(out,indent=2)+'\n');print('delivery',len(files),out['totalBytes'],'receipt',h(rp))
