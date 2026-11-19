from pathlib import Path
import json,hashlib,collections
S=Path(__file__).resolve().parent;E=S/'evidence'; D=json.JSONDecoder(strict=False)
def events(p):
 s=p.read_text();i=0
 while i<len(s):
  while i<len(s) and s[i].isspace(): i+=1
  if i==len(s):break
  x,i=D.raw_decode(s,i);yield x
b=list(events(E/'combined-tests.stdout'));a=list(events(E/'supplemental-tests.stdout'))
assert not set(x.get('Package') for x in a)&set(x.get('Package') for x in b)
profiles={'main':[x for x in b if x.get('Package','').rsplit('/',1)[-1]not in ('server','shell')]+a,'server':[x for x in b if x.get('Package','').endswith('/weed/server')],'shell-local-observation':[x for x in b if x.get('Package','').endswith('/weed/shell')]}
manifest={'schema':'ouf.source32-observed-profiles.v1','rawInputs':[{ 'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [E/'combined-tests.stdout',E/'supplemental-tests.stdout']],'derivation':'main = combined excluding exact server/shell packages, followed by supplemental distinct packages; server and shell preserve their complete observed event streams. No event failures converted into PASS. Broad exit1 retained.','profiles':{}}
for name,ev in profiles.items():
 p=E/(name+'.jsonl');p.write_text(''.join(json.dumps(x,separators=(',',':'))+'\n' for x in ev))
 terms=[x for x in ev if x.get('Action')in('pass','fail','skip')];tests=[x for x in terms if x.get('Test')];pkgs=[x for x in terms if not x.get('Test')]
 v={'path':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'counts':dict(collections.Counter(x['Action']for x in tests)),'packageCounts':dict(collections.Counter(x['Action']for x in pkgs)),'packages':sorted(set(x['Package']for x in ev)),'testTerminals':[{'package':x['Package'],'test':x['Test'],'action':x['Action']}for x in tests]};manifest['profiles'][name]=v
 print(name,v['counts'],v['packageCounts'])
(E/'observed-profiles.json').write_text(json.dumps(manifest,indent=2)+'\n')
# Exact failure identity parity against prior Google baseline.
p=Path('google-profile32-stage/proposal/evidence/seaweedfs-google-profile-20261103/baseline-shell-terminals.jsonl'); old=list(events(p));now=profiles['shell-local-observation'];f=lambda e:sorted((x['Package'],x['Test'])for x in e if x.get('Test')and x.get('Action')=='fail');assert f(old)==f(now),(f(old),f(now));(E/'shell-failure-baseline-parity.json').write_text(json.dumps({'baselinePath':str(p),'baselineSha256':hashlib.sha256(p.read_bytes()).hexdigest(),'exactFailureIdentityParity':True,'failedTests':f(now),'requiredHostedStatus':'REQUIRED_HOSTED_PASS_NOT_LOCALLY_OBSERVED'},indent=2)+'\n')
